#include "scarab/fuzzer/oracle.h"

// fuzzer_engine.h provides the full definition of FuzzerExecutionResult that
// oracle.h only forward-declares.
#include "scarab/fuzzer/fuzzer_engine.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

namespace scarab::fuzzer {

namespace {

namespace fs = std::filesystem;

// ---------------------------------------------------------------------------
// Small helpers for the TSan output parser
// ---------------------------------------------------------------------------

/// Strip a trailing " (pid=N)" suffix and whitespace from the race-type field.
std::string trim_race_type(const std::string& s) {
  const auto paren = s.find(" (");
  const std::string trimmed =
      (paren != std::string::npos) ? s.substr(0, paren) : s;
  size_t end = trimmed.size();
  while (end > 0 && trimmed[end - 1] == ' ') {
    --end;
  }
  return trimmed.substr(0, end);
}

/// Returns true when the line is a TSan stack-frame line ("    #N …").
bool is_stack_line(const std::string& line) {
  for (size_t i = 0; i < line.size(); ++i) {
    if (line[i] == ' ') continue;
    return (line[i] == '#') && (i + 1 < line.size()) &&
           (line[i + 1] >= '0' && line[i + 1] <= '9');
  }
  return false;
}

std::string to_lower_copy(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return value;
}

bool contains_case_insensitive(const std::string& haystack,
                               const std::string& needle) {
  if (needle.empty()) {
    return false;
  }
  const std::string haystack_lower = to_lower_copy(haystack);
  const std::string needle_lower = to_lower_copy(needle);
  return haystack_lower.find(needle_lower) != std::string::npos;
}

std::string strip_matching_quotes(const std::string& value) {
  if (value.size() < 2) {
    return value;
  }
  const char first = value.front();
  const char last = value.back();
  if ((first == '"' && last == '"') || (first == '\'' && last == '\'')) {
    return value.substr(1, value.size() - 2);
  }
  return value;
}

std::string extract_tsan_log_path_from_env() {
  const char* tsan_options = std::getenv("TSAN_OPTIONS");
  if (tsan_options == nullptr || *tsan_options == '\0') {
    return {};
  }

  // TSAN_OPTIONS is typically space-separated. Accept ':' too, since some
  // sanitizer runtimes and wrappers use colon-delimited option strings.
  static const std::regex kLogPathRegex(R"((?:^|[\s:])log_path=([^\s:]+))");
  std::cmatch match;
  if (!std::regex_search(tsan_options, match, kLogPathRegex) || match.size() < 2) {
    return {};
  }
  return strip_matching_quotes(match[1].str());
}

std::vector<fs::path> find_tsan_log_files(const std::string& log_path_prefix) {
  std::vector<fs::path> files;
  if (log_path_prefix.empty()) {
    return files;
  }

  const fs::path prefix_path(log_path_prefix);
  const fs::path directory =
      prefix_path.has_parent_path() ? prefix_path.parent_path() : fs::current_path();
  const std::string base = prefix_path.filename().string();
  if (base.empty()) {
    return files;
  }

  std::error_code ec;
  if (!fs::exists(directory, ec)) {
    return files;
  }

  for (const auto& entry : fs::directory_iterator(directory, ec)) {
    if (ec || !entry.is_regular_file()) {
      continue;
    }
    const std::string name = entry.path().filename().string();
    if (name == base || name.rfind(base + ".", 0) == 0) {
      files.push_back(entry.path());
    }
  }
  std::sort(files.begin(), files.end());
  return files;
}

std::string read_file_incremental(const fs::path& file_path, uint64_t* offset) {
  if (offset == nullptr) {
    return {};
  }

  std::ifstream input(file_path, std::ios::binary);
  if (!input.good()) {
    return {};
  }

  input.seekg(0, std::ios::end);
  const std::streampos end_pos = input.tellg();
  if (end_pos < 0) {
    return {};
  }

  uint64_t file_size = static_cast<uint64_t>(end_pos);
  uint64_t start = *offset;
  if (start > file_size) {
    // File rotated/truncated.
    start = 0;
  }

  if (start == file_size) {
    *offset = file_size;
    return {};
  }

  const uint64_t chunk_size = file_size - start;
  std::string out;
  out.resize(static_cast<size_t>(chunk_size));

  input.seekg(static_cast<std::streamoff>(start), std::ios::beg);
  input.read(out.data(), static_cast<std::streamsize>(chunk_size));
  const std::streamsize read_size = input.gcount();
  if (read_size <= 0) {
    *offset = file_size;
    return {};
  }
  out.resize(static_cast<size_t>(read_size));
  *offset = file_size;
  return out;
}

}  // namespace

// ---------------------------------------------------------------------------
// OracleManager::parse_tsan_output
// ---------------------------------------------------------------------------
//
// Typical TSan stderr block structure:
//
//   ==================
//   WARNING: ThreadSanitizer: data race (pid=N)
//     Write of size 4 at 0xADDR by thread T2:
//       #0 Foo::bar() foo.cpp:42 (binary+0x1234)
//       #1 rclcpp::... ...
//
//     Previous read of size 4 at 0xADDR by thread T1:
//       #0 Foo::baz() foo.cpp:55 (binary+0x5678)
//       ...
//
//     Thread T2 (tid=N, running) created by main thread at:
//       ...
//   SUMMARY: ThreadSanitizer: data race foo.cpp:42 in Foo::bar()
//   ==================
//
// The parser is state-machine based and handles multiple consecutive sections.

std::vector<OracleManager::TSanReport> OracleManager::parse_tsan_output(
    const std::string& stderr_output) {
  std::vector<TSanReport> reports;
  if (stderr_output.empty()) return reports;

  static const std::regex kWarning(R"(WARNING: ThreadSanitizer: (.+))");
  // First (current) access: "  Write of size N at 0xADDR by thread TN:"
  static const std::regex kAccess1(
      R"(^\s+(Write|Read) of size (\d+) at (0x[0-9a-fA-F]+))");
  // Second (previous) access: "  Previous write/read of size N at 0xADDR …"
  static const std::regex kAccess2(
      R"(^\s+Previous (write|read) of size (\d+) at (0x[0-9a-fA-F]+))");

  enum class State { IDLE, AFTER_WARNING, ACCESS1_STACK, ACCESS2_STACK };

  State state = State::IDLE;
  TSanReport cur;

  auto save_and_reset = [&]() {
    if (!cur.race_type.empty()) {
      reports.push_back(cur);
    }
    cur = TSanReport{};
    state = State::IDLE;
  };

  std::istringstream stream(stderr_output);
  std::string line;
  while (std::getline(stream, line)) {
    std::smatch m;

    if (state == State::IDLE) {
      if (std::regex_search(line, m, kWarning)) {
        cur = TSanReport{};
        cur.race_type = trim_race_type(m[1].str());
        cur.raw_text = line + "\n";
        state = State::AFTER_WARNING;
      }
      continue;
    }

    cur.raw_text += line + "\n";
    if (state == State::AFTER_WARNING) {
      if (std::regex_search(line, m, kAccess1)) {
        cur.access1_type = m[1].str();
        cur.size = std::stoi(m[2].str());
        try {
          cur.address = std::stoull(m[3].str(), nullptr, 16);
        } catch (...) {
          cur.address = 0;
        }
        state = State::ACCESS1_STACK;
      } else if (std::regex_search(line, m, kAccess2)) {
        // Some TSan versions emit "Previous …" before the first-access block.
        cur.access2_type = m[1].str();
        state = State::ACCESS2_STACK;
      } else if (is_stack_line(line)) {
        cur.access1_stack += line + "\n";
        state = State::ACCESS1_STACK;
      } else if (line.find("==================") != std::string::npos) {
        save_and_reset();
      }

    } else if (state == State::ACCESS1_STACK) {
      if (is_stack_line(line)) {
        cur.access1_stack += line + "\n";
      } else if (std::regex_search(line, m, kAccess2)) {
        cur.access2_type = m[1].str();
        // Update size/address if not already set (edge case)
        if (cur.size == 0) {
          try {
            cur.size    = std::stoi(m[2].str());
            cur.address = std::stoull(m[3].str(), nullptr, 16);
          } catch (...) {
          }
        }
        state = State::ACCESS2_STACK;
      } else if (line.find("==================") != std::string::npos) {
        save_and_reset();
      }
      // blank lines, "Thread T…", "SUMMARY:": stay in ACCESS1_STACK (skip)

    } else if (state == State::ACCESS2_STACK) {
      if (is_stack_line(line)) {
        cur.access2_stack += line + "\n";
      } else if (line.find("==================") != std::string::npos) {
        save_and_reset();
      }
      // Thread info / SUMMARY / blank: stay in ACCESS2_STACK (skip)
    }
  }

  // Catch unterminated final section (no closing ==================)
  if (!cur.race_type.empty()) {
    reports.push_back(cur);
  }

  return reports;
}

// ---------------------------------------------------------------------------
// OracleManager private helpers
// ---------------------------------------------------------------------------

std::vector<OracleManager::BugInfo> OracleManager::check_crash(
    const FuzzerExecutionResult& r) {
  std::vector<BugInfo> bugs;
  // Skip environment errors (e.g. "SCARAB built without ROS2") – those are
  // not real crashes in the target under test.
  if (!r.crashed || r.is_env_error) return bugs;

  BugInfo bug;
  bug.type     = "crash";
  bug.severity = 5;

  const int sig = (r.exit_code < 0) ? -r.exit_code : r.exit_code;
  switch (sig) {
    case 11: bug.description = "SIGSEGV (segmentation fault)"; break;
    case  6: bug.description = "SIGABRT (abort)";              break;
    case  4: bug.description = "SIGILL (illegal instruction)"; break;
    case  8: bug.description = "SIGFPE (floating-point exception)"; break;
    case  0:
      bug.description = r.error_message.empty() ? "Abnormal termination"
                                                 : r.error_message;
      break;
    default:
      bug.description =
          "Signal " + std::to_string(sig) +
          (r.error_message.empty() ? "" : " (" + r.error_message + ")");
      break;
  }
  bug.stack_trace = r.stderr_output;
  bugs.push_back(std::move(bug));
  return bugs;
}

OracleManager::OracleManager() = default;

OracleManager::OracleManager(Options options) : options_(std::move(options)) {}

void OracleManager::set_options(Options options) { options_ = std::move(options); }

const OracleManager::Options& OracleManager::options() const { return options_; }

void OracleManager::prime_tsan_log_offsets_from_env() {
  const std::string tsan_log_prefix = extract_tsan_log_path_from_env();
  if (tsan_log_prefix.empty()) {
    return;
  }

  const auto log_files = find_tsan_log_files(tsan_log_prefix);
  for (const auto& log_file : log_files) {
    std::error_code ec;
    const auto file_size = fs::file_size(log_file, ec);
    if (ec) {
      continue;
    }

    const uint64_t size_u64 = static_cast<uint64_t>(file_size);
    auto [it, inserted] = tsan_log_offsets_.emplace(log_file.string(), size_u64);
    if (!inserted && it->second > size_u64) {
      // Handle log rotation/truncation without rewinding to stale bytes.
      it->second = size_u64;
    }
  }
}

bool OracleManager::is_filtered_tsan_report(const TSanReport& report) const {
  std::string combined = report.raw_text;
  if (!report.access1_stack.empty()) {
    combined += "\n" + report.access1_stack;
  }
  if (!report.access2_stack.empty()) {
    combined += "\n" + report.access2_stack;
  }

  for (const auto& token : options_.stack_filter) {
    if (contains_case_insensitive(combined, token)) {
      return true;
    }
  }
  return false;
}

bool OracleManager::is_internal_tsan_report(const TSanReport& report) const {
  std::string combined = report.raw_text;
  if (!report.access1_stack.empty()) {
    combined += "\n" + report.access1_stack;
  }
  if (!report.access2_stack.empty()) {
    combined += "\n" + report.access2_stack;
  }

  // If any target source pattern is found, this is NOT an internal-only race.
  for (const auto& target : options_.target_source_patterns) {
    if (contains_case_insensitive(combined, target)) {
      return false;
    }
  }

  // If any SCARAB-internal pattern is found (and no target pattern), treat as
  // internal tool race.
  for (const auto& internal : options_.internal_stack_patterns) {
    if (contains_case_insensitive(combined, internal)) {
      return true;
    }
  }

  return false;
}

std::vector<OracleManager::BugInfo> OracleManager::check_tsan(
    const FuzzerExecutionResult& r) {
  std::vector<BugInfo> bugs;
  std::string tsan_output = r.stderr_output;

  // When TSAN_OPTIONS includes log_path=..., reports may be written to files
  // instead of stderr. Merge newly appended log chunks into the parser input.
  const std::string tsan_log_prefix = extract_tsan_log_path_from_env();
  if (!tsan_log_prefix.empty()) {
    const auto log_files = find_tsan_log_files(tsan_log_prefix);
    for (const auto& log_file : log_files) {
      uint64_t& offset = tsan_log_offsets_[log_file.string()];
      const std::string appended = read_file_incremental(log_file, &offset);
      if (!appended.empty()) {
        if (!tsan_output.empty() && tsan_output.back() != '\n') {
          tsan_output.push_back('\n');
        }
        tsan_output += appended;
      }
    }
  }

  if (tsan_output.empty()) return bugs;

  const auto reports = parse_tsan_output(tsan_output);
  bugs.reserve(reports.size());

  for (const auto& rep : reports) {
    if (is_filtered_tsan_report(rep)) {
      continue;
    }

    if (is_internal_tsan_report(rep)) {
      ++internal_races_filtered_;
      continue;
    }

    BugInfo bug;
    const std::string race_type_lower = to_lower_copy(rep.race_type);
    const bool is_data_race =
        race_type_lower.find("data race") != std::string::npos;
    const bool is_low_signal_sync_issue =
        race_type_lower.find("lock-order-inversion") != std::string::npos ||
        race_type_lower.find("double lock") != std::string::npos;

    if (is_data_race) {
      bug.type = "tsan_race";
      bug.severity = 5;
    } else if (is_low_signal_sync_issue) {
      bug.type = "tsan_sync_issue";
      bug.severity = 2;
    } else if (race_type_lower.find("thread leak") != std::string::npos) {
      bug.type = "tsan_race";
      bug.severity = 3;
    } else {
      bug.type = "tsan_race";
      bug.severity = 4;
    }

    bug.description = "ThreadSanitizer: " + rep.race_type;
    if (rep.address != 0) {
      std::ostringstream oss;
      oss << std::hex << rep.address;
      bug.description += " at 0x" + oss.str();
    }
    if (!rep.access1_type.empty() && !rep.access2_type.empty()) {
      bug.description +=
          " (" + rep.access1_type + "/" + rep.access2_type + ")";
    }

    bug.stack_trace = rep.access1_stack;
    if (!rep.access2_stack.empty()) {
      bug.stack_trace += "---\n" + rep.access2_stack;
    }

    bugs.push_back(std::move(bug));
  }
  return bugs;
}

// ---------------------------------------------------------------------------
// OracleManager::check  (main entry-point)
// ---------------------------------------------------------------------------

std::vector<OracleManager::BugInfo> OracleManager::check(
    const FuzzerExecutionResult& result) {
  std::vector<BugInfo> bugs;

  const auto crash_bugs = check_crash(result);
  bugs.insert(bugs.end(), crash_bugs.begin(), crash_bugs.end());

  const auto tsan_bugs = check_tsan(result);
  bugs.insert(bugs.end(), tsan_bugs.begin(), tsan_bugs.end());

  return bugs;
}

}  // namespace scarab::fuzzer
