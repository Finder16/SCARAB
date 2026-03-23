#include "scarab/analyzer/sync_checker.h"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <regex>

namespace scarab::analyzer {

namespace {

std::string canonical_or_input(const std::string& path) {
  std::error_code ec;
  const auto canonical = std::filesystem::weakly_canonical(path, ec);
  if (ec) {
    return path;
  }
  return canonical.string();
}

std::string to_lower(std::string text) {
  std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return text;
}

}  // namespace

scarab::common::SyncStatus SyncChecker::check(const AccessInfo& access,
                                              std::string* protecting_mutex) const {
  if (protecting_mutex != nullptr) {
    protecting_mutex->clear();
  }

  if (is_atomic_type(access.variable_type)) {
    return scarab::common::SyncStatus::PROTECTED;
  }

  if (access.source_file.empty() || access.line <= 0) {
    return scarab::common::SyncStatus::UNKNOWN;
  }

  const auto& file_info = get_file_sync_info(access.source_file);
  if (is_within_lock_scope(access.line, file_info.lock_scopes, protecting_mutex)) {
    return scarab::common::SyncStatus::PROTECTED;
  }

  if (file_info.has_complex_sync_pattern) {
    return scarab::common::SyncStatus::UNKNOWN;
  }

  return scarab::common::SyncStatus::UNPROTECTED;
}

AccessInfo SyncChecker::annotate(const AccessInfo& access) const {
  AccessInfo annotated = access;
  std::string mutex_name;
  annotated.sync_status = check(access, &mutex_name);
  annotated.protecting_mutex = mutex_name;
  return annotated;
}

const SyncChecker::FileSyncInfo& SyncChecker::get_file_sync_info(const std::string& source_file) const {
  const std::string canonical = canonical_or_input(source_file);
  const auto found = file_cache_.find(canonical);
  if (found != file_cache_.end()) {
    return found->second;
  }

  const auto inserted = file_cache_.emplace(canonical, build_file_sync_info(canonical));
  return inserted.first->second;
}

SyncChecker::FileSyncInfo SyncChecker::build_file_sync_info(const std::string& source_file) const {
  FileSyncInfo info;

  std::ifstream input(source_file);
  if (!input.good()) {
    return info;
  }

  std::vector<std::string> lines;
  std::string line_text;
  while (std::getline(input, line_text)) {
    lines.push_back(line_text);
  }

  std::vector<int> depth_before(lines.size() + 1, 0);
  int depth = 0;

  const std::regex raii_lock(
      R"((?:std::)?(?:lock_guard|scoped_lock|unique_lock)\s*<[^>]+>\s+[A-Za-z_][A-Za-z0-9_]*\s*(?:\(|\{)\s*([A-Za-z_][A-Za-z0-9_]*)\b)");
  const std::regex raw_lock(R"((?:\.|->)\s*lock\s*\()");
  const std::regex raw_unlock(R"((?:\.|->)\s*unlock\s*\()");
  const std::regex complex_sync(R"((condition_variable|atomic_flag|semaphore|futex|pthread_mutex_))");

  for (size_t idx = 0; idx < lines.size(); ++idx) {
    const int line_no = static_cast<int>(idx + 1);
    depth_before[line_no] = depth;

    std::smatch raii_match;
    if (std::regex_search(lines[idx], raii_match, raii_lock) && raii_match.size() > 1) {
      LockScope scope;
      scope.mutex_name = raii_match.str(1);
      scope.start_line = line_no;
      scope.end_line = static_cast<int>(lines.size());
      scope.scope_depth = depth_before[line_no];
      info.lock_scopes.push_back(std::move(scope));
    }

    if (std::regex_search(lines[idx], raw_lock) || std::regex_search(lines[idx], raw_unlock) ||
        std::regex_search(lines[idx], complex_sync)) {
      info.has_complex_sync_pattern = true;
    }

    for (char c : lines[idx]) {
      if (c == '{') {
        ++depth;
      } else if (c == '}') {
        --depth;
      }
    }
  }

  for (auto& scope : info.lock_scopes) {
    for (int line = scope.start_line + 1; line <= static_cast<int>(lines.size()); ++line) {
      if (depth_before[line] < scope.scope_depth) {
        scope.end_line = line - 1;
        break;
      }
    }
  }

  return info;
}

bool SyncChecker::is_atomic_type(std::string_view variable_type) const {
  const std::string lower = to_lower(std::string(variable_type));
  return lower.find("atomic<") != std::string::npos || lower.find("std::atomic") != std::string::npos;
}

bool SyncChecker::is_within_lock_scope(int access_line, const std::vector<LockScope>& scopes,
                                       std::string* protecting_mutex) const {
  for (const auto& scope : scopes) {
    if (access_line >= scope.start_line && access_line <= scope.end_line) {
      if (protecting_mutex != nullptr) {
        *protecting_mutex = scope.mutex_name;
      }
      return true;
    }
  }
  return false;
}

}  // namespace scarab::analyzer
