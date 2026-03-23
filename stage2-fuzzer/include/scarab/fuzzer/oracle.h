#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace scarab::fuzzer {

// Forward-declared to break the circular include with fuzzer_engine.h.
// Full definition lives in fuzzer_engine.h; oracle.cpp includes that header.
struct FuzzerExecutionResult;

/// Analyses one execution result through multiple oracle layers and returns
/// every detected fault.
///
/// Architecture reference: §3.9 Oracle
class OracleManager {
 public:
  // ── Public types ──────────────────────────────────────────────────────────

  struct Options {
    // TSan reports whose stack/raw section contains one of these substrings
    // are treated as middleware noise and ignored.
    std::vector<std::string> stack_filter = {
        // FastDDS / FastRTPS
        "eprosima",
        "fastrtps",
        "fastdds",
        "rmw_fastrtps",
        // CycloneDDS
        "cyclonedds",
        "libddsc",
        "ddsrt_",
        "rmw_cyclonedds",
    };

    // Patterns identifying SCARAB-internal code in TSan stacks.  A report
    // whose stacks match at least one of these patterns AND none of the
    // target_source_patterns is classified as an internal tool race and
    // filtered out.
    std::vector<std::string> internal_stack_patterns = {
        "scarab::fuzzer::",
        "scarab/fuzzer/",
        "stage2-fuzzer/src/",
        "recorder.cpp",
        "instrumented_executor.cpp",
        "fuzzer_engine.cpp",
        "Recorder::",
        "InstrumentedExecutor::",
        "FuzzerEngine::",
        "EngineMiniNode",
    };

    // Patterns identifying target application code (e.g. nav2).  If ANY of
    // these appear in a race report's stacks, the report is NOT filtered —
    // it may be a real target bug.
    std::vector<std::string> target_source_patterns = {
        "nav2_",
        "navigation2/",
    };
  };

  /// A single detected fault.
  struct BugInfo {
    std::string type;         ///< "crash", "tsan_race", "asan_error", …
    std::string description;  ///< Human-readable one-liner
    std::string stack_trace;  ///< Raw stack text extracted from output
    int severity = 1;         ///< 1 (informational) – 5 (critical)
  };

  /// Parsed representation of one ThreadSanitizer report block.
  struct TSanReport {
    std::string race_type;     ///< "data race", "thread leak", …
    std::string access1_type;  ///< "Write" or "Read"
    std::string access2_type;  ///< "write" or "read" (the "Previous …" access)
    std::string access1_stack;
    std::string access2_stack;
    std::string raw_text;      ///< Full raw section body (for filtering)
    uint64_t address = 0;
    int size = 0;
  };

  // ── Public API ────────────────────────────────────────────────────────────

  OracleManager();
  explicit OracleManager(Options options);

  void set_options(Options options);
  const Options& options() const;

  /// Number of TSan reports filtered as SCARAB-internal tool races.
  uint32_t internal_races_filtered() const { return internal_races_filtered_; }

  /// Prime per-file TSan offsets for current TSAN_OPTIONS(log_path=...) prefix.
  /// This snapshots existing log sizes so check() only consumes newly appended
  /// reports for the current execution.
  void prime_tsan_log_offsets_from_env();

  /// Run all oracle layers (crash, TSan, …) against the given result.
  /// Returns every detected bug; empty vector means clean execution.
  std::vector<BugInfo> check(const FuzzerExecutionResult& result);

  /// Parse raw TSan stderr text into structured TSanReport objects.
  /// Thread-safe (reads no mutable state).  Exposed for unit testing.
  static std::vector<TSanReport> parse_tsan_output(
      const std::string& stderr_output);

 private:
  bool is_filtered_tsan_report(const TSanReport& report) const;
  bool is_internal_tsan_report(const TSanReport& report) const;

  // L1: crash / sanitizer oracles
  std::vector<BugInfo> check_crash(const FuzzerExecutionResult& r);
  std::vector<BugInfo> check_tsan(const FuzzerExecutionResult& r);

  // Tracks consumed byte offsets per TSan log file when TSAN_OPTIONS contains
  // log_path=... so each check() call only processes newly appended reports.
  std::unordered_map<std::string, uint64_t> tsan_log_offsets_;
  Options options_;
  uint32_t internal_races_filtered_ = 0;
};

}  // namespace scarab::fuzzer
