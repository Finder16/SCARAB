#pragma once

#include <cstddef>
#include <string>
#include <unordered_map>

#include "scarab/fuzzer/oracle.h"

namespace scarab::fuzzer {

class Deduplicator {
 public:
  Deduplicator() = default;

  // Returns true when this is the first time this signature is observed.
  bool observe(const OracleManager::BugInfo& bug);

  size_t total_reports() const;
  size_t unique_reports() const;

  static std::string build_signature(const OracleManager::BugInfo& bug);

 private:
  static std::string stack_top_frames_key(const std::string& stack_trace,
                                          size_t frame_limit);
  static uint64_t fnv1a64(const std::string& text);

  size_t total_reports_ = 0;
  std::unordered_map<std::string, size_t> signature_counts_;
};

}  // namespace scarab::fuzzer
