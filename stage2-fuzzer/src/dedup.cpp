#include "scarab/fuzzer/dedup.h"

#include <algorithm>
#include <cctype>
#include <sstream>

namespace scarab::fuzzer {

bool Deduplicator::observe(const OracleManager::BugInfo& bug) {
  ++total_reports_;
  const std::string signature = build_signature(bug);
  const auto [it, inserted] = signature_counts_.emplace(signature, 1);
  if (!inserted) {
    ++it->second;
    return false;
  }
  return true;
}

size_t Deduplicator::total_reports() const { return total_reports_; }

size_t Deduplicator::unique_reports() const { return signature_counts_.size(); }

std::string Deduplicator::build_signature(const OracleManager::BugInfo& bug) {
  constexpr size_t kDescPrefix = 50;
  constexpr size_t kTopFrames = 3;

  const std::string desc_prefix =
      bug.description.substr(0, std::min(kDescPrefix, bug.description.size()));
  const std::string stack_key = stack_top_frames_key(bug.stack_trace, kTopFrames);
  const uint64_t stack_hash = fnv1a64(stack_key);

  std::ostringstream oss;
  oss << bug.type << "|" << desc_prefix << "|" << std::hex << stack_hash;
  return oss.str();
}

std::string Deduplicator::stack_top_frames_key(const std::string& stack_trace,
                                               size_t frame_limit) {
  std::istringstream stream(stack_trace);
  std::string line;
  std::string key;
  size_t frames = 0;

  while (frames < frame_limit && std::getline(stream, line)) {
    size_t i = 0;
    while (i < line.size() &&
           std::isspace(static_cast<unsigned char>(line[i])) != 0) {
      ++i;
    }
    if (i >= line.size() || line[i] != '#') {
      continue;
    }

    if (!key.empty()) {
      key += '\n';
    }
    key += line.substr(i);
    ++frames;
  }
  return key;
}

uint64_t Deduplicator::fnv1a64(const std::string& text) {
  uint64_t hash = 1469598103934665603ull;
  for (unsigned char c : text) {
    hash ^= static_cast<uint64_t>(c);
    hash *= 1099511628211ull;
  }
  return hash;
}

}  // namespace scarab::fuzzer
