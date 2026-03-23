#pragma once

#include <cstdint>
#include <random>
#include <vector>

#include "scarab/common/race_candidate.h"
#include "scarab/fuzzer/instrumented_executor.h"

namespace scarab::fuzzer {

/// Callback-level Directed PCT scheduler.
///
/// Assigns random priorities to callbacks and places d-1 priority change
/// points biased towards the conflicting callback pair identified by the
/// target RaceCandidate.  Priorities are converted to delay_us values so
/// that lower-priority callbacks sleep longer, yielding execution time to
/// higher-priority ones.
class DirectedPctScheduler {
 public:
  DirectedPctScheduler() = default;
  explicit DirectedPctScheduler(
      const std::vector<scarab::common::RaceCandidate>& candidates);

  /// Generate a PCT-directed schedule from the base seed.
  FuzzSchedule generate_schedule(const Seed& base, std::mt19937& rng) const;

  /// Feed back execution result to adjust candidate weights.
  /// When a bug is found for a candidate, its weight is boosted.
  void update_priorities(bool bug_found, uint32_t candidate_id);

  /// Weighted random candidate selection.
  size_t select_candidate_index(std::mt19937& rng) const;

  const std::vector<float>& candidate_weights() const {
    return candidate_weights_;
  }
  int bug_depth() const { return bug_depth_; }
  void set_bug_depth(int depth);
  bool empty() const { return candidates_.empty(); }
  size_t num_candidates() const { return candidates_.size(); }

 private:
  std::vector<scarab::common::RaceCandidate> candidates_;
  std::vector<float> candidate_weights_;
  int bug_depth_ = 2;

  // Delay assigned per priority rank (lower priority = more delay).
  static constexpr uint32_t kDelayStepUs = 500;
  // Random jitter added to each delay for variety.
  static constexpr uint32_t kMaxJitterUs = 100;
  // Probability that a change point targets a race-relevant entry.
  static constexpr float kDirectedBias = 0.8f;
  // Multiplicative boost applied to a candidate's weight after a bug find.
  static constexpr float kBugFoundBoost = 2.0f;
  // Floor value for any candidate weight.
  static constexpr float kMinWeight = 0.1f;
};

}  // namespace scarab::fuzzer
