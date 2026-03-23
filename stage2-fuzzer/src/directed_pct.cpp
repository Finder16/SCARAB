#include "scarab/fuzzer/directed_pct.h"

#include <algorithm>
#include <numeric>

namespace scarab::fuzzer {

DirectedPctScheduler::DirectedPctScheduler(
    const std::vector<scarab::common::RaceCandidate>& candidates)
    : candidates_(candidates) {
  candidate_weights_.resize(candidates_.size());
  for (size_t i = 0; i < candidates_.size(); ++i) {
    // Higher RaceCandidate priority → higher initial weight.
    float base = 1.0f + static_cast<float>(candidates_[i].priority) * 0.5f;
    candidate_weights_[i] = std::max(kMinWeight, base);
  }
}

void DirectedPctScheduler::set_bug_depth(int depth) {
  bug_depth_ = std::max(1, depth);
}

size_t DirectedPctScheduler::select_candidate_index(std::mt19937& rng) const {
  if (candidates_.size() <= 1) {
    return 0;
  }

  std::discrete_distribution<size_t> dist(candidate_weights_.begin(),
                                          candidate_weights_.end());
  return dist(rng);
}

FuzzSchedule DirectedPctScheduler::generate_schedule(const Seed& base,
                                                     std::mt19937& rng) const {
  FuzzSchedule schedule = FuzzSchedule::from_seed(base);
  if (schedule.entries.empty() || candidates_.empty()) {
    return schedule;
  }

  const size_t N = schedule.entries.size();

  // ── 1. Find the RaceCandidate this seed targets ────────────────────────
  const uint32_t target_cid = base.header().candidate_id;
  const scarab::common::RaceCandidate* target = nullptr;
  size_t target_candidate_idx = 0;
  for (size_t i = 0; i < candidates_.size(); ++i) {
    auto parsed = Seed::candidate_id_from_string(candidates_[i].id);
    if (parsed.has_value() && *parsed == target_cid) {
      target = &candidates_[i];
      target_candidate_idx = i;
      break;
    }
  }
  // Fallback: pick a candidate based on weights.
  if (target == nullptr) {
    target_candidate_idx = select_candidate_index(
        const_cast<std::mt19937&>(rng));
    target = &candidates_[target_candidate_idx];
  }

  // ── 2. Assign random priorities 1..N ───────────────────────────────────
  std::vector<int> priorities(N);
  std::iota(priorities.begin(), priorities.end(), 1);
  std::shuffle(priorities.begin(), priorities.end(), rng);

  // ── 3. Identify entries involved in the race pair ──────────────────────
  // By Seed::create_initial convention, callback_id 0 = callback_a,
  // callback_id 1 = callback_b.
  std::vector<size_t> race_entry_indices;
  for (size_t i = 0; i < N; ++i) {
    if (schedule.entries[i].callback_id <= 1) {
      race_entry_indices.push_back(i);
    }
  }

  // ── 4. Place d-1 priority change points ────────────────────────────────
  // At each change point a specific callback's priority is demoted to 0
  // (the lowest), forcing it to wait longer and letting other callbacks
  // execute first.  The "directed" aspect biases change points towards
  // entries belonging to the race pair (kDirectedBias probability).
  const int num_change_points = std::max(0, bug_depth_ - 1);
  for (int cp = 0; cp < num_change_points; ++cp) {
    size_t target_idx = 0;

    std::uniform_real_distribution<float> bias_roll(0.0f, 1.0f);
    if (!race_entry_indices.empty() && bias_roll(rng) < kDirectedBias) {
      std::uniform_int_distribution<size_t> race_dist(
          0, race_entry_indices.size() - 1);
      target_idx = race_entry_indices[race_dist(rng)];
    } else {
      std::uniform_int_distribution<size_t> all_dist(0, N - 1);
      target_idx = all_dist(rng);
    }

    // Demote to lowest priority.
    priorities[target_idx] = 0;
  }

  // ── 5. Convert priorities to delay_us ──────────────────────────────────
  // Lower priority ⟹ higher rank ⟹ larger delay.
  int max_priority = *std::max_element(priorities.begin(), priorities.end());
  if (max_priority <= 0) {
    max_priority = 1;
  }

  for (size_t i = 0; i < N; ++i) {
    auto rank = static_cast<uint32_t>(max_priority - priorities[i]);
    uint32_t delay = rank * kDelayStepUs;

    std::uniform_int_distribution<uint32_t> jitter(0, kMaxJitterUs);
    delay += jitter(rng);

    schedule.entries[i].delay_us = delay;
  }

  // ── 6. Populate access-point-level delays from target candidate ────────
  // Assign delays to the specific source lines where the race pair accesses
  // the shared variable.  This guides libscarab_rt to inject delays at the
  // exact instrumented load/store points identified by Stage 1.
  if (target != nullptr) {
    if (target->line_a > 0) {
      std::uniform_int_distribution<uint32_t> access_jitter(100, kDelayStepUs);
      schedule.access_point_delays[target->line_a] = access_jitter(rng);
    }
    if (target->line_b > 0) {
      std::uniform_int_distribution<uint32_t> access_jitter(100, kDelayStepUs);
      schedule.access_point_delays[target->line_b] = access_jitter(rng);
    }
  }

  return schedule;
}

void DirectedPctScheduler::update_priorities(bool bug_found,
                                             uint32_t candidate_id) {
  for (size_t i = 0; i < candidates_.size(); ++i) {
    auto parsed = Seed::candidate_id_from_string(candidates_[i].id);
    if (parsed.has_value() && *parsed == candidate_id) {
      if (bug_found) {
        candidate_weights_[i] = std::max(
            kMinWeight, candidate_weights_[i] * kBugFoundBoost);
      }
      break;
    }
  }
}

}  // namespace scarab::fuzzer
