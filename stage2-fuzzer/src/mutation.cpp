#include "scarab/fuzzer/mutation.h"

#include "scarab/common/logging.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <utility>

namespace scarab::fuzzer {

namespace {

int64_t clamp_i64(int64_t value, int64_t min_value, int64_t max_value) {
  return std::max(min_value, std::min(max_value, value));
}

}  // namespace

MutationEngine::MutationEngine(uint32_t seed) : internal_rng_(seed) {}

MutationEngine::MutationEngine(const MutationWeights& weights, uint32_t seed)
    : weights_(weights), internal_rng_(seed) {}

void MutationEngine::sync_header_counts(Seed* seed) {
  if (seed == nullptr) {
    return;
  }
  seed->header().magic = Seed::kMagic;
  seed->header().version = Seed::kVersion;
  seed->header().num_schedule_entries =
      static_cast<uint16_t>(seed->schedule_entries().size());
  seed->header().num_messages = static_cast<uint16_t>(seed->messages().size());
}

bool MutationEngine::is_valid_or_fallback(const Seed& original, Seed* candidate) {
  if (candidate == nullptr) {
    return false;
  }
  sync_header_counts(candidate);
  if (candidate->is_valid()) {
    return true;
  }

  scarab::common::log_error(
      "Mutation produced invalid seed. Falling back to original seed.");
  *candidate = original;
  sync_header_counts(candidate);
  return candidate->is_valid();
}

MutationType MutationEngine::pick_mutation(std::mt19937& rng) const {
  const std::array<std::pair<MutationType, float>, 10> weighted_mutations = {{
      {MutationType::PERTURB_DELAY, weights_.perturb_delay},
      {MutationType::SWAP_CALLBACK_ORDER, weights_.swap_callback_order},
      {MutationType::ADD_PREEMPTION, weights_.add_preemption},
      {MutationType::REMOVE_PREEMPTION, weights_.remove_preemption},
      {MutationType::PERTURB_TIMING, weights_.perturb_timing},
      {MutationType::SWAP_MESSAGE_ORDER, weights_.swap_message_order},
      {MutationType::CHANGE_THREAD, weights_.change_thread},
      {MutationType::MUTATE_PAYLOAD, weights_.mutate_payload},
      {MutationType::DUPLICATE_MESSAGE, weights_.duplicate_message},
      {MutationType::DROP_MESSAGE, weights_.drop_message},
  }};

  float total = 0.0F;
  for (const auto& [type, weight] : weighted_mutations) {
    (void)type;
    if (weight > 0.0F) {
      total += weight;
    }
  }
  if (total <= 0.0F) {
    return MutationType::PERTURB_DELAY;
  }

  std::uniform_real_distribution<float> pick_dist(0.0F, total);
  const float picked = pick_dist(rng);

  float cumulative = 0.0F;
  for (const auto& [type, weight] : weighted_mutations) {
    if (weight <= 0.0F) {
      continue;
    }
    cumulative += weight;
    if (picked <= cumulative) {
      return type;
    }
  }
  return MutationType::PERTURB_DELAY;
}

Seed MutationEngine::mutate(const Seed& seed, std::mt19937& rng) const {
  if (!seed.is_valid()) {
    return seed;
  }
  return apply_mutation(seed, pick_mutation(rng), rng);
}

Seed MutationEngine::mutate(const Seed& seed) {
  return mutate(seed, internal_rng_);
}

Seed MutationEngine::apply_mutation(const Seed& seed, MutationType mutation_type,
                                    std::mt19937& rng) const {
  Seed mutated = seed;

  switch (mutation_type) {
    case MutationType::PERTURB_DELAY:
      mutated = perturb_delay(seed, rng);
      break;
    case MutationType::SWAP_CALLBACK_ORDER:
      mutated = swap_callback_order(seed, rng);
      break;
    case MutationType::ADD_PREEMPTION:
      mutated = add_preemption(seed, rng);
      break;
    case MutationType::REMOVE_PREEMPTION:
      mutated = remove_preemption(seed, rng);
      break;
    case MutationType::PERTURB_TIMING:
      mutated = perturb_timing(seed, rng);
      break;
    case MutationType::SWAP_MESSAGE_ORDER:
      mutated = swap_message_order(seed, rng);
      break;
    case MutationType::CHANGE_THREAD:
      mutated = change_thread(seed, rng);
      break;
    case MutationType::MUTATE_PAYLOAD:
      mutated = mutate_payload(seed, rng);
      break;
    case MutationType::DUPLICATE_MESSAGE:
      mutated = duplicate_message(seed, rng);
      break;
    case MutationType::DROP_MESSAGE:
      mutated = drop_message(seed, rng);
      break;
  }

  if (!is_valid_or_fallback(seed, &mutated)) {
    return seed;
  }
  return mutated;
}

Seed MutationEngine::perturb_delay(const Seed& seed, std::mt19937& rng) const {
  Seed mutated = seed;
  auto& entries = mutated.schedule_entries();
  if (entries.empty()) {
    return mutated;
  }

  std::uniform_int_distribution<size_t> entry_dist(0, entries.size() - 1);
  const size_t idx = entry_dist(rng);

  std::uniform_int_distribution<int> delta_dist(-1000, 1000);
  int delta = 0;
  do {
    delta = delta_dist(rng);
  } while (delta == 0);

  const int64_t current = static_cast<int64_t>(entries[idx].delay_us);
  const int64_t next = clamp_i64(
      current + delta, 0, static_cast<int64_t>(std::numeric_limits<uint32_t>::max()));
  entries[idx].delay_us = static_cast<uint32_t>(next);
  return mutated;
}

Seed MutationEngine::swap_callback_order(const Seed& seed, std::mt19937& rng) const {
  Seed mutated = seed;
  auto& entries = mutated.schedule_entries();
  if (entries.size() < 2) {
    return mutated;
  }

  std::uniform_int_distribution<size_t> idx_dist(0, entries.size() - 1);
  size_t first = idx_dist(rng);
  size_t second = idx_dist(rng);
  while (second == first) {
    second = idx_dist(rng);
  }
  std::swap(entries[first], entries[second]);
  return mutated;
}

Seed MutationEngine::add_preemption(const Seed& seed, std::mt19937& rng) const {
  Seed mutated = seed;
  auto& entries = mutated.schedule_entries();
  if (entries.empty()) {
    return mutated;
  }

  std::vector<size_t> candidates;
  candidates.reserve(entries.size());
  for (size_t i = 0; i < entries.size(); ++i) {
    if (entries[i].preemptions.size() < std::numeric_limits<uint8_t>::max()) {
      candidates.push_back(i);
    }
  }
  if (candidates.empty()) {
    return mutated;
  }

  std::uniform_int_distribution<size_t> pick_entry(0, candidates.size() - 1);
  const size_t entry_idx = candidates[pick_entry(rng)];
  auto& preemptions = entries[entry_idx].preemptions;

  PreemptionEntry preemption;
  std::uniform_int_distribution<uint16_t> access_dist(1, std::numeric_limits<uint16_t>::max());
  std::uniform_int_distribution<uint32_t> yield_dist(1, 1000);
  preemption.access_point_id = access_dist(rng);
  preemption.yield_duration_us = yield_dist(rng);

  std::uniform_int_distribution<size_t> insert_dist(0, preemptions.size());
  const size_t insert_idx = insert_dist(rng);
  preemptions.insert(preemptions.begin() + static_cast<std::ptrdiff_t>(insert_idx), preemption);
  return mutated;
}

Seed MutationEngine::remove_preemption(const Seed& seed, std::mt19937& rng) const {
  Seed mutated = seed;
  auto& entries = mutated.schedule_entries();
  if (entries.empty()) {
    return mutated;
  }

  std::vector<size_t> entries_with_preemption;
  entries_with_preemption.reserve(entries.size());
  for (size_t i = 0; i < entries.size(); ++i) {
    if (!entries[i].preemptions.empty()) {
      entries_with_preemption.push_back(i);
    }
  }
  if (entries_with_preemption.empty()) {
    return mutated;
  }

  std::uniform_int_distribution<size_t> entry_dist(0, entries_with_preemption.size() - 1);
  const size_t entry_idx = entries_with_preemption[entry_dist(rng)];
  auto& preemptions = entries[entry_idx].preemptions;

  std::uniform_int_distribution<size_t> preemption_dist(0, preemptions.size() - 1);
  const size_t remove_idx = preemption_dist(rng);
  preemptions.erase(preemptions.begin() + static_cast<std::ptrdiff_t>(remove_idx));
  return mutated;
}

Seed MutationEngine::perturb_timing(const Seed& seed, std::mt19937& rng) const {
  Seed mutated = seed;
  auto& messages = mutated.messages();
  if (messages.empty()) {
    // Fall back to perturbing schedule delay if no messages.
    return perturb_delay(seed, rng);
  }

  std::uniform_int_distribution<size_t> msg_dist(0, messages.size() - 1);
  const size_t idx = msg_dist(rng);

  // Perturb offset_us by ±2000 microseconds.
  std::uniform_int_distribution<int> delta_dist(-2000, 2000);
  int delta = 0;
  do {
    delta = delta_dist(rng);
  } while (delta == 0);

  const int64_t current = static_cast<int64_t>(messages[idx].offset_us);
  const int64_t next = clamp_i64(
      current + delta, 0, static_cast<int64_t>(std::numeric_limits<uint32_t>::max()));
  messages[idx].offset_us = static_cast<uint32_t>(next);
  return mutated;
}

Seed MutationEngine::swap_message_order(const Seed& seed, std::mt19937& rng) const {
  Seed mutated = seed;
  auto& messages = mutated.messages();
  if (messages.size() < 2) {
    // Fall back to swapping callback order if not enough messages.
    return swap_callback_order(seed, rng);
  }

  std::uniform_int_distribution<size_t> idx_dist(0, messages.size() - 1);
  size_t first = idx_dist(rng);
  size_t second = idx_dist(rng);
  while (second == first) {
    second = idx_dist(rng);
  }
  std::swap(messages[first], messages[second]);
  return mutated;
}

Seed MutationEngine::change_thread(const Seed& seed, std::mt19937& rng) const {
  Seed mutated = seed;
  auto& entries = mutated.schedule_entries();
  if (entries.empty()) {
    return mutated;
  }

  std::uniform_int_distribution<size_t> entry_dist(0, entries.size() - 1);
  const size_t idx = entry_dist(rng);

  // Assign a random thread_id in [0, 7] (covers typical multi-threaded executors).
  std::uniform_int_distribution<uint8_t> thread_dist(0, 7);
  uint8_t new_thread = entries[idx].thread_id;
  // Ensure we actually change the thread.
  do {
    new_thread = thread_dist(rng);
  } while (new_thread == entries[idx].thread_id && entries.size() > 1);
  entries[idx].thread_id = new_thread;
  return mutated;
}

Seed MutationEngine::mutate_payload(const Seed& seed, std::mt19937& rng) const {
  Seed mutated = seed;
  auto& messages = mutated.messages();
  if (messages.empty()) {
    // Fall back to delay perturbation if no messages.
    return perturb_delay(seed, rng);
  }

  std::uniform_int_distribution<size_t> msg_dist(0, messages.size() - 1);
  const size_t idx = msg_dist(rng);
  auto& payload = messages[idx].payload;

  if (payload.empty()) {
    // Insert a random byte.
    std::uniform_int_distribution<uint8_t> byte_dist(0, 255);
    payload.push_back(byte_dist(rng));
  } else {
    // Flip a random bit in a random byte.
    std::uniform_int_distribution<size_t> pos_dist(0, payload.size() - 1);
    const size_t pos = pos_dist(rng);
    std::uniform_int_distribution<int> bit_dist(0, 7);
    payload[pos] ^= static_cast<uint8_t>(1u << bit_dist(rng));
  }
  return mutated;
}

Seed MutationEngine::duplicate_message(const Seed& seed, std::mt19937& rng) const {
  Seed mutated = seed;
  auto& messages = mutated.messages();
  if (messages.empty()) {
    return mutated;
  }
  // Cap at 255 messages to stay within uint16_t header count.
  if (messages.size() >= 255) {
    return mutated;
  }

  std::uniform_int_distribution<size_t> msg_dist(0, messages.size() - 1);
  const size_t src_idx = msg_dist(rng);
  MessageEntry dup = messages[src_idx];

  // Optionally offset the duplicate slightly in time.
  std::uniform_int_distribution<uint32_t> jitter_dist(0, 500);
  dup.offset_us = static_cast<uint32_t>(clamp_i64(
      static_cast<int64_t>(dup.offset_us) + jitter_dist(rng),
      0, static_cast<int64_t>(std::numeric_limits<uint32_t>::max())));

  // Insert after the source.
  messages.insert(
      messages.begin() + static_cast<std::ptrdiff_t>(src_idx + 1), dup);
  return mutated;
}

Seed MutationEngine::drop_message(const Seed& seed, std::mt19937& rng) const {
  Seed mutated = seed;
  auto& messages = mutated.messages();
  if (messages.empty()) {
    return mutated;
  }

  std::uniform_int_distribution<size_t> msg_dist(0, messages.size() - 1);
  const size_t idx = msg_dist(rng);
  messages.erase(messages.begin() + static_cast<std::ptrdiff_t>(idx));
  return mutated;
}

}  // namespace scarab::fuzzer
