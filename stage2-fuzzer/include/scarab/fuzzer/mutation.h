#pragma once

#include <random>

#include "scarab/fuzzer/seed.h"

namespace scarab::fuzzer {

enum class MutationType {
  PERTURB_DELAY,
  SWAP_CALLBACK_ORDER,
  ADD_PREEMPTION,
  REMOVE_PREEMPTION,
  PERTURB_TIMING,
  SWAP_MESSAGE_ORDER,
  CHANGE_THREAD,
  MUTATE_PAYLOAD,
  DUPLICATE_MESSAGE,
  DROP_MESSAGE,
};

class MutationEngine {
 public:
  struct MutationWeights {
    float perturb_delay = 0.20F;
    float swap_callback_order = 0.15F;
    float add_preemption = 0.10F;
    float remove_preemption = 0.10F;
    float change_thread = 0.05F;
    float perturb_timing = 0.15F;
    float swap_message_order = 0.10F;
    float mutate_payload = 0.05F;
    float duplicate_message = 0.05F;
    float drop_message = 0.05F;
  };

  explicit MutationEngine(uint32_t seed = 0xC0FFEEu);
  explicit MutationEngine(const MutationWeights& weights, uint32_t seed = 0xC0FFEEu);

  Seed mutate(const Seed& seed, std::mt19937& rng) const;
  Seed mutate(const Seed& seed);

  Seed apply_mutation(const Seed& seed, MutationType mutation_type,
                      std::mt19937& rng) const;

  Seed perturb_delay(const Seed& seed, std::mt19937& rng) const;
  Seed swap_callback_order(const Seed& seed, std::mt19937& rng) const;
  Seed add_preemption(const Seed& seed, std::mt19937& rng) const;
  Seed remove_preemption(const Seed& seed, std::mt19937& rng) const;

  Seed perturb_timing(const Seed& seed, std::mt19937& rng) const;
  Seed swap_message_order(const Seed& seed, std::mt19937& rng) const;
  Seed change_thread(const Seed& seed, std::mt19937& rng) const;
  Seed mutate_payload(const Seed& seed, std::mt19937& rng) const;
  Seed duplicate_message(const Seed& seed, std::mt19937& rng) const;
  Seed drop_message(const Seed& seed, std::mt19937& rng) const;

 private:
  static void sync_header_counts(Seed* seed);
  static bool is_valid_or_fallback(const Seed& original, Seed* candidate);
  MutationType pick_mutation(std::mt19937& rng) const;

  MutationWeights weights_;
  std::mt19937 internal_rng_;
};

}  // namespace scarab::fuzzer
