#pragma once

#include <vector>

#include "scarab/common/race_candidate.h"

namespace scarab::analyzer {

class CallbackGroupAnalyzer {
 public:
  CallbackGroupAnalyzer() = default;

  void analyze(const std::vector<scarab::common::CallbackInfo>& callbacks);
  bool can_execute_concurrently(const scarab::common::CallbackInfo& callback_a,
                                const scarab::common::CallbackInfo& callback_b) const;
};

}  // namespace scarab::analyzer
