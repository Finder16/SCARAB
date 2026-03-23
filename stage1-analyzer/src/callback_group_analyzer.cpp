#include "scarab/analyzer/callback_group_analyzer.h"

namespace scarab::analyzer {

void CallbackGroupAnalyzer::analyze(const std::vector<scarab::common::CallbackInfo>& callbacks) {
  (void)callbacks;
}

bool CallbackGroupAnalyzer::can_execute_concurrently(
    const scarab::common::CallbackInfo& callback_a,
    const scarab::common::CallbackInfo& callback_b) const {
  const bool both_mutually_exclusive =
      callback_a.group_type == scarab::common::CallbackGroupType::MUTUALLY_EXCLUSIVE &&
      callback_b.group_type == scarab::common::CallbackGroupType::MUTUALLY_EXCLUSIVE;

  if (!both_mutually_exclusive) {
    return true;
  }

  return callback_a.callback_group != callback_b.callback_group;
}

}  // namespace scarab::analyzer
