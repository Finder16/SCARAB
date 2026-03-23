#include "scarab/analyzer/alias_tracker.h"

namespace scarab::analyzer {

void AliasTracker::reset() { alias_map_.clear(); }

void AliasTracker::track_alias(const std::string& alias_name, const std::string& target_field) {
  if (alias_name.empty() || target_field.empty() || alias_name == target_field) {
    return;
  }
  alias_map_[alias_name] = target_field;
}

std::optional<std::string> AliasTracker::resolve(const std::string& name) const {
  auto it = alias_map_.find(name);
  if (it == alias_map_.end()) {
    return std::nullopt;
  }

  // Follow transitive chains: a → b → field_
  std::string current = it->second;
  for (int depth = 0; depth < kMaxChainDepth; ++depth) {
    auto next = alias_map_.find(current);
    if (next == alias_map_.end()) {
      break;
    }
    current = next->second;
  }
  return current;
}

// Legacy API
void AliasTracker::observe_var_decl(const std::string& alias_name,
                                     const std::string& target_name) {
  track_alias(alias_name, target_name);
}

std::optional<std::string> AliasTracker::resolve_alias(const std::string& alias_name) const {
  return resolve(alias_name);
}

}  // namespace scarab::analyzer
