#pragma once

#include <optional>
#include <string>
#include <unordered_map>

namespace scarab::analyzer {

/// Tracks local variable aliases to member fields within a function scope.
///
/// Supported patterns:
///   Rule 1 (reference binding):  auto& x = this->field_;
///   Rule 2 (pointer-to-field):   auto* p = &this->field_;
///   Rule 3 (1-hop deref):        auto& n = this->ptr_->data;
///
/// Usage:
///   1. Call reset() at the start of each function analysis.
///   2. Call track_alias() for each VarDecl whose initializer is a member access.
///   3. Call resolve() when encountering a DeclRefExpr to map alias → original field.
class AliasTracker {
 public:
  AliasTracker() = default;

  /// Clears all tracked aliases. Call once per function scope.
  void reset();

  /// Records that `alias_name` refers to the member field `target_field`.
  /// For chained aliases (auto& c = a; where a → field_), call with the
  /// intermediate name and it will be resolved transitively by resolve().
  void track_alias(const std::string& alias_name, const std::string& target_field);

  /// Resolves an alias name to its original member field name.
  /// Follows chains transitively (a → b → field_ returns "field_").
  /// Returns std::nullopt if the name is not a tracked alias.
  std::optional<std::string> resolve(const std::string& name) const;

  // Legacy API — delegates to the new names.
  void observe_var_decl(const std::string& alias_name, const std::string& target_name);
  std::optional<std::string> resolve_alias(const std::string& alias_name) const;

 private:
  // alias_name → target (may be another alias or a field name)
  std::unordered_map<std::string, std::string> alias_map_;

  static constexpr int kMaxChainDepth = 8;
};

}  // namespace scarab::analyzer
