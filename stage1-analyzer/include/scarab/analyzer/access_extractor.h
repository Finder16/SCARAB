#pragma once

#include <functional>
#include <map>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "scarab/analyzer/alias_tracker.h"
#include "scarab/analyzer/race_candidate.h"

#ifndef SCARAB_HAS_CLANG_TOOLING
#define SCARAB_HAS_CLANG_TOOLING 0
#endif

#if SCARAB_HAS_CLANG_TOOLING
#include <clang/AST/RecursiveASTVisitor.h>

namespace clang {
class ASTContext;
class CallExpr;
class CXXConstructExpr;
class CXXMemberCallExpr;
class CXXMethodDecl;
class DeclRefExpr;
class Expr;
class FunctionDecl;
class MemberExpr;
class VarDecl;
}  // namespace clang
#endif

namespace scarab::analyzer {

using CallbackAccessMap = std::map<std::string, std::vector<AccessInfo>>;

class AccessExtractor
#if SCARAB_HAS_CLANG_TOOLING
    : public clang::RecursiveASTVisitor<AccessExtractor>
#endif
{
 public:
  AccessExtractor() = default;

  CallbackAccessMap extract_accesses(const std::string& compile_commands_path,
                                     const std::string& source_file,
                                     const std::vector<CallbackInfo>& callbacks,
                                     int interproc_depth = 1);

#if SCARAB_HAS_CLANG_TOOLING
  bool VisitCallExpr(clang::CallExpr* call_expr);
  bool VisitCXXConstructExpr(clang::CXXConstructExpr* construct_expr);
  void run(clang::ASTContext& ctx);
  bool VisitCXXMemberCallExpr(clang::CXXMemberCallExpr* call_expr);
  bool VisitCXXMethodDecl(clang::CXXMethodDecl* method_decl);
  bool VisitDeclRefExpr(clang::DeclRefExpr* decl_ref_expr);
  bool VisitMemberExpr(clang::MemberExpr* member_expr);
  bool VisitVarDecl(clang::VarDecl* var_decl);
#endif

 private:
  void initialize_callback_index(const std::vector<CallbackInfo>& callbacks);
  std::string find_callback_name_for_line(int line) const;

#if SCARAB_HAS_CLANG_TOOLING
  struct SummaryCacheKey {
    const clang::FunctionDecl* function = nullptr;
    int remaining_depth = 0;

    bool operator==(const SummaryCacheKey& other) const {
      return function == other.function && remaining_depth == other.remaining_depth;
    }
  };

  struct SummaryCacheKeyHash {
    std::size_t operator()(const SummaryCacheKey& key) const {
      const auto function_hash = std::hash<const void*>{}(key.function);
      const auto depth_hash = std::hash<int>{}(key.remaining_depth);
      return function_hash ^ (depth_hash << 1);
    }
  };

  struct AccessSummary {
    std::vector<AccessInfo> accesses;
  };

  const clang::FunctionDecl* resolve_callback_target(const clang::Expr* callback_expr) const;
  std::vector<AccessInfo> analyze_function_with_cache(const clang::FunctionDecl* function_decl,
                                                      int remaining_depth);
  std::vector<AccessInfo> build_function_summary(const clang::FunctionDecl* function_decl,
                                                 int remaining_depth);
  scarab::common::AccessType determine_access_type(const clang::Expr* member_expr) const;
  void add_access(const std::string& callback_name, const AccessInfo& access_info);

  clang::ASTContext* ast_context_ = nullptr;
  std::string target_source_file_;
  bool collecting_callback_targets_ = false;
  int max_interproc_depth_ = 1;
  std::vector<AccessInfo>* active_access_sink_ = nullptr;
  std::vector<const clang::FunctionDecl*>* active_callee_sink_ = nullptr;
  int active_remaining_depth_ = 0;
  std::unordered_map<std::string, const clang::FunctionDecl*> callback_targets_;
  std::unordered_map<SummaryCacheKey, AccessSummary, SummaryCacheKeyHash> summary_cache_;
  std::unordered_set<SummaryCacheKey, SummaryCacheKeyHash> in_progress_;
#endif

  std::vector<std::pair<int, std::string>> callback_lines_;
  std::unordered_map<int, std::string> callback_name_by_line_;
  CallbackAccessMap callback_accesses_;
  AliasTracker alias_tracker_;
};

}  // namespace scarab::analyzer
