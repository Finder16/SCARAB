#pragma once

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

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
class Expr;
class FunctionDecl;
}  // namespace clang
#endif

namespace scarab::analyzer {

class CallbackExtractor
#if SCARAB_HAS_CLANG_TOOLING
    : public clang::RecursiveASTVisitor<CallbackExtractor>
#endif
{
 public:
  CallbackExtractor() = default;

  std::vector<CallbackInfo> extract_callbacks(const std::string& compile_commands_path,
                                              const std::string& source_file);

#if SCARAB_HAS_CLANG_TOOLING
  void run(clang::ASTContext& ctx);
  bool VisitCallExpr(clang::CallExpr* call_expr);
  bool VisitCXXConstructExpr(clang::CXXConstructExpr* construct_expr);
  bool VisitCXXMemberCallExpr(clang::CXXMemberCallExpr* call_expr);
  bool VisitCXXMethodDecl(clang::CXXMethodDecl* method_decl);
  const std::vector<CallbackInfo>& get_callbacks() const;
#endif

 private:
#if SCARAB_HAS_CLANG_TOOLING
  static const std::unordered_map<std::string, int> kApiCallbackArgIndex;
  static const std::unordered_set<std::string> kLifecycleMethodNames;

  const clang::FunctionDecl* resolve_callback_target(const clang::Expr* callback_arg) const;
  bool append_callback_info(const std::string& api_name, const clang::Expr* callback_arg,
                            const std::string& topic_or_service = "");
  bool append_lifecycle_callback(const clang::CXXMethodDecl* method_decl);
  static scarab::common::CallbackType callback_type_for_api(const std::string& api_name);
  std::string extract_topic_or_service(const clang::CallExpr* call_expr,
                                       const std::string& api_name) const;
  bool has_callback_key(const CallbackInfo& info) const;
  std::string make_callback_key(const CallbackInfo& info) const;

  clang::ASTContext* ast_context_ = nullptr;
  std::unordered_set<std::string> callback_keys_;
#endif

  std::vector<CallbackInfo> callbacks_;
};

}  // namespace scarab::analyzer
