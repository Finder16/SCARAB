#include "scarab/analyzer/access_extractor.h"

#include <nlohmann/json.hpp>

#if SCARAB_HAS_CLANG_TOOLING
#include <clang/AST/ASTConsumer.h>
#include <clang/AST/ASTContext.h>
#include <clang/AST/ASTTypeTraits.h>
#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>
#include <clang/AST/ExprCXX.h>
#include <clang/AST/ParentMapContext.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Frontend/FrontendActions.h>
#include <clang/Tooling/ArgumentsAdjusters.h>
#include <clang/Tooling/JSONCompilationDatabase.h>
#include <clang/Tooling/Tooling.h>
#include <llvm/ADT/StringRef.h>
#include <llvm/Support/Casting.h>
#endif

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <regex>
#include <string>
#include <utility>

namespace scarab::analyzer {

namespace {

std::string canonical_or_input(const std::string& path) {
  std::error_code ec;
  const auto canonical = std::filesystem::weakly_canonical(path, ec);
  if (ec) {
    return path;
  }
  return canonical.string();
}

std::string escape_regex(const std::string& text) {
  static const std::regex special(R"([-[\]{}()*+?.,\^$|#\s])");
  return std::regex_replace(text, special, R"(\$&)");
}

scarab::common::AccessType detect_access_type_text(const std::string& line_text,
                                                   const std::string& field_name) {
  const std::string escaped_field = escape_regex(field_name);
  const std::regex read_write_assign(
      "\\bthis\\s*->\\s*" + escaped_field + "\\s*(\\+=|-=|\\*=|/=|%=|&=|\\|=|\\^=)");
  if (std::regex_search(line_text, read_write_assign)) {
    return scarab::common::AccessType::READ_WRITE;
  }

  const std::regex write_assign("\\bthis\\s*->\\s*" + escaped_field + "\\s*=");
  if (std::regex_search(line_text, write_assign)) {
    return scarab::common::AccessType::WRITE;
  }

  const std::regex inc_dec_prefix("(\\+\\+|--)\\s*this\\s*->\\s*" + escaped_field + "\\b");
  const std::regex inc_dec_suffix("\\bthis\\s*->\\s*" + escaped_field + "\\s*(\\+\\+|--)");
  if (std::regex_search(line_text, inc_dec_prefix) || std::regex_search(line_text, inc_dec_suffix)) {
    return scarab::common::AccessType::READ_WRITE;
  }

  return scarab::common::AccessType::READ;
}

CallbackAccessMap parse_with_text_fallback(const std::string& compile_commands_path,
                                           const std::string& source_file,
                                           const std::vector<std::pair<int, std::string>>& callback_lines) {
  std::ifstream db_stream(compile_commands_path);
  if (!db_stream.good()) {
    return {};
  }

  nlohmann::json compile_db;
  try {
    db_stream >> compile_db;
  } catch (...) {
    return {};
  }

  const std::string normalized_source = canonical_or_input(source_file);
  bool source_is_listed = false;
  if (compile_db.is_array()) {
    for (const auto& entry : compile_db) {
      if (!entry.contains("file")) {
        continue;
      }
      const std::string listed_file = canonical_or_input(entry["file"].get<std::string>());
      if (listed_file == normalized_source) {
        source_is_listed = true;
        break;
      }
    }
  }
  if (!source_is_listed) {
    return {};
  }

  std::ifstream source_stream(source_file);
  if (!source_stream.good()) {
    return {};
  }

  std::vector<std::string> lines;
  std::string line_text;
  while (std::getline(source_stream, line_text)) {
    lines.push_back(line_text);
  }

  const std::regex this_field(R"(\bthis\s*->\s*([A-Za-z_][A-Za-z0-9_]*)\b)");
  CallbackAccessMap access_map;

  for (size_t i = 0; i < callback_lines.size(); ++i) {
    const int start_line = callback_lines[i].first;
    const std::string& callback_name = callback_lines[i].second;
    const int end_line = (i + 1 < callback_lines.size())
                             ? (callback_lines[i + 1].first - 1)
                             : static_cast<int>(lines.size());

    for (int line_no = std::max(1, start_line); line_no <= end_line && line_no <= static_cast<int>(lines.size());
         ++line_no) {
      const std::string& current = lines[static_cast<size_t>(line_no - 1)];
      auto begin = std::sregex_iterator(current.begin(), current.end(), this_field);
      auto end = std::sregex_iterator();

      for (auto it = begin; it != end; ++it) {
        AccessInfo access_info;
        access_info.variable_name = (*it)[1].str();
        access_info.variable_type = "";
        access_info.access_type = detect_access_type_text(current, access_info.variable_name);
        access_info.source_file = normalized_source;
        access_info.line = line_no;
        access_info.sync_status = scarab::common::SyncStatus::UNKNOWN;
        access_map[callback_name].push_back(std::move(access_info));
      }
    }
  }

  return access_map;
}

#if SCARAB_HAS_CLANG_TOOLING

const std::unordered_map<std::string, int> kApiCallbackArgIndex = {
    {"create_subscription", 2},
    {"create_timer", 1},
    {"create_wall_timer", 1},
    {"create_service", 1},
    {"create_client", 1},
    {"create_server", 2},
};

const std::unordered_set<std::string> kLifecycleMethodNames = {
    "on_activate",
    "on_deactivate",
    "on_configure",
    "on_cleanup",
    "on_shutdown",
};

const clang::Expr* peel_expr_wrappers(const clang::Expr* expr) {
  const clang::Expr* current = expr;
  while (current != nullptr) {
    current = current->IgnoreParenImpCasts();

    if (const auto* materialized = llvm::dyn_cast<clang::MaterializeTemporaryExpr>(current)) {
      current = materialized->getSubExpr();
      continue;
    }
    if (const auto* cleanup = llvm::dyn_cast<clang::ExprWithCleanups>(current)) {
      current = cleanup->getSubExpr();
      continue;
    }
    if (const auto* bind_temporary = llvm::dyn_cast<clang::CXXBindTemporaryExpr>(current)) {
      current = bind_temporary->getSubExpr();
      continue;
    }
    return current;
  }
  return nullptr;
}

bool is_std_namespace(const clang::DeclContext* context) {
  const clang::DeclContext* current = context;
  while (current != nullptr) {
    const auto* ns = llvm::dyn_cast<clang::NamespaceDecl>(current);
    if (ns != nullptr && ns->isStdNamespace()) {
      return true;
    }
    current = current->getParent();
  }
  return false;
}

bool is_std_bind_call(const clang::CallExpr* call_expr) {
  if (call_expr == nullptr) {
    return false;
  }

  const auto* callee = call_expr->getDirectCallee();
  if (callee == nullptr || callee->getNameAsString() != "bind") {
    return false;
  }
  return is_std_namespace(callee->getDeclContext());
}

const clang::CallExpr* get_bind_call(const clang::Expr* callback_expr) {
  const auto* peeled = peel_expr_wrappers(callback_expr);
  const auto* call_expr = llvm::dyn_cast_or_null<clang::CallExpr>(peeled);
  if (!is_std_bind_call(call_expr)) {
    return nullptr;
  }
  return call_expr;
}

const clang::FunctionDecl* get_bound_method_target(const clang::CallExpr* bind_call) {
  if (bind_call == nullptr || bind_call->getNumArgs() < 2) {
    return nullptr;
  }

  const clang::Expr* method_expr = peel_expr_wrappers(bind_call->getArg(0));
  if (const auto* addr_of = llvm::dyn_cast_or_null<clang::UnaryOperator>(method_expr)) {
    if (addr_of->getOpcode() == clang::UO_AddrOf) {
      method_expr = peel_expr_wrappers(addr_of->getSubExpr());
    }
  }

  const clang::FunctionDecl* target = nullptr;
  if (const auto* decl_ref = llvm::dyn_cast_or_null<clang::DeclRefExpr>(method_expr)) {
    target = llvm::dyn_cast<clang::FunctionDecl>(decl_ref->getDecl());
  } else if (const auto* member_expr = llvm::dyn_cast_or_null<clang::MemberExpr>(method_expr)) {
    target = llvm::dyn_cast<clang::FunctionDecl>(member_expr->getMemberDecl());
  }

  if (target == nullptr) {
    return nullptr;
  }
  if (const auto* definition = target->getDefinition()) {
    return definition;
  }
  return target;
}

bool is_bound_this_pointer(const clang::CallExpr* bind_call) {
  if (bind_call == nullptr || bind_call->getNumArgs() < 2) {
    return false;
  }
  const clang::Expr* bound_object = peel_expr_wrappers(bind_call->getArg(1));
  return llvm::dyn_cast_or_null<clang::CXXThisExpr>(bound_object) != nullptr;
}

int extract_line_number(const clang::Expr* callback_expr, const clang::SourceManager& source_manager) {
  const auto* peeled = peel_expr_wrappers(callback_expr);
  if (peeled == nullptr) {
    return 0;
  }
  const clang::PresumedLoc loc = source_manager.getPresumedLoc(peeled->getBeginLoc());
  if (!loc.isValid()) {
    return 0;
  }
  return static_cast<int>(loc.getLine());
}

bool has_std_flag(const clang::tooling::CommandLineArguments& args) {
  return std::any_of(args.begin(), args.end(), [](const std::string& arg) {
    return arg.rfind("-std=", 0) == 0 || arg.rfind("--std=", 0) == 0;
  });
}

clang::tooling::ArgumentsAdjuster make_default_std_adjuster() {
  return [](const clang::tooling::CommandLineArguments& args, llvm::StringRef) {
    clang::tooling::CommandLineArguments adjusted = args;
    if (has_std_flag(adjusted)) {
      return adjusted;
    }

    auto insert_pos = adjusted.begin();
    if (insert_pos != adjusted.end()) {
      ++insert_pos;
    }
    adjusted.insert(insert_pos, "-std=gnu++17");
    return adjusted;
  };
}

class AccessExtractorConsumer : public clang::ASTConsumer {
 public:
  explicit AccessExtractorConsumer(AccessExtractor& extractor) : extractor_(extractor) {}

  void HandleTranslationUnit(clang::ASTContext& context) override { extractor_.run(context); }

 private:
  AccessExtractor& extractor_;
};

class AccessExtractorAction : public clang::ASTFrontendAction {
 public:
  explicit AccessExtractorAction(AccessExtractor& extractor) : extractor_(extractor) {}

  std::unique_ptr<clang::ASTConsumer> CreateASTConsumer(clang::CompilerInstance&,
                                                        llvm::StringRef) override {
    return std::make_unique<AccessExtractorConsumer>(extractor_);
  }

 private:
  AccessExtractor& extractor_;
};

class AccessExtractorFactory : public clang::tooling::FrontendActionFactory {
 public:
  explicit AccessExtractorFactory(AccessExtractor& extractor) : extractor_(extractor) {}

  std::unique_ptr<clang::FrontendAction> create() override {
    return std::make_unique<AccessExtractorAction>(extractor_);
  }

 private:
  AccessExtractor& extractor_;
};

#endif

}  // namespace

void AccessExtractor::initialize_callback_index(const std::vector<CallbackInfo>& callbacks) {
  callback_lines_.clear();
  callback_name_by_line_.clear();
  for (const auto& callback : callbacks) {
    callback_lines_.push_back({callback.line, callback.name});
    callback_name_by_line_[callback.line] = callback.name;
    callback_accesses_[callback.name] = {};
  }
  std::sort(callback_lines_.begin(), callback_lines_.end(),
            [](const auto& lhs, const auto& rhs) { return lhs.first < rhs.first; });
}

std::string AccessExtractor::find_callback_name_for_line(int line) const {
  std::string callback_name;
  for (const auto& [callback_line, name] : callback_lines_) {
    if (line < callback_line) {
      break;
    }
    callback_name = name;
  }
  return callback_name;
}

#if SCARAB_HAS_CLANG_TOOLING

void AccessExtractor::run(clang::ASTContext& ctx) {
  ast_context_ = &ctx;
  callback_targets_.clear();
  collecting_callback_targets_ = true;
  TraverseDecl(ctx.getTranslationUnitDecl());
  collecting_callback_targets_ = false;

  for (const auto& [line, callback_name] : callback_lines_) {
    (void)line;
    const auto found = callback_targets_.find(callback_name);
    if (found == callback_targets_.end()) {
      continue;
    }
    callback_accesses_[callback_name] =
        analyze_function_with_cache(found->second, max_interproc_depth_);
  }
}

bool AccessExtractor::VisitCXXMemberCallExpr(clang::CXXMemberCallExpr* call_expr) {
  if (ast_context_ == nullptr || call_expr == nullptr) {
    return true;
  }

  const auto* method_decl = call_expr->getMethodDecl();
  if (method_decl == nullptr) {
    return true;
  }

  if (collecting_callback_targets_) {
    const auto register_callback_target = [this](const clang::Expr* callback_arg) {
      const auto* callback_target = resolve_callback_target(callback_arg);
      if (callback_target == nullptr) {
        return;
      }

      const auto* callback_expr = peel_expr_wrappers(callback_arg);
      if (callback_expr == nullptr) {
        return;
      }

      const auto& source_manager = ast_context_->getSourceManager();
      const int callback_line = extract_line_number(callback_expr, source_manager);
      if (callback_line <= 0) {
        return;
      }

      auto callback_name_it = callback_name_by_line_.find(callback_line);
      if (callback_name_it == callback_name_by_line_.end()) {
        const std::string fallback_name =
            llvm::isa<clang::LambdaExpr>(callback_expr)
                ? "lambda@" + std::to_string(callback_line)
                : "bind:" + callback_target->getNameAsString() + "@" +
                      std::to_string(callback_line);
        if (callback_accesses_.find(fallback_name) == callback_accesses_.end()) {
          return;
        }
        callback_name_it = callback_name_by_line_.emplace(callback_line, fallback_name).first;
      }

      callback_targets_[callback_name_it->second] = callback_target;
    };

    const std::string api_name = method_decl->getNameAsString();
    if (api_name == "create_server") {
      for (unsigned i = 0; i < call_expr->getNumArgs(); ++i) {
        register_callback_target(call_expr->getArg(i));
      }
      return true;
    }

    const auto api_it = kApiCallbackArgIndex.find(api_name);
    if (api_it == kApiCallbackArgIndex.end()) {
      return true;
    }

    const int callback_arg_index = api_it->second;
    if (callback_arg_index < 0 ||
        call_expr->getNumArgs() <= static_cast<unsigned>(callback_arg_index)) {
      return true;
    }

    register_callback_target(call_expr->getArg(callback_arg_index));
    return true;
  }

  if (active_callee_sink_ == nullptr || active_remaining_depth_ <= 0) {
    return true;
  }

  const auto* callee_base = call_expr->getImplicitObjectArgument();
  if (callee_base == nullptr) {
    return true;
  }
  if (llvm::dyn_cast<clang::CXXThisExpr>(callee_base->IgnoreParenImpCasts()) == nullptr) {
    return true;
  }

  const auto* callee_def = method_decl->getDefinition();
  if (callee_def == nullptr || !callee_def->hasBody()) {
    return true;
  }

  active_callee_sink_->push_back(callee_def);
  return true;
}

bool AccessExtractor::VisitCallExpr(clang::CallExpr* call_expr) {
  if (ast_context_ == nullptr || call_expr == nullptr || !collecting_callback_targets_) {
    return true;
  }

  const auto* callee = call_expr->getDirectCallee();
  if (callee == nullptr || callee->getNameAsString() != "create_server") {
    return true;
  }
  const std::string qualified = callee->getQualifiedNameAsString();
  if (qualified.find("rclcpp_action::create_server") == std::string::npos) {
    return true;
  }

  for (unsigned i = 0; i < call_expr->getNumArgs(); ++i) {
    const auto* callback_arg = call_expr->getArg(i);
    const auto* callback_target = resolve_callback_target(callback_arg);
    if (callback_target == nullptr) {
      continue;
    }

    const auto* callback_expr = peel_expr_wrappers(callback_arg);
    if (callback_expr == nullptr) {
      continue;
    }
    const auto& source_manager = ast_context_->getSourceManager();
    const int callback_line = extract_line_number(callback_expr, source_manager);
    if (callback_line <= 0) {
      continue;
    }

    auto callback_name_it = callback_name_by_line_.find(callback_line);
    if (callback_name_it == callback_name_by_line_.end()) {
      const std::string fallback_name =
          llvm::isa<clang::LambdaExpr>(callback_expr)
              ? "lambda@" + std::to_string(callback_line)
              : "bind:" + callback_target->getNameAsString() + "@" +
                    std::to_string(callback_line);
      if (callback_accesses_.find(fallback_name) == callback_accesses_.end()) {
        continue;
      }
      callback_name_it = callback_name_by_line_.emplace(callback_line, fallback_name).first;
    }
    callback_targets_[callback_name_it->second] = callback_target;
  }

  return true;
}

bool AccessExtractor::VisitCXXConstructExpr(clang::CXXConstructExpr* construct_expr) {
  if (ast_context_ == nullptr || construct_expr == nullptr || !collecting_callback_targets_) {
    return true;
  }

  const auto* constructor_decl = construct_expr->getConstructor();
  if (constructor_decl == nullptr) {
    return true;
  }
  const auto* parent = constructor_decl->getParent();
  if (parent == nullptr || parent->getNameAsString().find("SimpleActionServer") == std::string::npos) {
    return true;
  }

  for (unsigned i = 0; i < construct_expr->getNumArgs(); ++i) {
    const auto* callback_arg = construct_expr->getArg(i);
    const auto* callback_target = resolve_callback_target(callback_arg);
    if (callback_target == nullptr) {
      continue;
    }

    const auto* callback_expr = peel_expr_wrappers(callback_arg);
    if (callback_expr == nullptr) {
      continue;
    }
    const auto& source_manager = ast_context_->getSourceManager();
    const int callback_line = extract_line_number(callback_expr, source_manager);
    if (callback_line <= 0) {
      continue;
    }

    auto callback_name_it = callback_name_by_line_.find(callback_line);
    if (callback_name_it == callback_name_by_line_.end()) {
      const std::string fallback_name =
          llvm::isa<clang::LambdaExpr>(callback_expr)
              ? "lambda@" + std::to_string(callback_line)
              : "bind:" + callback_target->getNameAsString() + "@" +
                    std::to_string(callback_line);
      if (callback_accesses_.find(fallback_name) == callback_accesses_.end()) {
        continue;
      }
      callback_name_it = callback_name_by_line_.emplace(callback_line, fallback_name).first;
    }
    callback_targets_[callback_name_it->second] = callback_target;
  }

  return true;
}

bool AccessExtractor::VisitCXXMethodDecl(clang::CXXMethodDecl* method_decl) {
  if (ast_context_ == nullptr || method_decl == nullptr || !collecting_callback_targets_) {
    return true;
  }
  if (method_decl->isImplicit() || !method_decl->doesThisDeclarationHaveABody()) {
    return true;
  }

  const std::string method_name = method_decl->getNameAsString();
  if (kLifecycleMethodNames.find(method_name) == kLifecycleMethodNames.end()) {
    return true;
  }

  const auto& source_manager = ast_context_->getSourceManager();
  const clang::PresumedLoc loc = source_manager.getPresumedLoc(method_decl->getLocation());
  if (!loc.isValid()) {
    return true;
  }
  const int line = static_cast<int>(loc.getLine());
  const auto* definition = method_decl->getDefinition();
  const auto* target = definition != nullptr ? definition : method_decl;

  auto name_it = callback_name_by_line_.find(line);
  if (name_it != callback_name_by_line_.end()) {
    const std::string expected_prefix = "lifecycle:" + method_name + "@";
    if (name_it->second.rfind(expected_prefix, 0) == 0) {
      callback_targets_[name_it->second] = target;
      return true;
    }
  }

  const std::string prefix = "lifecycle:" + method_name + "@";
  for (const auto& [callback_name, _] : callback_accesses_) {
    if (callback_name.rfind(prefix, 0) == 0) {
      callback_targets_[callback_name] = target;
    }
  }
  return true;
}

const clang::FunctionDecl* AccessExtractor::resolve_callback_target(
    const clang::Expr* callback_expr) const {
  if (callback_expr == nullptr) {
    return nullptr;
  }

  const auto* peeled = peel_expr_wrappers(callback_expr);
  const auto* lambda = llvm::dyn_cast_or_null<clang::LambdaExpr>(peeled);
  if (lambda == nullptr) {
    const auto* bind_call = get_bind_call(callback_expr);
    if (bind_call == nullptr || !is_bound_this_pointer(bind_call)) {
      return nullptr;
    }
    return get_bound_method_target(bind_call);
  }
  return lambda->getCallOperator();
}

std::vector<AccessInfo> AccessExtractor::analyze_function_with_cache(
    const clang::FunctionDecl* function_decl, int remaining_depth) {
  if (function_decl == nullptr) {
    return {};
  }

  const auto* definition = function_decl->getDefinition();
  const auto* normalized = definition != nullptr ? definition : function_decl;
  const SummaryCacheKey key{normalized->getCanonicalDecl(), remaining_depth};

  if (const auto found = summary_cache_.find(key); found != summary_cache_.end()) {
    return found->second.accesses;
  }
  if (in_progress_.find(key) != in_progress_.end()) {
    return {};
  }

  in_progress_.insert(key);
  auto summary = build_function_summary(normalized, remaining_depth);
  in_progress_.erase(key);
  summary_cache_[key] = AccessSummary{summary};
  return summary;
}

std::vector<AccessInfo> AccessExtractor::build_function_summary(
    const clang::FunctionDecl* function_decl, int remaining_depth) {
  std::vector<AccessInfo> accesses;
  if (function_decl == nullptr || !function_decl->hasBody()) {
    return accesses;
  }

  std::vector<const clang::FunctionDecl*> callees;

  auto* previous_access_sink = active_access_sink_;
  auto* previous_callee_sink = active_callee_sink_;
  const int previous_remaining_depth = active_remaining_depth_;

  // Reset alias tracker per function scope so aliases from one function
  // don't leak into another.
  alias_tracker_.reset();

  active_access_sink_ = &accesses;
  active_callee_sink_ = &callees;
  active_remaining_depth_ = remaining_depth;
  TraverseStmt(function_decl->getBody());
  active_access_sink_ = previous_access_sink;
  active_callee_sink_ = previous_callee_sink;
  active_remaining_depth_ = previous_remaining_depth;

  if (remaining_depth <= 0) {
    return accesses;
  }

  for (const auto* callee : callees) {
    auto nested_accesses = analyze_function_with_cache(callee, remaining_depth - 1);
    accesses.insert(accesses.end(), nested_accesses.begin(), nested_accesses.end());
  }
  return accesses;
}

scarab::common::AccessType AccessExtractor::determine_access_type(const clang::Expr* member_expr) const {
  if (ast_context_ == nullptr || member_expr == nullptr) {
    return scarab::common::AccessType::READ;
  }

  const auto* tracked_expr = member_expr->IgnoreParenImpCasts();
  if (tracked_expr == nullptr) {
    return scarab::common::AccessType::READ;
  }

  const clang::Stmt* current = member_expr;
  while (current != nullptr) {
    const auto same_lhs = [&](const clang::Expr* candidate) {
      if (candidate == nullptr) {
        return false;
      }

      // Treat dereference/address wrappers as the same tracked l-value:
      // e.g., tracked expr `p` should match assignment lhs `*p`.
      const clang::Expr* normalized = candidate;
      while (normalized != nullptr) {
        normalized = normalized->IgnoreParenImpCasts();
        if (normalized == tracked_expr) {
          return true;
        }

        const auto* unary = llvm::dyn_cast<clang::UnaryOperator>(normalized);
        if (unary == nullptr) {
          break;
        }
        if (unary->getOpcode() != clang::UO_Deref &&
            unary->getOpcode() != clang::UO_AddrOf) {
          break;
        }
        normalized = unary->getSubExpr();
      }
      return false;
    };

    const auto parents = ast_context_->getParents(*current);
    if (parents.empty()) {
      break;
    }

    const auto* parent_stmt = parents[0].get<clang::Stmt>();
    if (parent_stmt == nullptr) {
      break;
    }

    if (const auto* compound = llvm::dyn_cast<clang::CompoundAssignOperator>(parent_stmt)) {
      if (same_lhs(compound->getLHS())) {
        return scarab::common::AccessType::READ_WRITE;
      }
    } else if (const auto* binary = llvm::dyn_cast<clang::BinaryOperator>(parent_stmt)) {
      if (binary->isAssignmentOp() && same_lhs(binary->getLHS())) {
        return scarab::common::AccessType::WRITE;
      }
    } else if (const auto* unary = llvm::dyn_cast<clang::UnaryOperator>(parent_stmt)) {
      if (unary->isIncrementDecrementOp() && same_lhs(unary->getSubExpr())) {
        return scarab::common::AccessType::READ_WRITE;
      }
    } else if (const auto* member_call = llvm::dyn_cast<clang::CXXMemberCallExpr>(parent_stmt)) {
      const auto* method = member_call->getMethodDecl();
      if (method != nullptr && !method->isConst() &&
          same_lhs(member_call->getImplicitObjectArgument())) {
        // Conservatively treat non-const method calls on members as writes.
        return scarab::common::AccessType::WRITE;
      }
    } else if (const auto* op_call = llvm::dyn_cast<clang::CXXOperatorCallExpr>(parent_stmt)) {
      const auto* callee = op_call->getDirectCallee();
      const auto* method = llvm::dyn_cast_or_null<clang::CXXMethodDecl>(callee);
      if (method != nullptr && !method->isConst()) {
        for (const auto* arg : op_call->arguments()) {
          if (same_lhs(arg)) {
            return scarab::common::AccessType::WRITE;
          }
        }
      }
    }

    current = parent_stmt;
  }

  return scarab::common::AccessType::READ;
}

void AccessExtractor::add_access(const std::string& callback_name, const AccessInfo& access_info) {
  callback_accesses_[callback_name].push_back(access_info);
}

bool AccessExtractor::VisitMemberExpr(clang::MemberExpr* member_expr) {
  if (ast_context_ == nullptr || member_expr == nullptr || active_access_sink_ == nullptr) {
    return true;
  }

  const auto* base_expr = member_expr->getBase()->IgnoreParenImpCasts();
  if (llvm::dyn_cast<clang::CXXThisExpr>(base_expr) == nullptr) {
    return true;
  }

  const auto* field_decl = llvm::dyn_cast<clang::FieldDecl>(member_expr->getMemberDecl());
  if (field_decl == nullptr) {
    return true;
  }

  const auto& source_manager = ast_context_->getSourceManager();
  const clang::PresumedLoc loc = source_manager.getPresumedLoc(member_expr->getExprLoc());
  if (!loc.isValid()) {
    return true;
  }

  const std::string source_file = canonical_or_input(loc.getFilename());
  if (!target_source_file_.empty() && source_file != target_source_file_) {
    return true;
  }

  const int line = static_cast<int>(loc.getLine());

  AccessInfo access_info;
  access_info.variable_name = field_decl->getNameAsString();
  access_info.variable_type = field_decl->getType().getAsString();
  access_info.access_type = determine_access_type(member_expr);
  access_info.source_file = source_file;
  access_info.line = line;
  access_info.sync_status = scarab::common::SyncStatus::UNKNOWN;
  access_info.protecting_mutex = "";

  if (const auto alias = alias_tracker_.resolve_alias(access_info.variable_name)) {
    access_info.variable_name = *alias;
  }

  active_access_sink_->push_back(std::move(access_info));
  return true;
}

bool AccessExtractor::VisitDeclRefExpr(clang::DeclRefExpr* decl_ref_expr) {
  if (ast_context_ == nullptr || decl_ref_expr == nullptr || active_access_sink_ == nullptr) {
    return true;
  }

  const auto* decl = decl_ref_expr->getDecl();

  // Case 1: Direct implicit field reference (existing logic)
  if (const auto* field_decl = llvm::dyn_cast<clang::FieldDecl>(decl)) {
    const auto parents = ast_context_->getParents(*decl_ref_expr);
    if (!parents.empty() && parents[0].get<clang::MemberExpr>() != nullptr) {
      return true;
    }

    const auto& source_manager = ast_context_->getSourceManager();
    const clang::PresumedLoc loc = source_manager.getPresumedLoc(decl_ref_expr->getExprLoc());
    if (!loc.isValid()) {
      return true;
    }

    const std::string source_file = canonical_or_input(loc.getFilename());
    if (!target_source_file_.empty() && source_file != target_source_file_) {
      return true;
    }

    AccessInfo access_info;
    access_info.variable_name = field_decl->getNameAsString();
    access_info.variable_type = field_decl->getType().getAsString();
    access_info.access_type = determine_access_type(decl_ref_expr);
    access_info.source_file = source_file;
    access_info.line = static_cast<int>(loc.getLine());
    access_info.sync_status = scarab::common::SyncStatus::UNKNOWN;
    access_info.protecting_mutex = "";

    if (const auto alias = alias_tracker_.resolve(access_info.variable_name)) {
      access_info.variable_name = *alias;
    }

    active_access_sink_->push_back(std::move(access_info));
    return true;
  }

  // Case 2: Local variable that is an alias for a member field
  const auto* var_decl = llvm::dyn_cast<clang::VarDecl>(decl);
  if (var_decl == nullptr) {
    return true;
  }

  const std::string var_name = var_decl->getNameAsString();
  const auto resolved = alias_tracker_.resolve(var_name);
  if (!resolved) {
    return true;
  }

  // Skip if this DeclRefExpr is the initializer part of a VarDecl (the binding itself)
  const auto parents = ast_context_->getParents(*decl_ref_expr);
  if (!parents.empty() && parents[0].get<clang::VarDecl>() != nullptr) {
    return true;
  }

  const auto& source_manager = ast_context_->getSourceManager();
  const clang::PresumedLoc loc = source_manager.getPresumedLoc(decl_ref_expr->getExprLoc());
  if (!loc.isValid()) {
    return true;
  }

  const std::string source_file = canonical_or_input(loc.getFilename());
  if (!target_source_file_.empty() && source_file != target_source_file_) {
    return true;
  }

  AccessInfo access_info;
  access_info.variable_name = *resolved;
  access_info.variable_type = var_decl->getType().getNonReferenceType().getUnqualifiedType().getAsString();
  access_info.access_type = determine_access_type(decl_ref_expr);
  access_info.source_file = source_file;
  access_info.line = static_cast<int>(loc.getLine());
  access_info.sync_status = scarab::common::SyncStatus::UNKNOWN;
  access_info.protecting_mutex = "";

  active_access_sink_->push_back(std::move(access_info));
  return true;
}

bool AccessExtractor::VisitVarDecl(clang::VarDecl* var_decl) {
  if (ast_context_ == nullptr || var_decl == nullptr || active_access_sink_ == nullptr) {
    return true;
  }
  if (collecting_callback_targets_) {
    return true;
  }

  const auto* init = var_decl->getInit();
  if (init == nullptr) {
    return true;
  }

  const std::string alias_name = var_decl->getNameAsString();
  if (alias_name.empty()) {
    return true;
  }

  const auto* init_expr = init->IgnoreParenImpCasts();

  // Rule 2: auto* p = &this->field_  (UnaryOperator AddrOf wrapping MemberExpr)
  if (const auto* unary = llvm::dyn_cast<clang::UnaryOperator>(init_expr)) {
    if (unary->getOpcode() == clang::UO_AddrOf) {
      const auto* sub = unary->getSubExpr()->IgnoreParenImpCasts();
      if (const auto* member = llvm::dyn_cast<clang::MemberExpr>(sub)) {
        const auto* base = member->getBase()->IgnoreParenImpCasts();
        if (llvm::isa<clang::CXXThisExpr>(base)) {
          alias_tracker_.track_alias(alias_name, member->getMemberDecl()->getNameAsString());
          return true;
        }
      }
    }
    return true;
  }

  // Rule 1: auto& x = this->field_  (MemberExpr with CXXThisExpr base)
  if (const auto* member = llvm::dyn_cast<clang::MemberExpr>(init_expr)) {
    const auto* base = member->getBase()->IgnoreParenImpCasts();

    // Rule 1: direct this->field_
    if (llvm::isa<clang::CXXThisExpr>(base)) {
      alias_tracker_.track_alias(alias_name, member->getMemberDecl()->getNameAsString());
      return true;
    }

    // Rule 3: this->ptr_->data  (MemberExpr whose base is another MemberExpr on this)
    if (const auto* inner_member = llvm::dyn_cast<clang::MemberExpr>(base)) {
      const auto* inner_base = inner_member->getBase()->IgnoreParenImpCasts();
      if (llvm::isa<clang::CXXThisExpr>(inner_base)) {
        const std::string compound = inner_member->getMemberDecl()->getNameAsString() + "->" +
                                     member->getMemberDecl()->getNameAsString();
        alias_tracker_.track_alias(alias_name, compound);
        return true;
      }
    }
    return true;
  }

  // Chained alias: auto& c = a;  where 'a' is a DeclRefExpr to a VarDecl
  if (const auto* decl_ref = llvm::dyn_cast<clang::DeclRefExpr>(init_expr)) {
    const auto* ref_var = llvm::dyn_cast<clang::VarDecl>(decl_ref->getDecl());
    if (ref_var != nullptr) {
      const std::string ref_name = ref_var->getNameAsString();
      // Only chain if the referenced variable is already a tracked alias
      if (alias_tracker_.resolve(ref_name).has_value()) {
        alias_tracker_.track_alias(alias_name, ref_name);
      }
    }
  }

  return true;
}

#endif

CallbackAccessMap AccessExtractor::extract_accesses(const std::string& compile_commands_path,
                                                    const std::string& source_file,
                                                    const std::vector<CallbackInfo>& callbacks,
                                                    int interproc_depth) {
  callback_accesses_.clear();
  alias_tracker_.reset();
  initialize_callback_index(callbacks);

  if (callbacks.empty()) {
    return callback_accesses_;
  }

#if SCARAB_HAS_CLANG_TOOLING
  target_source_file_ = canonical_or_input(source_file);
  max_interproc_depth_ = std::clamp(interproc_depth, 0, 3);
  summary_cache_.clear();
  in_progress_.clear();

  std::string error_message;
  auto compilation_db = clang::tooling::JSONCompilationDatabase::loadFromFile(
      compile_commands_path, error_message, clang::tooling::JSONCommandLineSyntax::AutoDetect);
  if (compilation_db == nullptr) {
    return callback_accesses_;
  }

  std::vector<std::string> source_files = {source_file};
  clang::tooling::ClangTool tool(*compilation_db, source_files);
  tool.appendArgumentsAdjuster(make_default_std_adjuster());
  AccessExtractorFactory action_factory(*this);
  if (tool.run(&action_factory) != 0) {
    return callback_accesses_;
  }
  return callback_accesses_;
#else
  const auto fallback_map = parse_with_text_fallback(compile_commands_path, source_file, callback_lines_);
  for (const auto& [callback_name, accesses] : fallback_map) {
    callback_accesses_[callback_name] = accesses;
  }
  return callback_accesses_;
#endif
}

}  // namespace scarab::analyzer
