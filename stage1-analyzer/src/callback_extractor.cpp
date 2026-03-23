#include "scarab/analyzer/callback_extractor.h"

#include <nlohmann/json.hpp>

#if SCARAB_HAS_CLANG_TOOLING
#include <clang/AST/ASTConsumer.h>
#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>
#include <clang/AST/ExprCXX.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Frontend/FrontendActions.h>
#include <clang/Tooling/ArgumentsAdjusters.h>
#include <clang/Tooling/JSONCompilationDatabase.h>
#include <clang/Tooling/Tooling.h>
#include <llvm/ADT/StringRef.h>
#endif

#include <algorithm>
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

bool append_fallback_callback(std::vector<CallbackInfo>* callbacks,
                              std::unordered_set<std::string>* callback_keys,
                              CallbackInfo info) {
  if (callbacks == nullptr || callback_keys == nullptr) {
    return false;
  }

  const std::string key = info.source_file + ":" + std::to_string(info.line) + ":" +
                          std::to_string(static_cast<int>(info.type)) + ":" + info.name;
  if (!callback_keys->insert(key).second) {
    return false;
  }
  callbacks->push_back(std::move(info));
  return true;
}

scarab::common::CallbackType fallback_type_for_api(const std::string& api_name) {
  if (api_name == "create_subscription") {
    return scarab::common::CallbackType::SUBSCRIPTION;
  }
  if (api_name == "create_timer" || api_name == "create_wall_timer") {
    return scarab::common::CallbackType::TIMER;
  }
  if (api_name == "create_service" || api_name == "create_client") {
    return scarab::common::CallbackType::SERVICE;
  }
  if (api_name == "on_activate" || api_name == "on_deactivate" || api_name == "on_configure" ||
      api_name == "on_cleanup" || api_name == "on_shutdown") {
    return scarab::common::CallbackType::LIFECYCLE;
  }
  return scarab::common::CallbackType::ACTION;
}

std::string extract_first_string_literal(const std::string& block) {
  static const std::regex quoted("\"([^\"]+)\"");
  std::smatch match;
  if (std::regex_search(block, match, quoted) && match.size() > 1) {
    return match.str(1);
  }
  return {};
}

std::vector<CallbackInfo> parse_with_text_fallback(const std::string& compile_commands_path,
                                                   const std::string& source_file) {
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

  const std::regex subscription_topic(R"re(create_subscription(?:\s*<[^>]+>)?\s*\(\s*"([^"]+)")re");
  const std::regex service_name(
      R"re(create_(?:service|client)(?:\s*<[^>]+>)?\s*\(\s*"([^"]+)")re");
  const std::regex action_name(R"re(create_server(?:\s*<[^>]+>)?\s*\([^;]*?"([^"]+)")re");
  const std::regex inline_lambda(R"(\[[^\]]*\]\s*\([^)]*\)\s*\{)");
  const std::regex std_bind_direct(
      R"(std::bind\s*\(\s*&[A-Za-z_]\w*::([A-Za-z_]\w*)\s*,\s*this\b)");
  const std::regex lifecycle_override(
      R"(\b(on_activate|on_deactivate|on_configure|on_cleanup|on_shutdown)\s*\([^;{)]*\)\s*(?:const\s*)?(?:override\b)?)");
  const std::regex has_override(R"(\boverride\b)");

  std::vector<CallbackInfo> callbacks;
  std::unordered_set<std::string> callback_keys;
  for (size_t i = 0; i < lines.size(); ++i) {
    const std::string& current = lines[i];
    std::smatch lifecycle_match;
    if (std::regex_search(current, lifecycle_match, lifecycle_override) &&
        std::regex_search(current, has_override) && lifecycle_match.size() > 1) {
      const std::string method_name = lifecycle_match.str(1);
      CallbackInfo info;
      info.name = "lifecycle:" + method_name + "@" + std::to_string(static_cast<int>(i + 1));
      info.source_file = normalized_source;
      info.line = static_cast<int>(i + 1);
      info.type = scarab::common::CallbackType::LIFECYCLE;
      info.topic_or_service = method_name;
      info.callback_group = "default";
      info.group_type = scarab::common::CallbackGroupType::DEFAULT;
      append_fallback_callback(&callbacks, &callback_keys, std::move(info));
    }

    std::string api_name;
    if (current.find("create_subscription") != std::string::npos) {
      api_name = "create_subscription";
    } else if (current.find("create_timer") != std::string::npos) {
      api_name = "create_timer";
    } else if (current.find("create_wall_timer") != std::string::npos) {
      api_name = "create_wall_timer";
    } else if (current.find("create_service") != std::string::npos) {
      api_name = "create_service";
    } else if (current.find("create_client") != std::string::npos) {
      api_name = "create_client";
    } else if (current.find("create_server") != std::string::npos) {
      api_name = "create_server";
    } else if (current.find("SimpleActionServer") != std::string::npos) {
      api_name = "SimpleActionServer";
    } else {
      continue;
    }

    std::string block = current;
    size_t end_line = i;
    if (current.find(';') == std::string::npos) {
      for (size_t j = i + 1; j < lines.size() && j < i + 30; ++j) {
        block += "\n";
        block += lines[j];
        end_line = j;
        if (lines[j].find(';') != std::string::npos) {
          break;
        }
      }
    }

    const auto callback_type = fallback_type_for_api(api_name);

    std::string topic_or_service;
    if (api_name == "create_subscription") {
      std::smatch match;
      if (std::regex_search(block, match, subscription_topic) && match.size() > 1) {
        topic_or_service = match.str(1);
      }
    } else if (api_name == "create_service" || api_name == "create_client") {
      std::smatch match;
      if (std::regex_search(block, match, service_name) && match.size() > 1) {
        topic_or_service = match.str(1);
      } else {
        topic_or_service = extract_first_string_literal(block);
      }
    } else if (api_name == "create_server" || api_name == "SimpleActionServer") {
      std::smatch match;
      if (std::regex_search(block, match, action_name) && match.size() > 1) {
        topic_or_service = match.str(1);
      } else {
        topic_or_service = extract_first_string_literal(block);
      }
    }

    bool added_any = false;
    for (size_t j = i; j <= end_line; ++j) {
      const std::string& line = lines[j];

      if (std::regex_search(line, inline_lambda)) {
        CallbackInfo info;
        info.name = "lambda@" + std::to_string(static_cast<int>(j + 1));
        info.source_file = normalized_source;
        info.line = static_cast<int>(j + 1);
        info.type = callback_type;
        info.topic_or_service = topic_or_service;
        info.callback_group = "default";
        info.group_type = scarab::common::CallbackGroupType::DEFAULT;
        added_any |= append_fallback_callback(&callbacks, &callback_keys, std::move(info));
        if (callback_type != scarab::common::CallbackType::ACTION) {
          break;
        }
      }

      for (std::sregex_iterator it(line.begin(), line.end(), std_bind_direct), end_it;
           it != end_it; ++it) {
        CallbackInfo info;
        info.name = "bind:" + (*it)[1].str() + "@" + std::to_string(static_cast<int>(j + 1));
        info.source_file = normalized_source;
        info.line = static_cast<int>(j + 1);
        info.type = callback_type;
        info.topic_or_service = topic_or_service;
        info.callback_group = "default";
        info.group_type = scarab::common::CallbackGroupType::DEFAULT;
        added_any |= append_fallback_callback(&callbacks, &callback_keys, std::move(info));
        if (callback_type != scarab::common::CallbackType::ACTION) {
          break;
        }
      }

      if (added_any && callback_type != scarab::common::CallbackType::ACTION) {
        break;
      }
    }

    if (!added_any) {
      continue;
    }
    i = end_line;
  }

  return callbacks;
}

#if SCARAB_HAS_CLANG_TOOLING

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

std::string extract_string_literal_arg(const clang::CallExpr* call_expr, int arg_index) {
  if (call_expr == nullptr || arg_index < 0 ||
      call_expr->getNumArgs() <= static_cast<unsigned>(arg_index)) {
    return {};
  }

  const auto* arg = call_expr->getArg(arg_index)->IgnoreParenImpCasts();
  const auto* literal = llvm::dyn_cast<clang::StringLiteral>(arg);
  if (literal == nullptr) {
    return {};
  }
  return literal->getString().str();
}

std::string extract_first_string_literal_arg(const clang::CallExpr* call_expr) {
  if (call_expr == nullptr) {
    return {};
  }
  for (unsigned i = 0; i < call_expr->getNumArgs(); ++i) {
    const auto name = extract_string_literal_arg(call_expr, static_cast<int>(i));
    if (!name.empty()) {
      return name;
    }
  }
  return {};
}

std::string extract_first_string_literal_arg(const clang::CXXConstructExpr* construct_expr) {
  if (construct_expr == nullptr) {
    return {};
  }
  for (unsigned i = 0; i < construct_expr->getNumArgs(); ++i) {
    const auto* arg = construct_expr->getArg(i)->IgnoreParenImpCasts();
    const auto* literal = llvm::dyn_cast<clang::StringLiteral>(arg);
    if (literal != nullptr) {
      return literal->getString().str();
    }
  }
  return {};
}

bool is_lifecycle_base_method(const clang::CXXMethodDecl* method_decl) {
  if (method_decl == nullptr) {
    return false;
  }
  const std::string qualified = method_decl->getQualifiedNameAsString();
  return qualified.find("rclcpp_lifecycle::LifecycleNode::") != std::string::npos ||
         qualified.find("nav2_util::LifecycleNode::") != std::string::npos;
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

class CallbackExtractorConsumer : public clang::ASTConsumer {
 public:
  explicit CallbackExtractorConsumer(CallbackExtractor& extractor) : extractor_(extractor) {}

  void HandleTranslationUnit(clang::ASTContext& context) override { extractor_.run(context); }

 private:
  CallbackExtractor& extractor_;
};

class CallbackExtractorAction : public clang::ASTFrontendAction {
 public:
  explicit CallbackExtractorAction(CallbackExtractor& extractor) : extractor_(extractor) {}

  std::unique_ptr<clang::ASTConsumer> CreateASTConsumer(clang::CompilerInstance&,
                                                        llvm::StringRef) override {
    return std::make_unique<CallbackExtractorConsumer>(extractor_);
  }

 private:
  CallbackExtractor& extractor_;
};

class CallbackExtractorFactory : public clang::tooling::FrontendActionFactory {
 public:
  explicit CallbackExtractorFactory(CallbackExtractor& extractor) : extractor_(extractor) {}

  std::unique_ptr<clang::FrontendAction> create() override {
    return std::make_unique<CallbackExtractorAction>(extractor_);
  }

 private:
  CallbackExtractor& extractor_;
};

#endif

}  // namespace

#if SCARAB_HAS_CLANG_TOOLING

const std::unordered_map<std::string, int> CallbackExtractor::kApiCallbackArgIndex = {
    {"create_subscription", 2},
    {"create_timer", 1},
    {"create_wall_timer", 1},
    {"create_service", 1},
    {"create_client", 1},
};

const std::unordered_set<std::string> CallbackExtractor::kLifecycleMethodNames = {
    "on_activate",
    "on_deactivate",
    "on_configure",
    "on_cleanup",
    "on_shutdown",
};

void CallbackExtractor::run(clang::ASTContext& ctx) {
  ast_context_ = &ctx;
  callback_keys_.clear();
  TraverseDecl(ctx.getTranslationUnitDecl());
}

scarab::common::CallbackType CallbackExtractor::callback_type_for_api(const std::string& api_name) {
  if (api_name == "create_subscription") {
    return scarab::common::CallbackType::SUBSCRIPTION;
  }
  if (api_name == "create_timer" || api_name == "create_wall_timer") {
    return scarab::common::CallbackType::TIMER;
  }
  if (api_name == "create_service" || api_name == "create_client") {
    return scarab::common::CallbackType::SERVICE;
  }
  if (api_name == "on_activate" || api_name == "on_deactivate" || api_name == "on_configure" ||
      api_name == "on_cleanup" || api_name == "on_shutdown") {
    return scarab::common::CallbackType::LIFECYCLE;
  }
  return scarab::common::CallbackType::ACTION;
}

bool CallbackExtractor::append_callback_info(const std::string& api_name,
                                             const clang::Expr* callback_arg,
                                             const std::string& topic_or_service) {
  if (ast_context_ == nullptr || callback_arg == nullptr) {
    return false;
  }

  const auto* callback_target = resolve_callback_target(callback_arg);
  if (callback_target == nullptr) {
    return false;
  }

  const auto* callback_expr = peel_expr_wrappers(callback_arg);
  if (callback_expr == nullptr) {
    return false;
  }

  const auto& source_manager = ast_context_->getSourceManager();
  const clang::PresumedLoc loc = source_manager.getPresumedLoc(callback_expr->getBeginLoc());
  if (!loc.isValid()) {
    return false;
  }
  const int callback_line = extract_line_number(callback_expr, source_manager);
  if (callback_line <= 0) {
    return false;
  }

  CallbackInfo info;
  if (llvm::isa<clang::LambdaExpr>(callback_expr)) {
    info.name = "lambda@" + std::to_string(callback_line);
  } else {
    info.name = "bind:" + callback_target->getNameAsString() + "@" +
                std::to_string(callback_line);
  }
  info.source_file = loc.getFilename();
  info.line = callback_line;
  info.callback_group = "default";
  info.group_type = scarab::common::CallbackGroupType::DEFAULT;
  info.type = callback_type_for_api(api_name);
  info.topic_or_service = topic_or_service;

  if (has_callback_key(info)) {
    return false;
  }

  callback_keys_.insert(make_callback_key(info));
  callbacks_.push_back(std::move(info));
  return true;
}

bool CallbackExtractor::append_lifecycle_callback(const clang::CXXMethodDecl* method_decl) {
  if (ast_context_ == nullptr || method_decl == nullptr) {
    return false;
  }

  const auto& source_manager = ast_context_->getSourceManager();
  const clang::PresumedLoc loc = source_manager.getPresumedLoc(method_decl->getLocation());
  if (!loc.isValid()) {
    return false;
  }

  const int line = static_cast<int>(loc.getLine());
  if (line <= 0) {
    return false;
  }

  CallbackInfo info;
  info.name = "lifecycle:" + method_decl->getNameAsString() + "@" + std::to_string(line);
  info.source_file = loc.getFilename();
  info.line = line;
  info.type = scarab::common::CallbackType::LIFECYCLE;
  info.topic_or_service = method_decl->getNameAsString();
  info.callback_group = "default";
  info.group_type = scarab::common::CallbackGroupType::DEFAULT;

  if (has_callback_key(info)) {
    return false;
  }

  callback_keys_.insert(make_callback_key(info));
  callbacks_.push_back(std::move(info));
  return true;
}

std::string CallbackExtractor::extract_topic_or_service(const clang::CallExpr* call_expr,
                                                        const std::string& api_name) const {
  if (call_expr == nullptr) {
    return {};
  }

  if (api_name == "create_subscription" || api_name == "create_service" ||
      api_name == "create_client") {
    const auto from_first_arg = extract_string_literal_arg(call_expr, 0);
    if (!from_first_arg.empty()) {
      return from_first_arg;
    }
    return extract_first_string_literal_arg(call_expr);
  }

  if (api_name == "create_server") {
    // rclcpp_action::create_server(node, "action", goal_cb, cancel_cb, accept_cb, ...)
    const auto from_second_arg = extract_string_literal_arg(call_expr, 1);
    if (!from_second_arg.empty()) {
      return from_second_arg;
    }
    return extract_first_string_literal_arg(call_expr);
  }

  return {};
}

bool CallbackExtractor::has_callback_key(const CallbackInfo& info) const {
  return callback_keys_.find(make_callback_key(info)) != callback_keys_.end();
}

std::string CallbackExtractor::make_callback_key(const CallbackInfo& info) const {
  return info.source_file + ":" + std::to_string(info.line) + ":" +
         std::to_string(static_cast<int>(info.type)) + ":" + info.name;
}

bool CallbackExtractor::VisitCXXMemberCallExpr(clang::CXXMemberCallExpr* call_expr) {
  if (ast_context_ == nullptr || call_expr == nullptr) {
    return true;
  }

  const auto* method_decl = call_expr->getMethodDecl();
  if (method_decl == nullptr) {
    return true;
  }

  const std::string api_name = method_decl->getNameAsString();
  if (api_name == "create_server") {
    const std::string action_name = extract_topic_or_service(call_expr, api_name);
    for (unsigned i = 0; i < call_expr->getNumArgs(); ++i) {
      append_callback_info(api_name, call_expr->getArg(i), action_name);
    }
    return true;
  }

  const auto api_it = kApiCallbackArgIndex.find(api_name);
  if (api_it == kApiCallbackArgIndex.end()) {
    return true;
  }

  const int callback_index = api_it->second;
  if (callback_index < 0 || call_expr->getNumArgs() <= static_cast<unsigned>(callback_index)) {
    return true;
  }

  append_callback_info(api_name, call_expr->getArg(callback_index),
                       extract_topic_or_service(call_expr, api_name));
  return true;
}

bool CallbackExtractor::VisitCallExpr(clang::CallExpr* call_expr) {
  if (ast_context_ == nullptr || call_expr == nullptr) {
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

  const std::string action_name = extract_topic_or_service(call_expr, "create_server");
  for (unsigned i = 0; i < call_expr->getNumArgs(); ++i) {
    append_callback_info("create_server", call_expr->getArg(i), action_name);
  }
  return true;
}

bool CallbackExtractor::VisitCXXConstructExpr(clang::CXXConstructExpr* construct_expr) {
  if (ast_context_ == nullptr || construct_expr == nullptr) {
    return true;
  }

  const auto* constructor_decl = construct_expr->getConstructor();
  if (constructor_decl == nullptr) {
    return true;
  }
  const auto* record = constructor_decl->getParent();
  if (record == nullptr || record->getNameAsString().find("SimpleActionServer") == std::string::npos) {
    return true;
  }

  const std::string action_name = extract_first_string_literal_arg(construct_expr);
  for (unsigned i = 0; i < construct_expr->getNumArgs(); ++i) {
    append_callback_info("SimpleActionServer", construct_expr->getArg(i), action_name);
  }
  return true;
}

bool CallbackExtractor::VisitCXXMethodDecl(clang::CXXMethodDecl* method_decl) {
  if (ast_context_ == nullptr || method_decl == nullptr || method_decl->isImplicit()) {
    return true;
  }
  // Keep declaration-only methods out to reduce duplicate callbacks.
  if (!method_decl->doesThisDeclarationHaveABody()) {
    return true;
  }

  const std::string method_name = method_decl->getNameAsString();
  if (kLifecycleMethodNames.find(method_name) == kLifecycleMethodNames.end()) {
    return true;
  }

  bool overrides_lifecycle_base = false;
  for (const auto* overridden : method_decl->overridden_methods()) {
    if (is_lifecycle_base_method(overridden)) {
      overrides_lifecycle_base = true;
      break;
    }
  }

  if (!overrides_lifecycle_base) {
    return true;
  }

  append_lifecycle_callback(method_decl);
  return true;
}

const clang::FunctionDecl* CallbackExtractor::resolve_callback_target(
    const clang::Expr* callback_arg) const {
  const auto* peeled = peel_expr_wrappers(callback_arg);
  const auto* lambda = llvm::dyn_cast_or_null<clang::LambdaExpr>(peeled);
  if (lambda == nullptr) {
    const auto* bind_call = get_bind_call(callback_arg);
    if (bind_call == nullptr || !is_bound_this_pointer(bind_call)) {
      return nullptr;
    }
    return get_bound_method_target(bind_call);
  }
  return lambda->getCallOperator();
}

const std::vector<CallbackInfo>& CallbackExtractor::get_callbacks() const { return callbacks_; }

#endif

std::vector<CallbackInfo> CallbackExtractor::extract_callbacks(
    const std::string& compile_commands_path, const std::string& source_file) {
  callbacks_.clear();

#if SCARAB_HAS_CLANG_TOOLING
  std::string error_message;
  auto compilation_db = clang::tooling::JSONCompilationDatabase::loadFromFile(
      compile_commands_path, error_message, clang::tooling::JSONCommandLineSyntax::AutoDetect);
  if (compilation_db == nullptr) {
    return {};
  }

  std::vector<std::string> source_files = {source_file};
  clang::tooling::ClangTool tool(*compilation_db, source_files);
  tool.appendArgumentsAdjuster(make_default_std_adjuster());
  CallbackExtractorFactory action_factory(*this);
  if (tool.run(&action_factory) != 0) {
    return {};
  }
  return callbacks_;
#else
  callbacks_ = parse_with_text_fallback(compile_commands_path, source_file);
  return callbacks_;
#endif
}

}  // namespace scarab::analyzer
