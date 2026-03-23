#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <random>
#include <string>
#include <unordered_map>
#include <vector>

#include "scarab/common/race_candidate.h"
#include "scarab/fuzzer/directed_pct.h"
#include "scarab/fuzzer/instrumented_executor.h"
#include "scarab/fuzzer/mutation.h"
#include "scarab/fuzzer/oracle.h"
#include "scarab/fuzzer/seed.h"

#if defined(SCARAB_FUZZER_HAS_ROS2)
#include "rclcpp/rclcpp.hpp"
#endif

namespace scarab::fuzzer {

struct FuzzerConfig {
  std::string candidates_path;
  int duration_sec = 0;
  std::string corpus_dir;
  std::string output_dir;
  int num_threads = 2;
  int iteration_runtime_ms = 100;
  bool enable_minimization = true;
  bool use_directed_pct = true;
  float directed_pct_ratio = 0.7f;
};

struct FuzzerExecutionResult {
  bool success = false;
  bool crashed = false;
  bool callbacks_executed = false;
  size_t callback_event_count = 0;
  std::string error_message;
  /// TSan / ASan output captured from the process's stderr during execution.
  std::string stderr_output;
  /// Process exit code; negative values represent signals (-11 = SIGSEGV, …).
  int exit_code = 0;
  /// True when the execution could not start due to an environment issue
  /// (e.g. SCARAB built without ROS2).  The oracle skips these.
  bool is_env_error = false;
  /// Path to the event log recorded during this execution (empty if none).
  std::string event_log_path;
};

struct FuzzerRunSummary {
  size_t iterations = 0;
  size_t total_executions = 0;
  size_t crashes = 0;
  size_t bugs_found = 0;  // Unique bug signatures
  size_t total_bug_reports = 0;
  size_t internal_races_filtered = 0;
  size_t callbacks_ok = 0;
  size_t seeds_loaded = 0;
  size_t seeds_saved = 0;
  size_t initial_seeds_created = 0;
  size_t corpus_size = 0;
};

class FuzzerEngine {
 public:
  explicit FuzzerEngine(uint32_t rng_seed = 0xC0FFEEu);
  ~FuzzerEngine();

  bool run(const FuzzerConfig& config, FuzzerRunSummary* summary = nullptr);

#if defined(SCARAB_FUZZER_HAS_ROS2)
  /// Inject a custom node factory used by execute_one() instead of the
  /// built-in EngineMiniNode.  The factory is called once per iteration to
  /// create a fresh node instance.  When set, callbacks_executed is always
  /// reported as true (the engine cannot introspect the custom node).
  using NodeFactory = std::function<std::shared_ptr<rclcpp::Node>()>;
  void set_node_factory(NodeFactory factory);

  /// Optional executor lifecycle hooks used with custom node factories.
  /// setup_hook runs right after adding the primary node to executor.
  /// teardown_hook runs right before removing the primary node.
  using NodeExecutorHook =
      std::function<void(const std::shared_ptr<rclcpp::Node>&,
                         const std::shared_ptr<InstrumentedExecutor>&)>;
  void set_node_setup_hook(NodeExecutorHook hook);
  void set_node_teardown_hook(NodeExecutorHook hook);

  // Reuse a custom target node + executor across iterations instead of
  // reconstructing them each time. This is useful for plugin-heavy ROS2 nodes
  // (e.g. nav2) whose repeated teardown can trigger class_loader aborts.
  void set_reuse_custom_node_across_iterations(bool enabled);

  // When enabled, persistent custom node/executor resources are intentionally
  // retained until process exit (leaked) to avoid fragile plugin unload paths
  // during shutdown. Intended for E2E nav2 runner processes only.
  void set_retain_custom_node_until_process_exit(bool enabled);

  /// Optional hook called after each executor->spin() returns in persistent
  /// reuse mode.  Gives the target a chance to clean up inter-iteration state
  /// (e.g. cancel in-flight action goals) before the next spin() call.
  void set_node_iteration_end_hook(NodeExecutorHook hook);
#endif

 private:
  bool load_candidates(const std::string& path,
                       std::vector<scarab::common::RaceCandidate>* candidates,
                       std::string* error_message) const;
  bool load_corpus(const std::string& corpus_dir, std::vector<Seed>* corpus,
                   FuzzerRunSummary* summary, std::string* error_message) const;
  bool add_seed_to_corpus(const Seed& seed, const std::string& corpus_dir,
                          std::vector<Seed>* corpus, FuzzerRunSummary* summary,
                          std::string* error_message);
  Seed select_seed(const std::vector<Seed>& corpus, bool energy_based = false);
  FuzzerExecutionResult execute_one(const Seed& seed, const FuzzerConfig& config);
  bool try_replay_reproduces(const EventLog& candidate,
                             const FuzzerConfig& config,
                             const std::string& target_sig);
  static bool write_run_summary_file(const FuzzerRunSummary& summary,
                                     const std::string& output_dir,
                                     std::string* error_message);

  MutationEngine mutation_engine_;
  OracleManager oracle_manager_;
  DirectedPctScheduler directed_pct_;
  std::mt19937 rng_;

  struct CandidateStats {
    uint32_t times_selected = 0;
    uint32_t bugs_found = 0;
  };
  std::unordered_map<uint32_t, CandidateStats> candidate_stats_;
#if defined(SCARAB_FUZZER_HAS_ROS2)
  NodeFactory node_factory_;
  NodeExecutorHook node_setup_hook_;
  NodeExecutorHook node_teardown_hook_;
  NodeExecutorHook node_iteration_end_hook_;
  bool reuse_custom_node_across_iterations_ = false;
  bool retain_custom_node_until_process_exit_ = false;
  std::shared_ptr<rclcpp::Node> persistent_custom_node_;
  std::shared_ptr<InstrumentedExecutor> persistent_custom_executor_;
  bool persistent_custom_setup_done_ = false;
#endif
};

}  // namespace scarab::fuzzer
