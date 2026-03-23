#include "scarab/fuzzer/fuzzer_engine.h"

#include "scarab/common/json_io.h"
#include "scarab/common/logging.h"
#include "scarab/fuzzer/dedup.h"
#include "scarab/fuzzer/minimizer.h"
#include "scarab/fuzzer/recorder.h"
#include "scarab/fuzzer/replayer.h"
#include "scarab/fuzzer/scarab_rt.h"
#include "scarab/fuzzer/stderr_capture.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <optional>
#include <sstream>
#include <thread>
#include <unordered_set>

#if defined(SCARAB_FUZZER_HAS_ROS2)
#include "rclcpp/rclcpp.hpp"
#include "std_msgs/msg/int32.hpp"

#include <unistd.h>
#endif

namespace scarab::fuzzer {

namespace {

namespace fs = std::filesystem;

bool read_binary_file(const fs::path& path, std::vector<uint8_t>* bytes) {
  if (bytes == nullptr) {
    return false;
  }

  std::ifstream input(path, std::ios::binary);
  if (!input.good()) {
    return false;
  }

  input.seekg(0, std::ios::end);
  const auto end = input.tellg();
  if (end < 0) {
    return false;
  }
  bytes->resize(static_cast<size_t>(end));
  input.seekg(0, std::ios::beg);
  if (!bytes->empty()) {
    input.read(reinterpret_cast<char*>(bytes->data()),
               static_cast<std::streamsize>(bytes->size()));
  }
  return input.good() || input.eof();
}

bool write_binary_file(const fs::path& path, const std::vector<uint8_t>& bytes) {
  std::ofstream output(path, std::ios::binary);
  if (!output.good()) {
    return false;
  }
  if (!bytes.empty()) {
    output.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
  }
  return output.good();
}

std::string seed_key(const std::vector<uint8_t>& bytes) {
  if (bytes.empty()) {
    return std::string();
  }
  return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

std::string make_seed_file_name(uint32_t candidate_id, size_t index) {
  std::ostringstream oss;
  oss << "seed_c" << candidate_id << "_i" << index << ".seed";
  return oss.str();
}

}  // namespace

#if defined(SCARAB_FUZZER_HAS_ROS2)
namespace {

class EngineMiniNode : public rclcpp::Node {
 public:
  EngineMiniNode() : rclcpp::Node("scarab_fuzzer_engine_probe") {
    pub_a_ = this->create_publisher<std_msgs::msg::Int32>("topic_a", 10);
    pub_b_ = this->create_publisher<std_msgs::msg::Int32>("topic_b", 10);

    sub_a_ = this->create_subscription<std_msgs::msg::Int32>(
        "topic_a", 10, [this](const std_msgs::msg::Int32::SharedPtr msg) {
          shared_value_ = msg->data;
          ++sub_a_calls_;
        });

    sub_b_ = this->create_subscription<std_msgs::msg::Int32>(
        "topic_b", 10, [this](const std_msgs::msg::Int32::SharedPtr msg) {
          shared_value_ += msg->data;
          ++sub_b_calls_;
        });

    timer_ = this->create_wall_timer(std::chrono::milliseconds(20), [this]() {
      std_msgs::msg::Int32 msg_a;
      std_msgs::msg::Int32 msg_b;
      msg_a.data = shared_value_ + 1;
      msg_b.data = shared_value_ + 2;
      pub_a_->publish(msg_a);
      pub_b_->publish(msg_b);
      ++timer_calls_;
    });
  }

  bool callbacks_executed() const {
    return timer_calls_ > 0 && sub_a_calls_ > 0 && sub_b_calls_ > 0;
  }

 private:
  int shared_value_ = 0;
  int timer_calls_ = 0;
  int sub_a_calls_ = 0;
  int sub_b_calls_ = 0;

  rclcpp::Publisher<std_msgs::msg::Int32>::SharedPtr pub_a_;
  rclcpp::Publisher<std_msgs::msg::Int32>::SharedPtr pub_b_;
  rclcpp::Subscription<std_msgs::msg::Int32>::SharedPtr sub_a_;
  rclcpp::Subscription<std_msgs::msg::Int32>::SharedPtr sub_b_;
  rclcpp::TimerBase::SharedPtr timer_;
};

class RosRuntimeScope {
 public:
  RosRuntimeScope() {
    if (!rclcpp::ok()) {
      int argc = 0;
      char** argv = nullptr;
      rclcpp::init(argc, argv);
      owns_runtime_ = true;
    }
  }

  ~RosRuntimeScope() {
    if (owns_runtime_ && rclcpp::ok()) {
      rclcpp::shutdown();
    }
  }

 private:
  bool owns_runtime_ = false;
};

// ScopedStderrCapture is now provided by scarab/fuzzer/stderr_capture.h.
using scarab::fuzzer::ScopedStderrCapture;

void retain_shared_ptr_until_process_exit(const std::shared_ptr<void>& ptr) {
  if (!ptr) {
    return;
  }
  static auto* retained = new std::vector<std::shared_ptr<void>>();
  retained->push_back(ptr);
}

}  // namespace
#endif

FuzzerEngine::FuzzerEngine(uint32_t rng_seed)
    : mutation_engine_(rng_seed), rng_(rng_seed) {}

FuzzerEngine::~FuzzerEngine() {
#if defined(SCARAB_FUZZER_HAS_ROS2)
  if (retain_custom_node_until_process_exit_) {
    retain_shared_ptr_until_process_exit(persistent_custom_executor_);
    retain_shared_ptr_until_process_exit(persistent_custom_node_);
    persistent_custom_executor_.reset();
    persistent_custom_node_.reset();
    persistent_custom_setup_done_ = false;
    return;
  }

  if (persistent_custom_executor_ != nullptr) {
    try {
      persistent_custom_executor_->cancel();
    } catch (...) {
    }
  }

  if (persistent_custom_setup_done_ && node_teardown_hook_ &&
      persistent_custom_node_ != nullptr && persistent_custom_executor_ != nullptr) {
    try {
      node_teardown_hook_(persistent_custom_node_, persistent_custom_executor_);
    } catch (const std::exception& e) {
      scarab::common::log_error(
          std::string("FuzzerEngine persistent node teardown failed: ") + e.what());
    } catch (...) {
      scarab::common::log_error("FuzzerEngine persistent node teardown failed");
    }
  }

  if (persistent_custom_executor_ != nullptr && persistent_custom_node_ != nullptr) {
    try {
      persistent_custom_executor_->remove_node(persistent_custom_node_);
    } catch (...) {
    }
  }

  persistent_custom_setup_done_ = false;
  persistent_custom_executor_.reset();
  persistent_custom_node_.reset();
#endif
}

#if defined(SCARAB_FUZZER_HAS_ROS2)
void FuzzerEngine::set_node_factory(NodeFactory factory) {
  node_factory_ = std::move(factory);
}

void FuzzerEngine::set_node_setup_hook(NodeExecutorHook hook) {
  node_setup_hook_ = std::move(hook);
}

void FuzzerEngine::set_node_teardown_hook(NodeExecutorHook hook) {
  node_teardown_hook_ = std::move(hook);
}

void FuzzerEngine::set_reuse_custom_node_across_iterations(bool enabled) {
  reuse_custom_node_across_iterations_ = enabled;
}

void FuzzerEngine::set_retain_custom_node_until_process_exit(bool enabled) {
  retain_custom_node_until_process_exit_ = enabled;
}

void FuzzerEngine::set_node_iteration_end_hook(NodeExecutorHook hook) {
  node_iteration_end_hook_ = std::move(hook);
}
#endif

bool FuzzerEngine::load_candidates(
    const std::string& path, std::vector<scarab::common::RaceCandidate>* candidates,
    std::string* error_message) const {
  return scarab::common::load_race_candidates_from_file(path, candidates, error_message);
}

bool FuzzerEngine::load_corpus(const std::string& corpus_dir, std::vector<Seed>* corpus,
                               FuzzerRunSummary* summary,
                               std::string* error_message) const {
  if (corpus == nullptr) {
    if (error_message != nullptr) {
      *error_message = "Corpus output pointer is null";
    }
    return false;
  }
  corpus->clear();

  const fs::path dir(corpus_dir);
  std::error_code ec;
  fs::create_directories(dir, ec);
  if (ec) {
    if (error_message != nullptr) {
      *error_message = "Failed to create corpus directory: " + dir.string();
    }
    return false;
  }

  for (const auto& entry : fs::directory_iterator(dir, ec)) {
    if (ec) {
      if (error_message != nullptr) {
        *error_message = "Failed to iterate corpus directory: " + dir.string();
      }
      return false;
    }

    if (!entry.is_regular_file()) {
      continue;
    }

    std::vector<uint8_t> bytes;
    if (!read_binary_file(entry.path(), &bytes)) {
      scarab::common::log_error("Failed to read corpus seed: " + entry.path().string());
      continue;
    }

    auto parsed = Seed::deserialize(bytes);
    if (!parsed.has_value()) {
      scarab::common::log_error("Ignoring invalid seed file: " + entry.path().string());
      continue;
    }

    corpus->push_back(*parsed);
    if (summary != nullptr) {
      ++summary->seeds_loaded;
    }
  }

  return true;
}

bool FuzzerEngine::add_seed_to_corpus(const Seed& seed, const std::string& corpus_dir,
                                      std::vector<Seed>* corpus,
                                      FuzzerRunSummary* summary,
                                      std::string* error_message) {
  if (corpus == nullptr) {
    if (error_message != nullptr) {
      *error_message = "Corpus output pointer is null";
    }
    return false;
  }

  const std::vector<uint8_t> serialized = seed.serialize();
  if (serialized.empty()) {
    if (error_message != nullptr) {
      *error_message = "Seed serialization failed";
    }
    return false;
  }

  std::unordered_set<std::string> seen_keys;
  seen_keys.reserve(corpus->size() + 1);
  for (const auto& existing : *corpus) {
    const auto bytes = existing.serialize();
    seen_keys.insert(seed_key(bytes));
  }

  const std::string key = seed_key(serialized);
  if (seen_keys.find(key) != seen_keys.end()) {
    return true;
  }

  corpus->push_back(seed);
  const fs::path dir(corpus_dir);
  const size_t file_index = corpus->size();
  const fs::path path = dir / make_seed_file_name(seed.header().candidate_id, file_index);
  if (!write_binary_file(path, serialized)) {
    if (error_message != nullptr) {
      *error_message = "Failed to save seed: " + path.string();
    }
    return false;
  }

  if (summary != nullptr) {
    ++summary->seeds_saved;
    summary->corpus_size = corpus->size();
  }
  return true;
}

Seed FuzzerEngine::select_seed(const std::vector<Seed>& corpus,
                               bool energy_based) {
  if (!energy_based || corpus.empty()) {
    std::uniform_int_distribution<size_t> dist(0, corpus.size() - 1);
    return corpus[dist(rng_)];
  }

  // Energy-based selection: weight each seed by its candidate's
  // exploration state.
  std::vector<double> weights(corpus.size());
  for (size_t i = 0; i < corpus.size(); ++i) {
    const uint32_t cid = corpus[i].header().candidate_id;
    double w = 1.0;

    auto it = candidate_stats_.find(cid);
    if (it != candidate_stats_.end()) {
      // Boost candidates that have found bugs.
      if (it->second.bugs_found > 0) {
        w += 2.0 * it->second.bugs_found;
      }
      // Diminishing returns for heavily-explored candidates.
      if (it->second.times_selected > 0) {
        w /= (1.0 + std::log2(1.0 + it->second.times_selected));
      }
    } else {
      // Unexplored candidate — give it a discovery boost.
      w = 2.0;
    }

    weights[i] = std::max(0.1, w);
  }

  std::discrete_distribution<size_t> dist(weights.begin(), weights.end());
  const size_t idx = dist(rng_);

  // Track selection count.
  const uint32_t cid = corpus[idx].header().candidate_id;
  candidate_stats_[cid].times_selected++;

  return corpus[idx];
}

FuzzerExecutionResult FuzzerEngine::execute_one(const Seed& seed, const FuzzerConfig& config) {
  (void)seed;
  FuzzerExecutionResult result;

#if !defined(SCARAB_FUZZER_HAS_ROS2)
  result.success = false;
  result.crashed = true;
  result.is_env_error = true;
  result.error_message = "SCARAB built without ROS2 support";
  return result;
#else
  // Use an injected NodeFactory when one is set, otherwise fall back to the
  // built-in EngineMiniNode probe.
  const bool using_custom_node = static_cast<bool>(node_factory_);
  const bool reuse_persistent_custom =
      using_custom_node && reuse_custom_node_across_iterations_;

  // Persistent custom-node mode keeps the ROS runtime alive across iterations.
  // Do not create a scoped init/shutdown guard in that mode.
  std::unique_ptr<RosRuntimeScope> ros_scope;
  if (reuse_persistent_custom) {
    if (!rclcpp::ok()) {
      int argc = 0;
      char** argv = nullptr;
      rclcpp::init(argc, argv);
    }
  } else {
    ros_scope = std::make_unique<RosRuntimeScope>();
  }
  // Capture STDERR_FILENO for the duration of this execution so that TSan /
  // ASan output written by the in-process callbacks is available to the oracle.
  ScopedStderrCapture stderr_capture;
  // Snapshot existing TSAN log bytes so oracle parsing consumes only output
  // emitted by this execution.
  oracle_manager_.prime_tsan_log_offsets_from_env();

  std::shared_ptr<rclcpp::Node> node;
  std::shared_ptr<EngineMiniNode> mini_node;
  std::shared_ptr<InstrumentedExecutor> executor;
  std::shared_ptr<Recorder> recorder;
  std::thread stopper;
  bool custom_setup_done = false;
  bool teardown_enabled = true;

  auto teardown_custom_node = [&]() {
    if (!teardown_enabled || !executor || !node) {
      return;
    }
    if (custom_setup_done && node_teardown_hook_) {
      try {
        node_teardown_hook_(node, executor);
      } catch (const std::exception& e) {
        scarab::common::log_error(
            std::string("FuzzerEngine node teardown hook failed: ") + e.what());
      } catch (...) {
        scarab::common::log_error("FuzzerEngine node teardown hook failed");
      }
    }
    try {
      executor->remove_node(node);
    } catch (...) {
    }
  };

  try {
    // Set up event recording for this iteration.
    if (!config.output_dir.empty()) {
      const auto event_log_path = fs::path(config.output_dir) / ".current_events.scrb";
      recorder = std::make_shared<Recorder>(event_log_path.string());
      recorder->start();
    }

    if (reuse_persistent_custom) {
      if (!persistent_custom_node_) {
        persistent_custom_node_ = node_factory_();
      }
      node = persistent_custom_node_;

      if (!persistent_custom_executor_) {
        persistent_custom_executor_ = std::make_shared<InstrumentedExecutor>(
            InstrumentedExecutor::Mode::FUZZ,
            static_cast<size_t>(std::max(1, config.num_threads)),
            false,
            std::chrono::milliseconds(5));
        persistent_custom_executor_->add_node(node);
        if (node_setup_hook_) {
          node_setup_hook_(node, persistent_custom_executor_);
          persistent_custom_setup_done_ = true;
        }
      }

      executor = persistent_custom_executor_;
      custom_setup_done = persistent_custom_setup_done_;
      teardown_enabled = false;
    } else if (using_custom_node) {
      node = node_factory_();
    } else {
      mini_node = std::make_shared<EngineMiniNode>();
      node = mini_node;
    }

    if (!executor) {
      executor = std::make_shared<InstrumentedExecutor>(
          InstrumentedExecutor::Mode::FUZZ,
          static_cast<size_t>(std::max(1, config.num_threads)),
          false,
          std::chrono::milliseconds(5));
    }
    const auto schedule = FuzzSchedule::from_seed(seed);
    executor->set_schedule(schedule);
    executor->clear_callback_events();
    executor->set_recorder(recorder);
    if (!reuse_persistent_custom) {
      executor->add_node(node);
      if (node_setup_hook_) {
        node_setup_hook_(node, executor);
        custom_setup_done = true;
      }
    }

    // Install the access-point runtime hooks before spinning the executor.
    // RECORD mode when we have a recorder, FUZZ mode otherwise.
    const auto rt_mode = recorder ? ScarabRuntime::Mode::RECORD
                                  : ScarabRuntime::Mode::FUZZ;
    ScarabRuntime::install(rt_mode, schedule, recorder);

    stopper = std::thread([executor, &config]() {
      std::this_thread::sleep_for(
          std::chrono::milliseconds(std::max(10, config.iteration_runtime_ms)));
      executor->cancel();
    });

    executor->spin();
    if (stopper.joinable()) {
      stopper.join();
    }

    // Give persistent targets a chance to clean up between iterations
    // (e.g. cancel in-flight action goals) while the executor threads
    // are still available to process cleanup callbacks.
    if (reuse_persistent_custom && node_iteration_end_hook_ && node) {
      try {
        node_iteration_end_hook_(node, executor);
      } catch (...) {
      }
    }

    ScarabRuntime::uninstall();
    teardown_custom_node();

    if (recorder) {
      recorder->stop();
      result.event_log_path = recorder->output_path();
    }

    // Restore stderr and collect any sanitizer output before building result.
    result.stderr_output = stderr_capture.finish();
    result.exit_code = 0;
    result.success = true;
    result.crashed = false;
    result.callbacks_executed = using_custom_node ? true : mini_node->callbacks_executed();
    result.callback_event_count = executor->callback_events().size();
    return result;
  } catch (const std::exception& e) {
    if (executor != nullptr) {
      executor->cancel();
    }
    if (stopper.joinable()) {
      stopper.join();
    }
    ScarabRuntime::uninstall();
    teardown_custom_node();
    if (recorder) {
      recorder->stop();
      result.event_log_path = recorder->output_path();
    }
    result.stderr_output = stderr_capture.finish();
    result.exit_code = -6;  // SIGABRT
    result.success = false;
    result.crashed = true;
    result.error_message = e.what();
    return result;
  } catch (...) {
    if (executor != nullptr) {
      executor->cancel();
    }
    if (stopper.joinable()) {
      stopper.join();
    }
    ScarabRuntime::uninstall();
    teardown_custom_node();
    if (recorder) {
      recorder->stop();
      result.event_log_path = recorder->output_path();
    }
    result.stderr_output = stderr_capture.finish();
    result.exit_code = -6;  // SIGABRT
    result.success = false;
    result.crashed = true;
    result.error_message = "Unknown exception";
    return result;
  }
#endif
}

bool FuzzerEngine::try_replay_reproduces(const EventLog& candidate,
                                          const FuzzerConfig& config,
                                          const std::string& target_sig) {
#if !defined(SCARAB_FUZZER_HAS_ROS2)
  (void)candidate;
  (void)config;
  (void)target_sig;
  return false;
#else
  // Write the candidate event log to a temp file.
  const auto tmp_dir = fs::temp_directory_path() / "scarab-minimize-replay";
  fs::create_directories(tmp_dir);
  const auto tmp_path =
      tmp_dir / ("replay_" + std::to_string(::getpid()) + ".scrb");

  if (!write_event_log_to_file(candidate, tmp_path.string())) {
    return false;
  }

  try {
    RosRuntimeScope ros_scope;
    ScopedStderrCapture stderr_capture;
    oracle_manager_.prime_tsan_log_offsets_from_env();

    auto replayer = std::make_shared<Replayer>(tmp_path.string());

    const bool using_custom_node = static_cast<bool>(node_factory_);
    std::shared_ptr<rclcpp::Node> node;
    std::shared_ptr<EngineMiniNode> mini_node;
    bool custom_setup_done = false;

    if (using_custom_node) {
      node = node_factory_();
    } else {
      mini_node = std::make_shared<EngineMiniNode>();
      node = mini_node;
    }

    auto executor = std::make_shared<InstrumentedExecutor>(
        InstrumentedExecutor::Mode::REPLAY,
        static_cast<size_t>(std::max(1, config.num_threads)),
        false,
        std::chrono::milliseconds(5));
    executor->set_replayer(replayer);
    executor->add_node(node);
    if (node_setup_hook_) {
      node_setup_hook_(node, executor);
      custom_setup_done = true;
    }

    auto teardown_custom_node = [&]() {
      if (!executor || !node) {
        return;
      }
      if (custom_setup_done && node_teardown_hook_) {
        try {
          node_teardown_hook_(node, executor);
        } catch (const std::exception& e) {
          scarab::common::log_error(
              std::string("FuzzerEngine replay node teardown hook failed: ") + e.what());
        } catch (...) {
          scarab::common::log_error("FuzzerEngine replay node teardown hook failed");
        }
      }
      executor->remove_node(node);
    };

    std::thread stopper([executor, &config]() {
      std::this_thread::sleep_for(
          std::chrono::milliseconds(std::max(10, config.iteration_runtime_ms)));
      executor->cancel();
    });

    executor->spin();
    if (stopper.joinable()) {
      stopper.join();
    }
    teardown_custom_node();

    FuzzerExecutionResult result;
    result.stderr_output = stderr_capture.finish();
    result.success = true;
    result.exit_code = 0;

    auto bugs = oracle_manager_.check(result);
    fs::remove(tmp_path);

    for (const auto& bug : bugs) {
      if (Deduplicator::build_signature(bug) == target_sig) {
        return true;
      }
    }
  } catch (...) {
    fs::remove(tmp_path);
  }

  return false;
#endif
}

bool FuzzerEngine::write_run_summary_file(const FuzzerRunSummary& summary,
                                          const std::string& output_dir,
                                          std::string* error_message) {
  std::error_code ec;
  fs::create_directories(output_dir, ec);
  if (ec) {
    if (error_message != nullptr) {
      *error_message = "Failed to create output directory: " + output_dir;
    }
    return false;
  }

  const fs::path summary_path = fs::path(output_dir) / "fuzzer_run_summary.txt";
  std::ofstream out(summary_path);
  if (!out.good()) {
    if (error_message != nullptr) {
      *error_message = "Failed to open summary file: " + summary_path.string();
    }
    return false;
  }

  out << "iterations=" << summary.iterations << '\n';
  out << "total_executions=" << summary.total_executions << '\n';
  out << "crashes=" << summary.crashes << '\n';
  out << "bugs_found=" << summary.bugs_found << '\n';
  out << "total_bug_reports=" << summary.total_bug_reports << '\n';
  out << "internal_races_filtered=" << summary.internal_races_filtered << '\n';
  out << "callbacks_ok=" << summary.callbacks_ok << '\n';
  out << "seeds_loaded=" << summary.seeds_loaded << '\n';
  out << "seeds_saved=" << summary.seeds_saved << '\n';
  out << "initial_seeds_created=" << summary.initial_seeds_created << '\n';
  out << "corpus_size=" << summary.corpus_size << '\n';
  return true;
}

bool FuzzerEngine::run(const FuzzerConfig& config, FuzzerRunSummary* summary) {
  FuzzerRunSummary local_summary;
  std::string error_message;

  if (config.duration_sec <= 0) {
    scarab::common::log_error("FuzzerEngine: duration_sec must be > 0");
    if (summary != nullptr) {
      *summary = local_summary;
    }
    return false;
  }
  if (config.candidates_path.empty() || config.corpus_dir.empty() ||
      config.output_dir.empty()) {
    scarab::common::log_error(
        "FuzzerEngine: candidates_path/corpus_dir/output_dir must be set");
    if (summary != nullptr) {
      *summary = local_summary;
    }
    return false;
  }

  std::vector<scarab::common::RaceCandidate> candidates;
  if (!load_candidates(config.candidates_path, &candidates, &error_message)) {
    scarab::common::log_error("FuzzerEngine: failed to load candidates: " + error_message);
    if (summary != nullptr) {
      *summary = local_summary;
    }
    return false;
  }

  // Initialize Directed PCT scheduler when enabled.
  // The environment variable SCARAB_DISABLE_DIRECTED_PCT=1 overrides the config
  // to force random scheduling (used by baseline comparison experiments).
  bool use_directed_pct = config.use_directed_pct;
  {
    const char* env_disable = std::getenv("SCARAB_DISABLE_DIRECTED_PCT");
    if (env_disable != nullptr && std::string(env_disable) == "1") {
      use_directed_pct = false;
      scarab::common::log_info("FuzzerEngine: Directed PCT disabled by environment variable");
    }
  }
  if (use_directed_pct && !candidates.empty()) {
    directed_pct_ = DirectedPctScheduler(candidates);
  }
  candidate_stats_.clear();

  std::vector<Seed> corpus;
  if (!load_corpus(config.corpus_dir, &corpus, &local_summary, &error_message)) {
    scarab::common::log_error("FuzzerEngine: failed to load corpus: " + error_message);
    if (summary != nullptr) {
      *summary = local_summary;
    }
    return false;
  }

  for (const auto& candidate : candidates) {
    const auto initial = Seed::create_initial(candidate);
    if (!initial.has_value()) {
      continue;
    }

    if (!add_seed_to_corpus(*initial, config.corpus_dir, &corpus, &local_summary,
                            &error_message)) {
      scarab::common::log_error("FuzzerEngine: failed to add initial seed: " + error_message);
      if (summary != nullptr) {
        *summary = local_summary;
      }
      return false;
    }
    ++local_summary.initial_seeds_created;
  }

  if (corpus.empty()) {
    scarab::common::log_error("FuzzerEngine: no seeds available to execute");
    if (summary != nullptr) {
      *summary = local_summary;
    }
    return false;
  }

  local_summary.corpus_size = corpus.size();
  const auto start = std::chrono::steady_clock::now();
  const auto deadline = start + std::chrono::seconds(config.duration_sec);

  // Ensure the bugs output directory exists before the loop.
  const fs::path bugs_dir = fs::path(config.output_dir) / "bugs";
  {
    std::error_code ec;
    fs::create_directories(bugs_dir, ec);
  }

  Deduplicator deduplicator;
  while (std::chrono::steady_clock::now() < deadline) {
    const Seed selected_seed =
        select_seed(corpus, use_directed_pct);

    Seed mutated_seed;
    if (use_directed_pct && !directed_pct_.empty()) {
      std::uniform_real_distribution<float> pct_roll(0.0f, 1.0f);
      if (pct_roll(rng_) < config.directed_pct_ratio) {
        // ── Directed PCT path ──────────────────────────────────────────
        FuzzSchedule pct_schedule =
            directed_pct_.generate_schedule(selected_seed, rng_);
        mutated_seed = selected_seed;
        auto& entries = mutated_seed.schedule_entries();
        for (size_t i = 0;
             i < entries.size() && i < pct_schedule.entries.size(); ++i) {
          entries[i].delay_us = pct_schedule.entries[i].delay_us;
        }
      } else {
        // ── Random mutation path (diversity) ───────────────────────────
        mutated_seed = mutation_engine_.mutate(selected_seed, rng_);
      }
    } else {
      mutated_seed = mutation_engine_.mutate(selected_seed, rng_);
    }

    FuzzerExecutionResult execution = execute_one(mutated_seed, config);
    ++local_summary.iterations;
    ++local_summary.total_executions;

    if (execution.crashed && !execution.is_env_error) {
      ++local_summary.crashes;
      if (!execution.error_message.empty()) {
        scarab::common::log_error(
            "FuzzerEngine execution error: " + execution.error_message);
      }
    }
    if (execution.callbacks_executed) {
      ++local_summary.callbacks_ok;
    }

    // ── Oracle check ──────────────────────────────────────────────────────
    if (!execution.is_env_error) {
      const auto bugs = oracle_manager_.check(execution);
      local_summary.total_bug_reports += bugs.size();
      local_summary.internal_races_filtered =
          oracle_manager_.internal_races_filtered();
      if (!bugs.empty()) {
        for (const auto& bug : bugs) {
          if (!deduplicator.observe(bug)) {
            continue;
          }

          ++local_summary.bugs_found;
          const fs::path bug_path =
              bugs_dir / make_seed_file_name(mutated_seed.header().candidate_id,
                                             local_summary.bugs_found);
          const std::vector<uint8_t> seed_bytes = mutated_seed.serialize();
          write_binary_file(bug_path, seed_bytes);

          // Save the event log alongside the seed for replay.
          if (!execution.event_log_path.empty()) {
            const auto event_src = fs::path(execution.event_log_path);
            if (fs::exists(event_src)) {
              const auto event_dst =
                  bugs_dir / ("bug_" + std::to_string(local_summary.bugs_found) +
                              "_events.scrb");
              std::error_code copy_ec;
              fs::copy_file(event_src, event_dst,
                            fs::copy_options::overwrite_existing, copy_ec);

              // ── Minimization ────────────────────────────────────────────
              if (config.enable_minimization) {
                try {
                  Replayer log_reader(event_dst.string());
                  const auto& original_log = log_reader.event_log();
                  const std::string target_sig =
                      Deduplicator::build_signature(bug);

                  Minimizer::Config min_cfg;
                  min_cfg.max_rounds = 8;
                  min_cfg.replay_attempts = 1;
                  Minimizer minimizer(min_cfg);

                  // Build a reproduce function that replays the candidate
                  // in-process and checks the oracle for the same signature.
                  auto reproduce_fn =
                      [this, &config, &target_sig](
                          const EventLog& candidate) -> bool {
                    return try_replay_reproduces(candidate, config, target_sig);
                  };

                  auto minimized =
                      minimizer.minimize(original_log, reproduce_fn);

                  const auto min_dst = bugs_dir /
                      ("bug_" + std::to_string(local_summary.bugs_found) +
                       "_events_min.scrb");
                  write_event_log_to_file(minimized, min_dst.string());
                  scarab::common::log_info(
                      "[MINIMIZED] " +
                      std::to_string(original_log.event_count()) + " -> " +
                      std::to_string(minimized.event_count()) + " events");
                } catch (const std::exception& min_err) {
                  scarab::common::log_error(
                      "Minimization failed: " + std::string(min_err.what()));
                }
              }
            }
          }

          scarab::common::log_info(
              "[BUG FOUND] type=" + bug.type +
              " severity=" + std::to_string(bug.severity) +
              " desc=" + bug.description);

          // Feed back to directed PCT scheduler.
          if (use_directed_pct && !directed_pct_.empty()) {
            const uint32_t cid = mutated_seed.header().candidate_id;
            directed_pct_.update_priorities(true, cid);
            candidate_stats_[cid].bugs_found++;
          }
        }
      }
    }

    if (!add_seed_to_corpus(mutated_seed, config.corpus_dir, &corpus, &local_summary,
                            &error_message)) {
      scarab::common::log_error("FuzzerEngine: failed to persist mutated seed: " +
                                error_message);
      break;
    }

    scarab::common::log_info("FuzzerEngine iteration=" +
                             std::to_string(local_summary.iterations) +
                             " callback_events=" +
                             std::to_string(execution.callback_event_count) +
                             " corpus=" + std::to_string(corpus.size()) +
                             " crashed=" + std::to_string(local_summary.crashes) +
                             " internal_filtered=" +
                             std::to_string(local_summary.internal_races_filtered) +
                             " unique bugs: " + std::to_string(local_summary.bugs_found) +
                             " / total reports: " +
                             std::to_string(local_summary.total_bug_reports));
  }

  local_summary.internal_races_filtered = oracle_manager_.internal_races_filtered();
  local_summary.corpus_size = corpus.size();
  if (!write_run_summary_file(local_summary, config.output_dir, &error_message)) {
    scarab::common::log_error("FuzzerEngine: failed to write run summary: " + error_message);
    if (summary != nullptr) {
      *summary = local_summary;
    }
    return false;
  }

  if (summary != nullptr) {
    *summary = local_summary;
  }
  return true;
}

}  // namespace scarab::fuzzer
