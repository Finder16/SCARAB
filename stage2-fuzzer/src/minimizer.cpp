#include "scarab/fuzzer/minimizer.h"

#include "scarab/common/logging.h"
#include "scarab/fuzzer/dedup.h"
#include "scarab/fuzzer/fuzzer_engine.h"
#include "scarab/fuzzer/recorder.h"
#include "scarab/fuzzer/replayer.h"

#include <algorithm>
#include <filesystem>
#include <string>
#include <unordered_map>
#include <vector>

#if defined(SCARAB_FUZZER_HAS_ROS2)
#include "scarab/fuzzer/instrumented_executor.h"

#include <mutex>
#include <thread>

#include <unistd.h>
#endif

namespace scarab::fuzzer {

namespace fs = std::filesystem;

// ── Constructors ─────────────────────────────────────────────────────────────

Minimizer::Minimizer() : config_() {}

Minimizer::Minimizer(Config config) : config_(config) {}

Minimizer::Minimizer(Config config, std::shared_ptr<OracleManager> oracle)
    : config_(config), oracle_(std::move(oracle)) {}

#if defined(SCARAB_FUZZER_HAS_ROS2)
void Minimizer::set_node_factory(NodeFactory factory) {
  node_factory_ = std::move(factory);
}
#endif

// ── Public minimize() overloads ──────────────────────────────────────────────

EventLog Minimizer::minimize(const EventLog& original,
                              const std::string& bug_signature) {
  auto reproduce_fn = [this, &bug_signature](const EventLog& candidate) {
    return reproduces(candidate, bug_signature);
  };
  return minimize(original, std::move(reproduce_fn));
}

EventLog Minimizer::minimize(const EventLog& original, ReproduceFn reproduce_fn) {
  if (original.events.empty()) {
    return original;
  }

  auto groups = group_events(original);
  if (groups.size() <= 1) {
    return original;
  }

  scarab::common::log_info(
      "Minimizer: starting with " + std::to_string(original.event_count()) +
      " events in " + std::to_string(groups.size()) + " callback groups");

  EventLog result = ddmin(original, std::move(groups), reproduce_fn, 2);

  const size_t orig_count = original.event_count();
  const size_t final_count = result.event_count();
  const int reduction =
      orig_count > 0
          ? static_cast<int>(100 * (orig_count - final_count) / orig_count)
          : 0;
  scarab::common::log_info(
      "Minimized: " + std::to_string(orig_count) + " -> " +
      std::to_string(final_count) + " events (" +
      std::to_string(reduction) + "% reduction)");

  return result;
}

// ── Callback grouping ────────────────────────────────────────────────────────

std::vector<Minimizer::CallbackGroup> Minimizer::group_events(
    const EventLog& log) {
  std::vector<CallbackGroup> groups;

  // Per-thread: index of the currently open group (between START and END).
  std::unordered_map<uint16_t, size_t> open_per_thread;

  for (size_t i = 0; i < log.events.size(); ++i) {
    const auto& event = log.events[i];

    switch (event.event_type) {
      case EventType::CALLBACK_DISPATCH: {
        auto it = open_per_thread.find(event.thread_id);
        if (it != open_per_thread.end()) {
          // Thread already has an open group — append.
          groups[it->second].event_indices.push_back(i);
        } else {
          // Start a new group for this DISPATCH.
          groups.push_back({{i}});
          open_per_thread[event.thread_id] = groups.size() - 1;
        }
        break;
      }

      case EventType::CALLBACK_START: {
        auto it = open_per_thread.find(event.thread_id);
        if (it != open_per_thread.end()) {
          groups[it->second].event_indices.push_back(i);
        } else {
          // START without preceding DISPATCH — start new group.
          groups.push_back({{i}});
          open_per_thread[event.thread_id] = groups.size() - 1;
        }
        break;
      }

      case EventType::DELAY:
      case EventType::YIELD: {
        auto it = open_per_thread.find(event.thread_id);
        if (it != open_per_thread.end()) {
          groups[it->second].event_indices.push_back(i);
        } else {
          // Standalone delay/yield — singleton group.
          groups.push_back({{i}});
        }
        break;
      }

      case EventType::CALLBACK_END: {
        auto it = open_per_thread.find(event.thread_id);
        if (it != open_per_thread.end()) {
          groups[it->second].event_indices.push_back(i);
          open_per_thread.erase(it);  // close the group
        } else {
          // Orphan END — singleton group.
          groups.push_back({{i}});
        }
        break;
      }
    }
  }

  return groups;
}

EventLog Minimizer::rebuild_log(
    const EventLog& original,
    const std::vector<CallbackGroup>& groups) {
  // Collect kept indices and sort to preserve original order.
  std::vector<bool> included(original.events.size(), false);
  for (const auto& group : groups) {
    for (size_t idx : group.event_indices) {
      included[idx] = true;
    }
  }

  EventLog result;
  result.start_timestamp_ns = original.start_timestamp_ns;
  for (size_t i = 0; i < original.events.size(); ++i) {
    if (included[i]) {
      result.events.push_back(original.events[i]);
    }
  }
  return result;
}

// ── Delta-debugging core ─────────────────────────────────────────────────────

EventLog Minimizer::ddmin(const EventLog& original,
                           std::vector<CallbackGroup> groups,
                           const ReproduceFn& reproduce_fn,
                           int n) {
  int round = 0;

  while (round < config_.max_rounds) {
    ++round;
    const int group_count = static_cast<int>(groups.size());

    if (group_count <= 1 || n > group_count) {
      break;
    }

    const int chunk_size = (group_count + n - 1) / n;
    bool reduced = false;

    for (int i = 0; i < n; ++i) {
      const int start = i * chunk_size;
      const int end = std::min(start + chunk_size, group_count);
      if (start >= group_count) break;

      // Build complement: all groups except this chunk.
      std::vector<CallbackGroup> complement;
      complement.reserve(static_cast<size_t>(group_count - (end - start)));
      for (int j = 0; j < group_count; ++j) {
        if (j < start || j >= end) {
          complement.push_back(groups[static_cast<size_t>(j)]);
        }
      }

      if (complement.empty()) continue;

      EventLog candidate = rebuild_log(original, complement);

      scarab::common::log_info(
          "Minimize round " + std::to_string(round) + ": " +
          std::to_string(rebuild_log(original, groups).event_count()) +
          " -> " + std::to_string(candidate.event_count()) +
          " events, testing...");

      if (reproduce_fn(candidate)) {
        scarab::common::log_info(
            "Minimize round " + std::to_string(round) + ": reproduces=yes");
        groups = std::move(complement);
        n = std::max(n - 1, 2);
        reduced = true;
        break;
      }
    }

    if (!reduced) {
      if (n >= group_count) {
        break;  // 1-minimal
      }
      n = std::min(2 * n, group_count);
    }
  }

  return rebuild_log(original, groups);
}

// ── Internal reproduces() ────────────────────────────────────────────────────

bool Minimizer::reproduces(const EventLog& candidate,
                            const std::string& target_sig) {
  if (!oracle_) return false;

#if !defined(SCARAB_FUZZER_HAS_ROS2)
  (void)candidate;
  (void)target_sig;
  return false;
#else
  if (!node_factory_) return false;

  const auto tmp_dir = fs::temp_directory_path() / "scarab-minimizer";
  fs::create_directories(tmp_dir);
  const auto tmp_path =
      tmp_dir / ("min_candidate_" + std::to_string(::getpid()) + ".scrb");

  for (int attempt = 0; attempt < config_.replay_attempts; ++attempt) {
    if (!write_event_log_to_file(candidate, tmp_path.string())) {
      return false;
    }

    try {
      auto replayer = std::make_shared<Replayer>(tmp_path.string());
      auto node = node_factory_();
      auto executor = std::make_shared<InstrumentedExecutor>(
          InstrumentedExecutor::Mode::REPLAY, 2);
      executor->set_replayer(replayer);
      executor->add_node(node);

      std::thread stopper([executor, this]() {
        std::this_thread::sleep_for(config_.timeout);
        executor->cancel();
      });

      executor->spin();
      stopper.join();
      executor->remove_node(node);

      // Build a minimal FuzzerExecutionResult for the oracle.
      FuzzerExecutionResult result;
      result.success = true;
      result.exit_code = 0;

      auto bugs = oracle_->check(result);
      for (const auto& bug : bugs) {
        if (Deduplicator::build_signature(bug) == target_sig) {
          fs::remove(tmp_path);
          return true;
        }
      }
    } catch (...) {
      // Replay failed — treat as non-reproducing.
    }
  }

  fs::remove(tmp_path);
  return false;
#endif
}

}  // namespace scarab::fuzzer
