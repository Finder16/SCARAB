#pragma once

#include "scarab/fuzzer/event.h"
#include "scarab/fuzzer/oracle.h"

#include <chrono>
#include <cstddef>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#if defined(SCARAB_FUZZER_HAS_ROS2)
#include "rclcpp/rclcpp.hpp"
#endif

namespace scarab::fuzzer {

class Minimizer {
 public:
  struct Config {
    int max_rounds = 20;
    int replay_attempts = 3;
    std::chrono::seconds timeout{30};
  };

  /// Reproduction predicate: returns true if the candidate event log still
  /// triggers the target bug.
  using ReproduceFn = std::function<bool(const EventLog&)>;

  Minimizer();
  explicit Minimizer(Config config);
  Minimizer(Config config, std::shared_ptr<OracleManager> oracle);

  /// Minimize using the internal reproduces() method (requires oracle +
  /// node_factory to be set for ROS2 builds).
  EventLog minimize(const EventLog& original, const std::string& bug_signature);

  /// Minimize using a caller-provided reproduction function.
  /// This overload is used by FuzzerEngine (which owns the replay
  /// infrastructure) and by unit tests (which provide a mock).
  EventLog minimize(const EventLog& original, ReproduceFn reproduce_fn);

#if defined(SCARAB_FUZZER_HAS_ROS2)
  using NodeFactory = std::function<std::shared_ptr<rclcpp::Node>()>;
  void set_node_factory(NodeFactory factory);
#endif

 private:
  /// A group of events forming one callback invocation (atomic unit for ddmin).
  /// START/END pairs on the same thread are always removed together.
  struct CallbackGroup {
    std::vector<size_t> event_indices;  // indices into EventLog::events
  };

  /// Parse an EventLog into atomic callback groups.
  static std::vector<CallbackGroup> group_events(const EventLog& log);

  /// Rebuild an EventLog keeping only the events referenced by @p groups,
  /// preserving their original order.
  static EventLog rebuild_log(const EventLog& original,
                               const std::vector<CallbackGroup>& groups);

  /// Core delta-debugging loop operating on callback groups.
  EventLog ddmin(const EventLog& original,
                 std::vector<CallbackGroup> groups,
                 const ReproduceFn& reproduce_fn,
                 int n);

  /// Internal reproduction check using oracle + replay infrastructure.
  bool reproduces(const EventLog& candidate, const std::string& target_sig);

  Config config_;
  std::shared_ptr<OracleManager> oracle_;
#if defined(SCARAB_FUZZER_HAS_ROS2)
  NodeFactory node_factory_;
#endif
};

}  // namespace scarab::fuzzer
