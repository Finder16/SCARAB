#pragma once

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>

#include "scarab/fuzzer/event.h"
#include "scarab/fuzzer/recorder.h"
#include "scarab/fuzzer/replayer.h"
#include "scarab/fuzzer/seed.h"

#if defined(SCARAB_FUZZER_HAS_ROS2)
#include "rclcpp/any_executable.hpp"
#include "rclcpp/executors/multi_threaded_executor.hpp"
#endif

namespace scarab::fuzzer {

#if defined(SCARAB_FUZZER_HAS_ROS2)
using CallbackId = uint16_t;
#endif

struct FuzzScheduleEntry {
  uint16_t callback_id = 0;
  uint8_t thread_id = 0;
  uint32_t delay_us = 0;
};

struct FuzzSchedule {
  std::vector<FuzzScheduleEntry> entries;
  uint32_t default_delay_us = 0;

  /// Access-point-level delays: source_line → delay_us.
  /// Used by libscarab_rt hooks to inject delays at specific shared variable
  /// access points identified by Stage 1.
  std::unordered_map<int, uint32_t> access_point_delays;

  static FuzzSchedule from_seed(const Seed& seed);
  uint32_t delay_for(uint16_t callback_id, size_t sequence_index) const;
  uint32_t access_delay_for(int source_line) const;
};

struct CallbackDispatchEvent {
  enum class Type : uint8_t { kReady = 0, kStart = 1, kEnd = 2 };

  Type type = Type::kReady;
  uint16_t callback_id = 0;
  uint32_t applied_delay_us = 0;
  uint64_t timestamp_ns = 0;
};

#if defined(SCARAB_FUZZER_HAS_ROS2)
class InstrumentedExecutor : public rclcpp::executors::MultiThreadedExecutor {
 public:
  enum class Mode { FUZZ, RECORD, REPLAY };

  explicit InstrumentedExecutor(
      Mode mode = Mode::FUZZ,
      size_t number_of_threads = 0,
      bool yield_before_execute = false,
      std::chrono::nanoseconds next_exec_timeout = std::chrono::nanoseconds(-1),
      const rclcpp::ExecutorOptions& options = rclcpp::ExecutorOptions());

  void spin() override;

  void set_seed(const Seed& seed);
  void set_schedule(const FuzzSchedule& schedule);
  void set_recorder(std::shared_ptr<Recorder> recorder);
  void set_replayer(std::shared_ptr<Replayer> replayer);

  std::vector<CallbackDispatchEvent> callback_events() const;
  void clear_callback_events();

 protected:
  virtual void on_callback_ready(CallbackId id);
  virtual void on_callback_start(CallbackId id);
  virtual void on_callback_end(CallbackId id);

 private:
  static constexpr CallbackId kUnknownCallbackId = 0xFFFFu;

  void run_loop(size_t this_thread_number);
  void run_loop_replay();
  void worker_thread_replay(uint16_t thread_id);
  CallbackId resolve_callback_id(const rclcpp::AnyExecutable& any_exec);
  uint32_t get_delay_for_callback(CallbackId callback_id);
  void push_event(CallbackDispatchEvent::Type type, CallbackId id,
                  uint32_t applied_delay_us);
  static uint64_t now_steady_ns();

  void record_event(EventType type, uint32_t callback_id,
                    uint32_t delay_us = 0);

  Mode mode_;
  size_t number_of_threads_;
  bool yield_before_execute_;
  std::chrono::nanoseconds next_exec_timeout_;

  mutable std::mutex callback_id_mutex_;
  std::unordered_map<const void*, CallbackId> callback_ids_;
  CallbackId next_callback_id_ = 0;

  mutable std::mutex schedule_mutex_;
  FuzzSchedule schedule_;
  size_t schedule_cursor_ = 0;

  mutable std::mutex events_mutex_;
  std::vector<CallbackDispatchEvent> callback_events_;

  mutable std::mutex wait_mutex_;
  std::shared_ptr<Recorder> recorder_;

  // Replay — single-dispatcher pattern.
  std::shared_ptr<Replayer> replayer_;

  struct WorkerSlot {
    std::mutex mtx;
    std::condition_variable cv;
    std::unique_ptr<rclcpp::AnyExecutable> task;
    CallbackId callback_id = 0;
    bool has_task = false;
    bool task_started = false;
    bool task_done = false;
    bool shutdown = false;
  };
  std::vector<std::unique_ptr<WorkerSlot>> worker_slots_;

  // Set per-thread in run_loop() / worker_thread_replay(); used by record_event().
  static thread_local uint16_t current_thread_id_;
};
#else
class InstrumentedExecutor {
 public:
  enum class Mode { FUZZ, RECORD, REPLAY };

  explicit InstrumentedExecutor(
      Mode mode = Mode::FUZZ, size_t number_of_threads = 0,
      bool yield_before_execute = false,
      std::chrono::nanoseconds next_exec_timeout = std::chrono::nanoseconds(-1));

  void set_seed(const Seed& seed);
  void set_schedule(const FuzzSchedule& schedule);
  void set_recorder(std::shared_ptr<Recorder> recorder);
  void set_replayer(std::shared_ptr<Replayer> replayer);

  std::vector<CallbackDispatchEvent> callback_events() const;
  void clear_callback_events();

 private:
  Mode mode_;
  size_t number_of_threads_;
  bool yield_before_execute_;
  std::chrono::nanoseconds next_exec_timeout_;
  FuzzSchedule schedule_;
  std::vector<CallbackDispatchEvent> callback_events_;
};
#endif

}  // namespace scarab::fuzzer
