#include "scarab/fuzzer/instrumented_executor.h"

#include <chrono>
#include <deque>
#include <stdexcept>
#include <thread>
#include <unordered_set>

namespace scarab::fuzzer {

FuzzSchedule FuzzSchedule::from_seed(const Seed& seed) {
  FuzzSchedule schedule;
  schedule.entries.reserve(seed.schedule_entries().size());

  for (const auto& entry : seed.schedule_entries()) {
    FuzzScheduleEntry schedule_entry;
    schedule_entry.callback_id = entry.callback_id;
    schedule_entry.thread_id = entry.thread_id;
    schedule_entry.delay_us = entry.delay_us;
    schedule.entries.push_back(schedule_entry);

    // Extract access-point-level delays from preemptions.
    for (const auto& preemption : entry.preemptions) {
      if (preemption.access_point_id != 0 && preemption.yield_duration_us > 0) {
        schedule.access_point_delays[static_cast<int>(preemption.access_point_id)] =
            preemption.yield_duration_us;
      }
    }
  }

  if (schedule.entries.size() == 1) {
    schedule.default_delay_us = schedule.entries.front().delay_us;
  }

  return schedule;
}

uint32_t FuzzSchedule::access_delay_for(int source_line) const {
  auto it = access_point_delays.find(source_line);
  if (it != access_point_delays.end()) {
    return it->second;
  }
  return 0;
}

uint32_t FuzzSchedule::delay_for(uint16_t callback_id, size_t sequence_index) const {
  for (const auto& entry : entries) {
    if (entry.callback_id == callback_id) {
      return entry.delay_us;
    }
  }
  if (sequence_index < entries.size()) {
    return entries[sequence_index].delay_us;
  }
  if (!entries.empty()) {
    return entries[sequence_index % entries.size()].delay_us;
  }
  return default_delay_us;
}

#if defined(SCARAB_FUZZER_HAS_ROS2)

thread_local uint16_t InstrumentedExecutor::current_thread_id_ = 0;

namespace {

const void* executable_identity(const rclcpp::AnyExecutable& any_exec) {
  if (any_exec.subscription != nullptr) {
    return any_exec.subscription.get();
  }
  if (any_exec.timer != nullptr) {
    return any_exec.timer.get();
  }
  if (any_exec.service != nullptr) {
    return any_exec.service.get();
  }
  if (any_exec.client != nullptr) {
    return any_exec.client.get();
  }
  if (any_exec.waitable != nullptr) {
    return any_exec.waitable.get();
  }
  if (any_exec.callback_group != nullptr) {
    return any_exec.callback_group.get();
  }
  return nullptr;
}

}  // namespace

InstrumentedExecutor::InstrumentedExecutor(
    Mode mode, size_t number_of_threads, bool yield_before_execute,
    std::chrono::nanoseconds next_exec_timeout, const rclcpp::ExecutorOptions& options)
    : rclcpp::executors::MultiThreadedExecutor(options, number_of_threads,
                                               yield_before_execute, next_exec_timeout),
      mode_(mode),
      number_of_threads_(number_of_threads),
      yield_before_execute_(yield_before_execute),
      next_exec_timeout_(next_exec_timeout) {
  if (number_of_threads_ == 0) {
    number_of_threads_ = std::thread::hardware_concurrency();
  }
  if (number_of_threads_ == 0) {
    number_of_threads_ = 1;
  }
}

void InstrumentedExecutor::spin() {
  if (spinning.exchange(true)) {
    throw std::runtime_error("spin() called while already spinning");
  }

  try {
    if (mode_ == Mode::REPLAY) {
      run_loop_replay();
    } else {
      std::vector<std::thread> threads;
      threads.reserve(number_of_threads_ > 0 ? number_of_threads_ - 1 : 0);

      size_t thread_id = 0;
      {
        std::lock_guard<std::mutex> wait_lock{wait_mutex_};
        for (; thread_id < number_of_threads_ - 1; ++thread_id) {
          threads.emplace_back([this, thread_id]() { run_loop(thread_id); });
        }
      }

      run_loop(thread_id);
      for (auto& thread : threads) {
        thread.join();
      }
    }
  } catch (...) {
    spinning.store(false);
    throw;
  }

  spinning.store(false);
}

void InstrumentedExecutor::set_seed(const Seed& seed) {
  set_schedule(FuzzSchedule::from_seed(seed));
}

void InstrumentedExecutor::set_schedule(const FuzzSchedule& schedule) {
  std::lock_guard<std::mutex> lock(schedule_mutex_);
  schedule_ = schedule;
  schedule_cursor_ = 0;
}

void InstrumentedExecutor::set_recorder(std::shared_ptr<Recorder> recorder) {
  recorder_ = std::move(recorder);
}

void InstrumentedExecutor::set_replayer(std::shared_ptr<Replayer> replayer) {
  replayer_ = std::move(replayer);
}

std::vector<CallbackDispatchEvent> InstrumentedExecutor::callback_events() const {
  std::lock_guard<std::mutex> lock(events_mutex_);
  return callback_events_;
}

void InstrumentedExecutor::clear_callback_events() {
  std::lock_guard<std::mutex> lock(events_mutex_);
  callback_events_.clear();
}

// ── Hook implementations ────────────────────────────────────────────────────

void InstrumentedExecutor::on_callback_ready(CallbackId id) {
  push_event(CallbackDispatchEvent::Type::kReady, id, 0);
  record_event(EventType::CALLBACK_DISPATCH, static_cast<uint32_t>(id));
}

void InstrumentedExecutor::on_callback_start(CallbackId id) {
  uint32_t applied_delay_us = 0;

  if (mode_ != Mode::REPLAY) {
    // FUZZ / RECORD mode — apply schedule delay.
    applied_delay_us = get_delay_for_callback(id);
    if (applied_delay_us > 0) {
      std::this_thread::sleep_for(std::chrono::microseconds(applied_delay_us));
    }
  }
  // In REPLAY mode the single dispatcher controls ordering; no sync needed.

  push_event(CallbackDispatchEvent::Type::kStart, id, applied_delay_us);
  record_event(EventType::CALLBACK_START, static_cast<uint32_t>(id));

  if (applied_delay_us > 0) {
    record_event(EventType::DELAY, static_cast<uint32_t>(id), applied_delay_us);
  }
}

void InstrumentedExecutor::on_callback_end(CallbackId id) {
  push_event(CallbackDispatchEvent::Type::kEnd, id, 0);
  record_event(EventType::CALLBACK_END, static_cast<uint32_t>(id));
}

// ── Private helpers ─────────────────────────────────────────────────────────

void InstrumentedExecutor::run_loop(size_t this_thread_number) {
  current_thread_id_ = static_cast<uint16_t>(this_thread_number);

  while (rclcpp::ok(this->context_) && spinning.load()) {
    rclcpp::AnyExecutable any_exec;
    {
      std::lock_guard<std::mutex> wait_lock{wait_mutex_};
      if (!rclcpp::ok(this->context_) || !spinning.load()) {
        return;
      }

      if (!get_next_executable(any_exec, next_exec_timeout_)) {
        continue;
      }
    }

    if (yield_before_execute_) {
      std::this_thread::yield();
    }

    const CallbackId callback_id = resolve_callback_id(any_exec);
    on_callback_ready(callback_id);
    on_callback_start(callback_id);
    execute_any_executable(any_exec);
    on_callback_end(callback_id);

    any_exec.callback_group.reset();
  }
}

void InstrumentedExecutor::run_loop_replay() {
  // Initialise per-thread worker slots.
  worker_slots_.clear();
  for (size_t i = 0; i < number_of_threads_; ++i) {
    auto slot = std::make_unique<WorkerSlot>();
    slot->task_started = true;
    slot->task_done = true;
    worker_slots_.push_back(std::move(slot));
  }

  // Launch worker threads (one per original thread id).
  std::vector<std::thread> workers;
  workers.reserve(number_of_threads_);
  for (size_t i = 0; i < number_of_threads_; ++i) {
    workers.emplace_back([this, i]() {
      worker_thread_replay(static_cast<uint16_t>(i));
    });
  }

  // Pending callbacks fetched earlier but not yet dispatched because they did
  // not match the next recorded callback id.
  std::deque<std::pair<CallbackId, rclcpp::AnyExecutable>> pending_callbacks;
  auto pop_pending_for_callback =
      [&pending_callbacks](CallbackId callback_id,
                           rclcpp::AnyExecutable* any_exec) -> bool {
    for (auto it = pending_callbacks.begin(); it != pending_callbacks.end();
         ++it) {
      if (it->first == callback_id) {
        *any_exec = std::move(it->second);
        pending_callbacks.erase(it);
        return true;
      }
    }
    return false;
  };
  std::unordered_map<uint32_t, CallbackId> recorded_to_actual_callback_id;
  std::unordered_set<CallbackId> mapped_actual_callback_ids;

  // ── Single-dispatcher loop ───────────────────────────────────────────────
  // Replay consumes CALLBACK_START decisions in recorded order and dispatches
  // the executable with the same callback_id on the recorded thread.
  while (rclcpp::ok(this->context_) && spinning.load()) {
    if (!replayer_ || replayer_->is_finished()) {
      break;
    }

    auto callback_start_event = replayer_->next_decision(EventType::CALLBACK_START);
    if (!callback_start_event.has_value()) {
      break;
    }

    const uint32_t recorded_callback_id = callback_start_event->callback_id;
    uint16_t target_thread = callback_start_event->thread_id;

    rclcpp::AnyExecutable any_exec;
    CallbackId expected_actual_callback_id = kUnknownCallbackId;
    bool mapping_ready = false;
    bool found_expected = false;

    if (const auto mapped =
            recorded_to_actual_callback_id.find(recorded_callback_id);
        mapped != recorded_to_actual_callback_id.end()) {
      expected_actual_callback_id = mapped->second;
      mapping_ready = true;
    } else {
      for (auto it = pending_callbacks.begin(); it != pending_callbacks.end();
           ++it) {
        if (mapped_actual_callback_ids.count(it->first) != 0) {
          continue;
        }
        expected_actual_callback_id = it->first;
        recorded_to_actual_callback_id.emplace(recorded_callback_id,
                                               expected_actual_callback_id);
        mapped_actual_callback_ids.insert(expected_actual_callback_id);
        any_exec = std::move(it->second);
        pending_callbacks.erase(it);
        mapping_ready = true;
        found_expected = true;
        break;
      }
    }

    if (mapping_ready && !found_expected) {
      found_expected =
          pop_pending_for_callback(expected_actual_callback_id, &any_exec);
    }

    while (!found_expected && rclcpp::ok(this->context_) && spinning.load()) {
      rclcpp::AnyExecutable candidate_exec;
      {
        std::lock_guard<std::mutex> wait_lock{wait_mutex_};
        if (!rclcpp::ok(this->context_) || !spinning.load()) {
          break;
        }
        if (!get_next_executable(candidate_exec, next_exec_timeout_)) {
          continue;
        }
      }

      const CallbackId candidate_id = resolve_callback_id(candidate_exec);
      if (!mapping_ready) {
        if (mapped_actual_callback_ids.count(candidate_id) == 0) {
          expected_actual_callback_id = candidate_id;
          recorded_to_actual_callback_id.emplace(recorded_callback_id,
                                                 expected_actual_callback_id);
          mapped_actual_callback_ids.insert(expected_actual_callback_id);
          any_exec = std::move(candidate_exec);
          found_expected = true;
          mapping_ready = true;
          break;
        }
      } else if (candidate_id == expected_actual_callback_id) {
        any_exec = std::move(candidate_exec);
        found_expected = true;
        break;
      }

      pending_callbacks.emplace_back(candidate_id, std::move(candidate_exec));
    }

    if (!found_expected) {
      break;
    }

    // Clamp to a valid worker index.
    if (target_thread >= static_cast<uint16_t>(number_of_threads_)) {
      target_thread = static_cast<uint16_t>(
          target_thread % number_of_threads_);
    }

    // Dispatch to the target worker.
    auto& slot = *worker_slots_[target_thread];
    bool stop_dispatching = false;
    {
      std::unique_lock<std::mutex> lock(slot.mtx);
      while (!slot.task_done && !slot.shutdown && spinning.load() &&
             rclcpp::ok(this->context_)) {
        slot.cv.wait_for(lock, std::chrono::milliseconds(5));
      }

      if (slot.shutdown || !slot.task_done || !spinning.load() ||
          !rclcpp::ok(this->context_)) {
        stop_dispatching = true;
      } else {
        slot.task =
            std::make_unique<rclcpp::AnyExecutable>(std::move(any_exec));
        slot.callback_id = static_cast<CallbackId>(recorded_callback_id);
        slot.has_task = true;
        slot.task_started = false;
        slot.task_done = false;
      }
    }
    if (stop_dispatching) {
      break;
    }
    slot.cv.notify_one();

    {
      std::unique_lock<std::mutex> lock(slot.mtx);
      while (!slot.task_started && !slot.shutdown && spinning.load() &&
             rclcpp::ok(this->context_)) {
        slot.cv.wait_for(lock, std::chrono::milliseconds(5));
      }
      if (!slot.task_started || slot.shutdown || !spinning.load() ||
          !rclcpp::ok(this->context_)) {
        break;
      }
    }
  }

  // Signal shutdown to all workers and join.
  for (auto& slot_ptr : worker_slots_) {
    {
      std::lock_guard<std::mutex> lock(slot_ptr->mtx);
      slot_ptr->shutdown = true;
    }
    slot_ptr->cv.notify_one();
  }

  for (auto& worker : workers) {
    worker.join();
  }

  for (auto& pending : pending_callbacks) {
    pending.second.callback_group.reset();
  }
  pending_callbacks.clear();

  worker_slots_.clear();
}

void InstrumentedExecutor::worker_thread_replay(uint16_t thread_id) {
  current_thread_id_ = thread_id;
  auto& slot = *worker_slots_[thread_id];

  while (true) {
    std::unique_lock<std::mutex> lock(slot.mtx);
    slot.cv.wait(lock, [&slot]() { return slot.has_task || slot.shutdown; });

    if (slot.shutdown && !slot.has_task) {
      break;
    }

    std::unique_ptr<rclcpp::AnyExecutable> task = std::move(slot.task);
    const CallbackId cb_id = slot.callback_id;
    slot.has_task = false;
    lock.unlock();

    if (!task) {
      std::lock_guard<std::mutex> lock2(slot.mtx);
      slot.task_started = true;
      slot.task_done = true;
      slot.cv.notify_one();
      continue;
    }

    if (yield_before_execute_) {
      std::this_thread::yield();
    }

    on_callback_ready(cb_id);
    on_callback_start(cb_id);
    {
      std::lock_guard<std::mutex> lock2(slot.mtx);
      slot.task_started = true;
    }
    slot.cv.notify_one();
    execute_any_executable(*task);
    on_callback_end(cb_id);
    task->callback_group.reset();

    // Signal completion to the dispatcher.
    {
      std::lock_guard<std::mutex> lock2(slot.mtx);
      slot.task_done = true;
    }
    slot.cv.notify_one();
  }
}

CallbackId InstrumentedExecutor::resolve_callback_id(
    const rclcpp::AnyExecutable& any_exec) {
  const void* identity = executable_identity(any_exec);
  if (identity == nullptr) {
    return kUnknownCallbackId;
  }

  std::lock_guard<std::mutex> lock(callback_id_mutex_);
  const auto found = callback_ids_.find(identity);
  if (found != callback_ids_.end()) {
    return found->second;
  }

  if (next_callback_id_ == kUnknownCallbackId) {
    return kUnknownCallbackId;
  }

  const CallbackId assigned = next_callback_id_;
  ++next_callback_id_;
  callback_ids_.emplace(identity, assigned);
  return assigned;
}

uint32_t InstrumentedExecutor::get_delay_for_callback(CallbackId callback_id) {
  std::lock_guard<std::mutex> lock(schedule_mutex_);
  const size_t current_sequence = schedule_cursor_;
  ++schedule_cursor_;
  return schedule_.delay_for(callback_id, current_sequence);
}

void InstrumentedExecutor::push_event(CallbackDispatchEvent::Type type, CallbackId id,
                                      uint32_t applied_delay_us) {
  CallbackDispatchEvent event;
  event.type = type;
  event.callback_id = id;
  event.applied_delay_us = applied_delay_us;
  event.timestamp_ns = now_steady_ns();

  std::lock_guard<std::mutex> lock(events_mutex_);
  callback_events_.push_back(event);
}

void InstrumentedExecutor::record_event(EventType type, uint32_t callback_id,
                                        uint32_t delay_us) {
  if (!recorder_) return;
  Event event;
  event.timestamp_ns = now_steady_ns();
  event.event_type = type;
  event.thread_id = current_thread_id_;
  event.callback_id = callback_id;
  event.delay_duration_us = delay_us;
  recorder_->record(event);
}

uint64_t InstrumentedExecutor::now_steady_ns() {
  const auto now = std::chrono::steady_clock::now().time_since_epoch();
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(now).count());
}

#else

InstrumentedExecutor::InstrumentedExecutor(
    Mode mode, size_t number_of_threads, bool yield_before_execute,
    std::chrono::nanoseconds next_exec_timeout)
    : mode_(mode),
      number_of_threads_(number_of_threads),
      yield_before_execute_(yield_before_execute),
      next_exec_timeout_(next_exec_timeout) {}

void InstrumentedExecutor::set_seed(const Seed& seed) {
  set_schedule(FuzzSchedule::from_seed(seed));
}

void InstrumentedExecutor::set_schedule(const FuzzSchedule& schedule) {
  schedule_ = schedule;
}

void InstrumentedExecutor::set_recorder(std::shared_ptr<Recorder> recorder) {
  (void)recorder;
}

void InstrumentedExecutor::set_replayer(std::shared_ptr<Replayer> replayer) {
  (void)replayer;
}

std::vector<CallbackDispatchEvent> InstrumentedExecutor::callback_events() const {
  return callback_events_;
}

void InstrumentedExecutor::clear_callback_events() { callback_events_.clear(); }

#endif

}  // namespace scarab::fuzzer
