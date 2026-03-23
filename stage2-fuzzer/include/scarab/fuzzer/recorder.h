#pragma once

#include "scarab/fuzzer/event.h"

#include <atomic>
#include <condition_variable>
#include <deque>
#include <fstream>
#include <mutex>
#include <string>
#include <thread>

namespace scarab::fuzzer {

class Recorder {
 public:
  explicit Recorder(const std::string& output_path);
  ~Recorder();

  Recorder(const Recorder&) = delete;
  Recorder& operator=(const Recorder&) = delete;

  /// Enqueue an event.  Thread-safe — called from executor callback threads.
  void record(const Event& event);

  /// Drain the internal queue and write all pending events to the file.
  /// Called automatically by the background writer; may also be called
  /// manually (e.g. in tests).
  void flush();

  /// Start the background writer thread (flushes every ~100 ms).
  void start();

  /// Stop the background writer, do a final flush, and update the file header
  /// with the total event count.
  void stop();

  const std::string& output_path() const { return output_path_; }
  uint32_t events_written() const {
    return events_written_.load(std::memory_order_relaxed);
  }

 private:
  void writer_loop();
  void write_header();
  void update_header_event_count();

  std::string output_path_;
  std::ofstream output_;

  // TODO: Replace with per-thread lock-free SPSC queue for lower overhead.
  std::mutex queue_mutex_;
  std::deque<Event> event_queue_;
  // Dedicated mutex for condition-variable sleeping; keeps writer waiting
  // from holding queue_mutex_ and avoids self-deadlock on re-entrant record().
  std::mutex writer_mutex_;

  std::thread writer_thread_;
  std::atomic<bool> running_{false};
  std::condition_variable writer_cv_;

  std::atomic<uint32_t> events_written_{0};
};

/// Write an EventLog to a binary file in the same format produced by Recorder.
/// Useful for persisting minimized / modified event logs.
/// Returns false on I/O failure.
bool write_event_log_to_file(const EventLog& log, const std::string& path);

}  // namespace scarab::fuzzer
