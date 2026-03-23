#include "scarab/fuzzer/recorder.h"

#include <cstring>

namespace scarab::fuzzer {

static void write_bytes(std::ofstream& out, const void* data, size_t size) {
  out.write(static_cast<const char*>(data), static_cast<std::streamsize>(size));
}

static void serialize_event(std::ofstream& out, const Event& event) {
  write_bytes(out, &event.timestamp_ns, 8);
  const uint8_t type = static_cast<uint8_t>(event.event_type);
  write_bytes(out, &type, 1);
  write_bytes(out, &event.thread_id, 2);
  write_bytes(out, &event.callback_id, 4);
  if (event_has_duration_payload(event.event_type)) {
    write_bytes(out, &event.delay_duration_us, 4);
  }
}

Recorder::Recorder(const std::string& output_path) : output_path_(output_path) {}

Recorder::~Recorder() {
  if (running_.load()) {
    stop();
  }
}

void Recorder::record(const Event& event) {
  {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    if (!running_.load(std::memory_order_relaxed)) return;
    event_queue_.push_back(event);
  }
  writer_cv_.notify_one();
}

void Recorder::flush() {
  std::deque<Event> local;
  {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    local.swap(event_queue_);
  }
  for (const auto& event : local) {
    serialize_event(output_, event);
    events_written_.fetch_add(1, std::memory_order_relaxed);
  }
  if (!local.empty()) {
    output_.flush();
  }
}

void Recorder::start() {
  if (running_.exchange(true)) return;  // already started

  output_.open(output_path_, std::ios::binary | std::ios::trunc);
  events_written_.store(0, std::memory_order_relaxed);
  write_header();

  writer_thread_ = std::thread([this]() { writer_loop(); });
}

void Recorder::stop() {
  if (!running_.exchange(false)) return;  // already stopped
  writer_cv_.notify_all();
  if (writer_thread_.joinable()) {
    writer_thread_.join();
  }
  // Final drain — the writer thread also does a final flush before exiting,
  // but record() may have been called between the writer's last iteration and
  // the join completing.
  flush();
  update_header_event_count();
  output_.close();
}

void Recorder::writer_loop() {
  while (running_.load()) {
    {
      std::unique_lock<std::mutex> lock(writer_mutex_);
      writer_cv_.wait_for(lock, std::chrono::milliseconds(100));
    }
    flush();
  }
  // Final flush after the loop exits.
  flush();
}

void Recorder::write_header() {
  write_bytes(output_, kEventFileMagic, 4);
  const uint16_t version = kEventFileVersion;
  write_bytes(output_, &version, 2);
  const uint32_t placeholder = 0;
  write_bytes(output_, &placeholder, 4);
  output_.flush();
}

void Recorder::update_header_event_count() {
  output_.seekp(6);  // offset past magic(4) + version(2)
  const uint32_t count = events_written_.load(std::memory_order_relaxed);
  write_bytes(output_, &count, 4);
  output_.flush();
}

bool write_event_log_to_file(const EventLog& log, const std::string& path) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out.good()) return false;

  // Header: [4B magic][2B version][4B event_count]
  write_bytes(out, kEventFileMagic, 4);
  const uint16_t version = kEventFileVersion;
  write_bytes(out, &version, 2);
  const uint32_t count = static_cast<uint32_t>(log.events.size());
  write_bytes(out, &count, 4);

  // Events
  for (const auto& event : log.events) {
    serialize_event(out, event);
  }

  return out.good();
}

}  // namespace scarab::fuzzer
