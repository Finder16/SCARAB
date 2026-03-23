#include "scarab/fuzzer/replayer.h"

#include <cstring>
#include <fstream>
#include <stdexcept>

namespace scarab::fuzzer {

namespace {

bool read_bytes(std::ifstream& in, void* data, size_t size) {
  return static_cast<bool>(
      in.read(static_cast<char*>(data), static_cast<std::streamsize>(size)));
}

std::optional<Event> deserialize_event(std::ifstream& in) {
  Event event;
  if (!read_bytes(in, &event.timestamp_ns, 8)) return std::nullopt;
  uint8_t type = 0;
  if (!read_bytes(in, &type, 1)) return std::nullopt;
  event.event_type = static_cast<EventType>(type);
  if (!read_bytes(in, &event.thread_id, 2)) return std::nullopt;
  if (!read_bytes(in, &event.callback_id, 4)) return std::nullopt;
  if (event_has_duration_payload(event.event_type)) {
    if (!read_bytes(in, &event.delay_duration_us, 4)) return std::nullopt;
  }
  return event;
}

}  // namespace

Replayer::Replayer(const std::string& event_log_path) {
  std::ifstream in(event_log_path, std::ios::binary);
  if (!in.good()) {
    throw std::runtime_error("Replayer: cannot open event log: " +
                             event_log_path);
  }

  // Read and validate header.
  uint8_t magic[4] = {};
  if (!read_bytes(in, magic, 4)) {
    throw std::runtime_error("Replayer: truncated header (magic)");
  }
  if (std::memcmp(magic, kEventFileMagic, 4) != 0) {
    throw std::runtime_error("Replayer: invalid magic in event log");
  }

  uint16_t version = 0;
  if (!read_bytes(in, &version, 2)) {
    throw std::runtime_error("Replayer: truncated header (version)");
  }
  if (version != kEventFileVersion) {
    throw std::runtime_error(
        "Replayer: unsupported event log version " + std::to_string(version));
  }

  uint32_t event_count = 0;
  if (!read_bytes(in, &event_count, 4)) {
    throw std::runtime_error("Replayer: truncated header (event_count)");
  }

  // Read events.
  event_log_.events.reserve(event_count);
  for (uint32_t i = 0; i < event_count; ++i) {
    auto event = deserialize_event(in);
    if (!event.has_value()) {
      throw std::runtime_error(
          "Replayer: truncated event at index " + std::to_string(i));
    }
    if (i == 0) {
      event_log_.start_timestamp_ns = event->timestamp_ns;
    }
    event_log_.events.push_back(*event);
  }
}

std::optional<Event> Replayer::next_decision(EventType expected_type,
                                             uint16_t /*thread_id*/) {
  while (cursor_ < event_log_.events.size()) {
    const auto& event = event_log_.events[cursor_];
    ++cursor_;
    if (event.event_type == expected_type) {
      return event;
    }
  }
  return std::nullopt;
}

std::optional<Event> Replayer::peek_next(EventType expected_type) const {
  for (size_t i = cursor_; i < event_log_.events.size(); ++i) {
    if (event_log_.events[i].event_type == expected_type) {
      return event_log_.events[i];
    }
  }
  return std::nullopt;
}

}  // namespace scarab::fuzzer
