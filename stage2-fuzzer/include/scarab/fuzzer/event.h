#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace scarab::fuzzer {

enum class EventType : uint8_t {
  CALLBACK_DISPATCH = 0x01,
  CALLBACK_START    = 0x02,
  CALLBACK_END      = 0x03,
  ACCESS_BEFORE     = 0x10,  // Shared variable access about to happen
  ACCESS_AFTER      = 0x11,  // Shared variable access completed
  YIELD             = 0x20,
  DELAY             = 0x21,
  // MESSAGE (0x30–0x31) and MUTEX (0x40–0x41) reserved for future use.
};

struct Event {
  uint64_t timestamp_ns = 0;
  EventType event_type  = EventType::CALLBACK_DISPATCH;
  uint16_t thread_id    = 0;
  uint32_t callback_id  = 0;

  // Payload — interpretation depends on event_type.
  // YIELD / DELAY    → duration in microseconds.
  // ACCESS_*         → access_type (0=READ, 1=WRITE, 2=READ_WRITE).
  //                    callback_id field carries source_line for ACCESS events.
  // CALLBACK_*       → unused (0).
  uint32_t delay_duration_us = 0;

  bool operator==(const Event& o) const {
    return timestamp_ns == o.timestamp_ns && event_type == o.event_type &&
           thread_id == o.thread_id && callback_id == o.callback_id &&
           delay_duration_us == o.delay_duration_us;
  }
};

struct EventLog {
  uint64_t start_timestamp_ns = 0;
  std::vector<Event> events;

  size_t event_count() const { return events.size(); }
};

// Binary file format constants.
// Header: [4B magic][2B version][4B event_count] = 10 bytes.
// Event:  [8B timestamp][1B type][2B thread_id][4B callback_id][opt 4B payload].
//   CALLBACK_* events: 15 bytes (no payload).
//   YIELD/DELAY:       19 bytes (4B duration_us payload).
constexpr uint8_t  kEventFileMagic[4] = {'S', 'C', 'R', 'B'};
constexpr uint16_t kEventFileVersion   = 1;
constexpr size_t   kEventFileHeaderSize = 10;  // 4 + 2 + 4

inline bool event_has_duration_payload(EventType type) {
  return type == EventType::YIELD || type == EventType::DELAY ||
         type == EventType::ACCESS_BEFORE || type == EventType::ACCESS_AFTER;
}

}  // namespace scarab::fuzzer
