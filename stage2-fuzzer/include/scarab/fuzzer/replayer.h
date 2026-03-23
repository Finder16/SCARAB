#pragma once

#include "scarab/fuzzer/event.h"

#include <cstddef>
#include <optional>
#include <string>

namespace scarab::fuzzer {

class Replayer {
 public:
  /// Load and parse a binary event-log file produced by Recorder.
  /// Throws std::runtime_error on I/O failure or magic/version mismatch.
  explicit Replayer(const std::string& event_log_path);

  /// Return and consume the next event whose event_type matches
  /// @p expected_type.  Events of other types between the cursor and the
  /// match are skipped (consumed silently).
  /// Returns std::nullopt if no matching event remains.
  /// @p thread_id is reserved for Phase 2 per-thread matching.
  std::optional<Event> next_decision(EventType expected_type,
                                     uint16_t thread_id = 0);

  /// Peek at the next event of the given type WITHOUT consuming it.
  /// Returns std::nullopt if the remaining events contain no match.
  std::optional<Event> peek_next(EventType expected_type) const;

  bool is_finished() const { return cursor_ >= event_log_.events.size(); }

  const EventLog& event_log() const { return event_log_; }
  size_t cursor() const { return cursor_; }

 private:
  EventLog event_log_;
  size_t cursor_ = 0;
};

}  // namespace scarab::fuzzer
