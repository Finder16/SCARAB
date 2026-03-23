#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "scarab/common/race_candidate.h"

namespace scarab::fuzzer {

struct SeedHeader {
  uint32_t magic = 0x53434142;  // "SCAB"
  uint16_t version = 1;
  uint32_t candidate_id = 0;
  uint16_t num_schedule_entries = 0;
  uint16_t num_messages = 0;

  bool operator==(const SeedHeader& other) const {
    return magic == other.magic && version == other.version &&
           candidate_id == other.candidate_id &&
           num_schedule_entries == other.num_schedule_entries &&
           num_messages == other.num_messages;
  }
};

struct PreemptionEntry {
  uint16_t access_point_id = 0;
  uint32_t yield_duration_us = 0;

  bool operator==(const PreemptionEntry& other) const {
    return access_point_id == other.access_point_id &&
           yield_duration_us == other.yield_duration_us;
  }
};

struct ScheduleEntry {
  uint16_t callback_id = 0;
  uint8_t thread_id = 0;
  uint32_t delay_us = 0;
  std::vector<PreemptionEntry> preemptions;

  bool operator==(const ScheduleEntry& other) const {
    return callback_id == other.callback_id && thread_id == other.thread_id &&
           delay_us == other.delay_us && preemptions == other.preemptions;
  }
};

struct MessageEntry {
  uint16_t topic_id = 0;
  uint32_t offset_us = 0;
  std::vector<uint8_t> payload;

  bool operator==(const MessageEntry& other) const {
    return topic_id == other.topic_id && offset_us == other.offset_us &&
           payload == other.payload;
  }
};

class Seed {
 public:
  static constexpr uint32_t kMagic = 0x53434142;
  static constexpr uint16_t kVersion = 1;

  Seed() = default;

  static std::optional<Seed> deserialize(const std::vector<uint8_t>& bytes);
  std::vector<uint8_t> serialize() const;

  static std::optional<Seed> create_initial(
      const scarab::common::RaceCandidate& candidate);

  bool validate(std::string* error_message = nullptr) const;
  bool is_valid() const { return validate(nullptr); }

  const SeedHeader& header() const { return header_; }
  SeedHeader& header() { return header_; }

  const std::vector<ScheduleEntry>& schedule_entries() const {
    return schedule_entries_;
  }
  std::vector<ScheduleEntry>& schedule_entries() { return schedule_entries_; }

  const std::vector<MessageEntry>& messages() const { return messages_; }
  std::vector<MessageEntry>& messages() { return messages_; }

  bool operator==(const Seed& other) const {
    return header_ == other.header_ &&
           schedule_entries_ == other.schedule_entries_ &&
           messages_ == other.messages_;
  }

  static std::optional<uint32_t> candidate_id_from_string(
      const std::string& candidate_id_text);

 private:
  static bool validate_header(const SeedHeader& header,
                              std::string* error_message);

  SeedHeader header_;
  std::vector<ScheduleEntry> schedule_entries_;
  std::vector<MessageEntry> messages_;
};

}  // namespace scarab::fuzzer
