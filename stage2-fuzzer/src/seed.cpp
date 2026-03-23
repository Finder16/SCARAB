#include "scarab/fuzzer/seed.h"

#include "scarab/common/logging.h"

#include <algorithm>
#include <cctype>
#include <limits>
#include <string>

namespace scarab::fuzzer {

namespace {

void set_error(std::string* error_message, const std::string& message) {
  if (error_message != nullptr) {
    *error_message = message;
  }
}

void write_u8(std::vector<uint8_t>* buffer, uint8_t value) {
  buffer->push_back(value);
}

void write_u16(std::vector<uint8_t>* buffer, uint16_t value) {
  buffer->push_back(static_cast<uint8_t>(value & 0xffU));
  buffer->push_back(static_cast<uint8_t>((value >> 8U) & 0xffU));
}

void write_u32(std::vector<uint8_t>* buffer, uint32_t value) {
  buffer->push_back(static_cast<uint8_t>(value & 0xffU));
  buffer->push_back(static_cast<uint8_t>((value >> 8U) & 0xffU));
  buffer->push_back(static_cast<uint8_t>((value >> 16U) & 0xffU));
  buffer->push_back(static_cast<uint8_t>((value >> 24U) & 0xffU));
}

bool read_u8(const std::vector<uint8_t>& buffer, size_t* offset, uint8_t* value) {
  if (*offset + 1 > buffer.size()) {
    return false;
  }
  *value = buffer[*offset];
  *offset += 1;
  return true;
}

bool read_u16(const std::vector<uint8_t>& buffer, size_t* offset, uint16_t* value) {
  if (*offset + 2 > buffer.size()) {
    return false;
  }
  *value = static_cast<uint16_t>(buffer[*offset]) |
           (static_cast<uint16_t>(buffer[*offset + 1]) << 8U);
  *offset += 2;
  return true;
}

bool read_u32(const std::vector<uint8_t>& buffer, size_t* offset, uint32_t* value) {
  if (*offset + 4 > buffer.size()) {
    return false;
  }
  *value = static_cast<uint32_t>(buffer[*offset]) |
           (static_cast<uint32_t>(buffer[*offset + 1]) << 8U) |
           (static_cast<uint32_t>(buffer[*offset + 2]) << 16U) |
           (static_cast<uint32_t>(buffer[*offset + 3]) << 24U);
  *offset += 4;
  return true;
}

bool read_bytes(const std::vector<uint8_t>& buffer, size_t* offset, size_t size,
                std::vector<uint8_t>* bytes) {
  if (*offset + size > buffer.size()) {
    return false;
  }
  bytes->assign(buffer.begin() + static_cast<std::ptrdiff_t>(*offset),
                buffer.begin() + static_cast<std::ptrdiff_t>(*offset + size));
  *offset += size;
  return true;
}

}  // namespace

bool Seed::validate_header(const SeedHeader& header, std::string* error_message) {
  if (header.magic != kMagic) {
    set_error(error_message, "Invalid seed magic");
    return false;
  }
  if (header.version != kVersion) {
    set_error(error_message, "Unsupported seed version");
    return false;
  }
  if (header.candidate_id == 0) {
    set_error(error_message, "Candidate ID must be positive");
    return false;
  }
  return true;
}

bool Seed::validate(std::string* error_message) const {
  if (!validate_header(header_, error_message)) {
    return false;
  }

  if (header_.num_schedule_entries != schedule_entries_.size()) {
    set_error(error_message, "Header schedule count mismatch");
    return false;
  }
  if (header_.num_messages != messages_.size()) {
    set_error(error_message, "Header message count mismatch");
    return false;
  }

  if (header_.num_schedule_entries == 0) {
    set_error(error_message, "Seed must have at least one schedule entry");
    return false;
  }

  for (const auto& schedule : schedule_entries_) {
    if (schedule.preemptions.size() > std::numeric_limits<uint8_t>::max()) {
      set_error(error_message, "Too many preemptions in schedule entry");
      return false;
    }
  }

  for (const auto& message : messages_) {
    if (message.payload.size() > std::numeric_limits<uint16_t>::max()) {
      set_error(error_message, "Message payload too large");
      return false;
    }
  }

  return true;
}

std::vector<uint8_t> Seed::serialize() const {
  SeedHeader header = header_;
  header.magic = kMagic;
  header.version = kVersion;

  if (schedule_entries_.size() > std::numeric_limits<uint16_t>::max() ||
      messages_.size() > std::numeric_limits<uint16_t>::max()) {
    scarab::common::log_error("Seed serialize failed: count overflow");
    return {};
  }

  header.num_schedule_entries = static_cast<uint16_t>(schedule_entries_.size());
  header.num_messages = static_cast<uint16_t>(messages_.size());

  Seed normalized = *this;
  normalized.header_ = header;
  std::string error_message;
  if (!normalized.validate(&error_message)) {
    scarab::common::log_error("Seed serialize failed: " + error_message);
    return {};
  }

  std::vector<uint8_t> buffer;
  buffer.reserve(64);
  write_u32(&buffer, header.magic);
  write_u16(&buffer, header.version);
  write_u32(&buffer, header.candidate_id);
  write_u16(&buffer, header.num_schedule_entries);
  write_u16(&buffer, header.num_messages);

  for (const auto& schedule : schedule_entries_) {
    write_u16(&buffer, schedule.callback_id);
    write_u8(&buffer, schedule.thread_id);
    write_u32(&buffer, schedule.delay_us);
    write_u8(&buffer, static_cast<uint8_t>(schedule.preemptions.size()));
    for (const auto& preemption : schedule.preemptions) {
      write_u16(&buffer, preemption.access_point_id);
      write_u32(&buffer, preemption.yield_duration_us);
    }
  }

  for (const auto& message : messages_) {
    write_u16(&buffer, message.topic_id);
    write_u32(&buffer, message.offset_us);
    write_u16(&buffer, static_cast<uint16_t>(message.payload.size()));
    buffer.insert(buffer.end(), message.payload.begin(), message.payload.end());
  }

  return buffer;
}

std::optional<Seed> Seed::deserialize(const std::vector<uint8_t>& bytes) {
  Seed seed;
  size_t offset = 0;
  if (!read_u32(bytes, &offset, &seed.header_.magic) ||
      !read_u16(bytes, &offset, &seed.header_.version) ||
      !read_u32(bytes, &offset, &seed.header_.candidate_id) ||
      !read_u16(bytes, &offset, &seed.header_.num_schedule_entries) ||
      !read_u16(bytes, &offset, &seed.header_.num_messages)) {
    scarab::common::log_error("Seed deserialize failed: truncated header");
    return std::nullopt;
  }

  std::string error_message;
  if (!validate_header(seed.header_, &error_message)) {
    scarab::common::log_error("Seed deserialize failed: " + error_message);
    return std::nullopt;
  }

  seed.schedule_entries_.reserve(seed.header_.num_schedule_entries);
  for (uint16_t i = 0; i < seed.header_.num_schedule_entries; ++i) {
    ScheduleEntry entry;
    uint8_t num_preemptions = 0;
    if (!read_u16(bytes, &offset, &entry.callback_id) ||
        !read_u8(bytes, &offset, &entry.thread_id) ||
        !read_u32(bytes, &offset, &entry.delay_us) ||
        !read_u8(bytes, &offset, &num_preemptions)) {
      scarab::common::log_error("Seed deserialize failed: truncated schedule entry");
      return std::nullopt;
    }

    entry.preemptions.reserve(num_preemptions);
    for (uint8_t p = 0; p < num_preemptions; ++p) {
      PreemptionEntry preemption;
      if (!read_u16(bytes, &offset, &preemption.access_point_id) ||
          !read_u32(bytes, &offset, &preemption.yield_duration_us)) {
        scarab::common::log_error(
            "Seed deserialize failed: truncated preemption entry");
        return std::nullopt;
      }
      entry.preemptions.push_back(preemption);
    }

    seed.schedule_entries_.push_back(std::move(entry));
  }

  seed.messages_.reserve(seed.header_.num_messages);
  for (uint16_t i = 0; i < seed.header_.num_messages; ++i) {
    MessageEntry entry;
    uint16_t payload_len = 0;
    if (!read_u16(bytes, &offset, &entry.topic_id) ||
        !read_u32(bytes, &offset, &entry.offset_us) ||
        !read_u16(bytes, &offset, &payload_len) ||
        !read_bytes(bytes, &offset, payload_len, &entry.payload)) {
      scarab::common::log_error("Seed deserialize failed: truncated message entry");
      return std::nullopt;
    }
    seed.messages_.push_back(std::move(entry));
  }

  if (offset != bytes.size()) {
    scarab::common::log_error("Seed deserialize failed: trailing bytes");
    return std::nullopt;
  }

  if (!seed.validate(&error_message)) {
    scarab::common::log_error("Seed deserialize failed: " + error_message);
    return std::nullopt;
  }

  return seed;
}

std::optional<uint32_t> Seed::candidate_id_from_string(
    const std::string& candidate_id_text) {
  if (candidate_id_text.empty()) {
    return std::nullopt;
  }

  std::string digits;
  if (candidate_id_text.size() > 3 &&
      (candidate_id_text[0] == 'R' || candidate_id_text[0] == 'r') &&
      (candidate_id_text[1] == 'C' || candidate_id_text[1] == 'c') &&
      candidate_id_text[2] == '-') {
    digits = candidate_id_text.substr(3);
  } else if (std::all_of(candidate_id_text.begin(), candidate_id_text.end(),
                         [](unsigned char c) { return std::isdigit(c) != 0; })) {
    digits = candidate_id_text;
  } else {
    return std::nullopt;
  }

  if (digits.empty() ||
      !std::all_of(digits.begin(), digits.end(),
                   [](unsigned char c) { return std::isdigit(c) != 0; })) {
    return std::nullopt;
  }

  try {
    const auto parsed = std::stoull(digits);
    if (parsed == 0 || parsed > std::numeric_limits<uint32_t>::max()) {
      return std::nullopt;
    }
    return static_cast<uint32_t>(parsed);
  } catch (...) {
    return std::nullopt;
  }
}

std::optional<Seed> Seed::create_initial(
    const scarab::common::RaceCandidate& candidate) {
  const auto candidate_id = candidate_id_from_string(candidate.id);
  if (!candidate_id.has_value()) {
    scarab::common::log_error("Seed create_initial failed: invalid candidate id \"" +
                              candidate.id + "\"");
    return std::nullopt;
  }

  Seed seed;
  seed.header_.magic = kMagic;
  seed.header_.version = kVersion;
  seed.header_.candidate_id = *candidate_id;

  ScheduleEntry callback_a;
  callback_a.callback_id = 0;
  callback_a.thread_id = 0;
  callback_a.delay_us = 0;

  ScheduleEntry callback_b;
  callback_b.callback_id = 1;
  callback_b.thread_id = 1;
  callback_b.delay_us = 0;

  seed.schedule_entries_ = {callback_a, callback_b};
  seed.messages_.clear();
  seed.header_.num_schedule_entries =
      static_cast<uint16_t>(seed.schedule_entries_.size());
  seed.header_.num_messages = 0;

  std::string error_message;
  if (!seed.validate(&error_message)) {
    scarab::common::log_error("Seed create_initial failed: " + error_message);
    return std::nullopt;
  }

  return seed;
}

}  // namespace scarab::fuzzer
