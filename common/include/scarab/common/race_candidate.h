#pragma once

#include <string>

namespace scarab::common {

enum class CallbackType {
  SUBSCRIPTION,
  TIMER,
  SERVICE,
  ACTION,
  LIFECYCLE,
};

enum class CallbackGroupType {
  MUTUALLY_EXCLUSIVE,
  REENTRANT,
  DEFAULT,
};

struct CallbackInfo {
  std::string name;
  std::string source_file;
  int line = 0;
  CallbackType type = CallbackType::SUBSCRIPTION;
  std::string topic_or_service;
  std::string callback_group;
  CallbackGroupType group_type = CallbackGroupType::DEFAULT;
};

enum class AccessType {
  READ,
  WRITE,
  READ_WRITE,
};

enum class SyncStatus {
  PROTECTED,
  UNKNOWN,
  UNPROTECTED,
};

struct AccessInfo {
  std::string variable_name;
  std::string variable_type;
  AccessType access_type = AccessType::READ;
  std::string source_file;
  int line = 0;
  SyncStatus sync_status = SyncStatus::UNKNOWN;
  std::string protecting_mutex;
};

struct RaceCandidate {
  std::string id;
  int priority = 0;
  CallbackInfo callback_a;
  CallbackInfo callback_b;
  std::string shared_variable;
  std::string variable_type;
  AccessType access_a = AccessType::READ;
  AccessType access_b = AccessType::READ;
  int line_a = 0;  // Source line of access point A
  int line_b = 0;  // Source line of access point B
  SyncStatus sync_status = SyncStatus::UNKNOWN;
  std::string node_class;
};

}  // namespace scarab::common
