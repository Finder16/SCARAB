#include "scarab/analyzer/race_candidate.h"

#include "scarab/analyzer/callback_group_analyzer.h"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <sstream>

namespace scarab::analyzer {

namespace {

std::string to_string(scarab::common::CallbackType value) {
  switch (value) {
    case scarab::common::CallbackType::SUBSCRIPTION:
      return "SUBSCRIPTION";
    case scarab::common::CallbackType::TIMER:
      return "TIMER";
    case scarab::common::CallbackType::SERVICE:
      return "SERVICE";
    case scarab::common::CallbackType::ACTION:
      return "ACTION";
    case scarab::common::CallbackType::LIFECYCLE:
      return "LIFECYCLE";
  }
  return "SUBSCRIPTION";
}

std::string to_string(scarab::common::CallbackGroupType value) {
  switch (value) {
    case scarab::common::CallbackGroupType::MUTUALLY_EXCLUSIVE:
      return "MUTUALLY_EXCLUSIVE";
    case scarab::common::CallbackGroupType::REENTRANT:
      return "REENTRANT";
    case scarab::common::CallbackGroupType::DEFAULT:
      return "DEFAULT";
  }
  return "DEFAULT";
}

std::string to_string(scarab::common::AccessType value) {
  switch (value) {
    case scarab::common::AccessType::READ:
      return "READ";
    case scarab::common::AccessType::WRITE:
      return "WRITE";
    case scarab::common::AccessType::READ_WRITE:
      return "READ_WRITE";
  }
  return "READ";
}

std::string to_string(scarab::common::SyncStatus value) {
  switch (value) {
    case scarab::common::SyncStatus::PROTECTED:
      return "PROTECTED";
    case scarab::common::SyncStatus::UNKNOWN:
      return "UNKNOWN";
    case scarab::common::SyncStatus::UNPROTECTED:
      return "UNPROTECTED";
  }
  return "UNKNOWN";
}

nlohmann::json callback_to_schema_json(const CallbackInfo& callback) {
  return {
      {"name", callback.name},
      {"type", to_string(callback.type)},
      {"topic_or_service", callback.topic_or_service.empty() ? nlohmann::json(nullptr)
                                                             : nlohmann::json(callback.topic_or_service)},
      {"callback_group", callback.callback_group},
      {"group_type", to_string(callback.group_type)},
      {"line", callback.line},
  };
}

std::string now_iso8601_utc() {
  const auto now = std::chrono::system_clock::now();
  const std::time_t now_time = std::chrono::system_clock::to_time_t(now);
  std::tm tm_utc{};
#if defined(_WIN32)
  gmtime_s(&tm_utc, &now_time);
#else
  gmtime_r(&now_time, &tm_utc);
#endif
  std::ostringstream oss;
  oss << std::put_time(&tm_utc, "%Y-%m-%dT%H:%M:%SZ");
  return oss.str();
}

}  // namespace

bool RaceCandidateGenerator::is_write_access(scarab::common::AccessType access_type) {
  return access_type == scarab::common::AccessType::WRITE ||
         access_type == scarab::common::AccessType::READ_WRITE;
}

bool RaceCandidateGenerator::is_conflicting_pair(scarab::common::AccessType access_a,
                                                 scarab::common::AccessType access_b) {
  return is_write_access(access_a) || is_write_access(access_b);
}

scarab::common::SyncStatus RaceCandidateGenerator::merge_sync_status(const AccessInfo& access_a,
                                                                     const AccessInfo& access_b) {
  if (access_a.sync_status == scarab::common::SyncStatus::PROTECTED &&
      access_b.sync_status == scarab::common::SyncStatus::PROTECTED) {
    if (!access_a.protecting_mutex.empty() && access_a.protecting_mutex == access_b.protecting_mutex) {
      return scarab::common::SyncStatus::PROTECTED;
    }
    return scarab::common::SyncStatus::UNKNOWN;
  }

  if (access_a.sync_status == scarab::common::SyncStatus::UNKNOWN ||
      access_b.sync_status == scarab::common::SyncStatus::UNKNOWN) {
    return scarab::common::SyncStatus::UNKNOWN;
  }

  if (access_a.sync_status == scarab::common::SyncStatus::PROTECTED ||
      access_b.sync_status == scarab::common::SyncStatus::PROTECTED) {
    return scarab::common::SyncStatus::UNKNOWN;
  }

  return scarab::common::SyncStatus::UNPROTECTED;
}

int RaceCandidateGenerator::compute_priority(const CallbackInfo& callback_a,
                                             const CallbackInfo& callback_b,
                                             const AccessInfo& access_a,
                                             const AccessInfo& access_b,
                                             scarab::common::SyncStatus sync_status) {
  int score = 0;

  if (is_write_access(access_a.access_type) && is_write_access(access_b.access_type)) {
    score += 5;
  } else {
    score += 3;
  }

  switch (sync_status) {
    case scarab::common::SyncStatus::UNPROTECTED:
      score += 4;
      break;
    case scarab::common::SyncStatus::UNKNOWN:
      score += 2;
      break;
    case scarab::common::SyncStatus::PROTECTED:
      break;
  }

  if (callback_a.group_type == scarab::common::CallbackGroupType::DEFAULT ||
      callback_b.group_type == scarab::common::CallbackGroupType::DEFAULT) {
    score += 1;
  }

  return std::clamp(score, 0, 10);
}

std::string RaceCandidateGenerator::make_candidate_id(int index) {
  std::ostringstream oss;
  oss << "RC-" << std::setw(3) << std::setfill('0') << index;
  return oss.str();
}

std::vector<RaceCandidate> RaceCandidateGenerator::generate(
    const std::vector<CallbackInfo>& callbacks,
    const std::map<std::string, std::vector<AccessInfo>>& access_map,
    const CallbackGroupAnalyzer& group_analyzer) const {
  std::vector<RaceCandidate> candidates;
  if (callbacks.size() < 2) {
    return candidates;
  }

  int next_id = 1;
  for (size_t i = 0; i < callbacks.size(); ++i) {
    for (size_t j = i + 1; j < callbacks.size(); ++j) {
      const auto& callback_a = callbacks[i];
      const auto& callback_b = callbacks[j];

      if (!group_analyzer.can_execute_concurrently(callback_a, callback_b)) {
        continue;
      }

      const auto found_a = access_map.find(callback_a.name);
      const auto found_b = access_map.find(callback_b.name);
      if (found_a == access_map.end() || found_b == access_map.end()) {
        continue;
      }

      for (const auto& access_a : found_a->second) {
        for (const auto& access_b : found_b->second) {
          if (access_a.variable_name.empty() || access_a.variable_name != access_b.variable_name) {
            continue;
          }
          if (!is_conflicting_pair(access_a.access_type, access_b.access_type)) {
            continue;
          }

          const auto merged_sync = merge_sync_status(access_a, access_b);
          if (merged_sync == scarab::common::SyncStatus::PROTECTED) {
            continue;
          }

          RaceCandidate candidate;
          candidate.id = make_candidate_id(next_id++);
          candidate.priority =
              compute_priority(callback_a, callback_b, access_a, access_b, merged_sync);
          candidate.callback_a = callback_a;
          candidate.callback_b = callback_b;
          candidate.shared_variable = access_a.variable_name;
          candidate.variable_type =
              !access_a.variable_type.empty() ? access_a.variable_type : access_b.variable_type;
          candidate.access_a = access_a.access_type;
          candidate.access_b = access_b.access_type;
          candidate.line_a = access_a.line;
          candidate.line_b = access_b.line;
          candidate.sync_status = merged_sync;
          candidate.node_class = "unknown";
          candidates.push_back(std::move(candidate));
        }
      }
    }
  }

  return candidates;
}

bool RaceCandidateGenerator::write_json(const std::vector<RaceCandidate>& candidates,
                                        const std::string& output_path,
                                        const std::string& project_name,
                                        int callbacks_found) const {
  nlohmann::json root;
  root["$schema"] = "scarab-candidates-v1";
  root["project"] = project_name;
  root["analysis_date"] = now_iso8601_utc();
  root["analyzer_version"] = "0.1.0";
  root["nodes_analyzed"] = 0;
  root["callbacks_found"] = callbacks_found;
  root["race_candidates"] = nlohmann::json::array();

  for (const auto& candidate : candidates) {
    nlohmann::json candidate_json;
    candidate_json["id"] = candidate.id;
    candidate_json["priority"] = candidate.priority;
    candidate_json["node_class"] = candidate.node_class;
    candidate_json["source_file"] = candidate.callback_a.source_file;
    candidate_json["callback_a"] = callback_to_schema_json(candidate.callback_a);
    candidate_json["callback_b"] = callback_to_schema_json(candidate.callback_b);
    candidate_json["shared_variable"] = {
        {"name", candidate.shared_variable},
        {"type", candidate.variable_type},
        {"access_a", to_string(candidate.access_a)},
        {"access_b", to_string(candidate.access_b)},
        {"line_a", candidate.line_a},
        {"line_b", candidate.line_b},
    };
    candidate_json["sync_status"] = to_string(candidate.sync_status);
    candidate_json["protecting_mutex"] = nullptr;
    root["race_candidates"].push_back(std::move(candidate_json));
  }

  std::ofstream out(output_path);
  if (!out.good()) {
    return false;
  }
  out << root.dump(2);
  return out.good();
}

}  // namespace scarab::analyzer
