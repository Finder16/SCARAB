#include "scarab/common/json_io.h"

#include <fstream>
#include <utility>

namespace scarab::common {

namespace {

void set_error(std::string* error_message, std::string message) {
  if (error_message != nullptr) {
    *error_message = std::move(message);
  }
}

bool parse_stage1_callback(const nlohmann::json& j, const std::string& fallback_source_file,
                           CallbackInfo* callback, std::string* error_message) {
  if (callback == nullptr || !j.is_object()) {
    set_error(error_message, "Invalid callback object in Stage 1 candidates schema");
    return false;
  }

  callback->name = j.value("name", "");
  callback->source_file = j.value("source_file", fallback_source_file);
  callback->line = j.value("line", 0);
  callback->type = j.contains("type") && !j.at("type").is_null()
                       ? j.at("type").get<CallbackType>()
                       : CallbackType::SUBSCRIPTION;
  callback->topic_or_service =
      j.contains("topic_or_service") && !j.at("topic_or_service").is_null()
          ? j.at("topic_or_service").get<std::string>()
          : std::string{};
  callback->callback_group =
      j.contains("callback_group") && !j.at("callback_group").is_null()
          ? j.at("callback_group").get<std::string>()
          : std::string{"default"};
  callback->group_type = j.contains("group_type") && !j.at("group_type").is_null()
                             ? j.at("group_type").get<CallbackGroupType>()
                             : CallbackGroupType::DEFAULT;
  return true;
}

bool parse_stage1_candidate(const nlohmann::json& j, RaceCandidate* candidate,
                            std::string* error_message) {
  if (candidate == nullptr || !j.is_object()) {
    set_error(error_message, "Invalid candidate object in Stage 1 candidates schema");
    return false;
  }

  candidate->id = j.value("id", "");
  candidate->priority = j.value("priority", 0);
  candidate->node_class = j.value("node_class", "");
  candidate->sync_status =
      j.contains("sync_status") && !j.at("sync_status").is_null()
          ? j.at("sync_status").get<SyncStatus>()
          : SyncStatus::UNKNOWN;

  const std::string source_file = j.value("source_file", "");
  if (j.contains("callback_a")) {
    if (!parse_stage1_callback(j.at("callback_a"), source_file, &candidate->callback_a,
                               error_message)) {
      return false;
    }
  }
  if (j.contains("callback_b")) {
    if (!parse_stage1_callback(j.at("callback_b"), source_file, &candidate->callback_b,
                               error_message)) {
      return false;
    }
  }

  if (j.contains("shared_variable") && j.at("shared_variable").is_object()) {
    const auto& shared = j.at("shared_variable");
    candidate->shared_variable = shared.value("name", "");
    candidate->variable_type = shared.value("type", "");
    if (shared.contains("access_a") && !shared.at("access_a").is_null()) {
      candidate->access_a = shared.at("access_a").get<AccessType>();
    }
    if (shared.contains("access_b") && !shared.at("access_b").is_null()) {
      candidate->access_b = shared.at("access_b").get<AccessType>();
    }
    candidate->line_a = shared.value("line_a", 0);
    candidate->line_b = shared.value("line_b", 0);
  } else {
    // Legacy format where fields are flattened directly on candidate.
    candidate->shared_variable = j.value("shared_variable", "");
    candidate->variable_type = j.value("variable_type", "");
    if (j.contains("access_a") && !j.at("access_a").is_null()) {
      candidate->access_a = j.at("access_a").get<AccessType>();
    }
    if (j.contains("access_b") && !j.at("access_b").is_null()) {
      candidate->access_b = j.at("access_b").get<AccessType>();
    }
    candidate->line_a = j.value("line_a", 0);
    candidate->line_b = j.value("line_b", 0);
  }
  return true;
}

bool parse_any_candidate(const nlohmann::json& j, RaceCandidate* candidate,
                         std::string* error_message) {
  if (candidate == nullptr) {
    set_error(error_message, "Candidate output pointer is null");
    return false;
  }

  try {
    *candidate = j.get<RaceCandidate>();
    return true;
  } catch (...) {
    // Fall through and try Stage 1 schema.
  }

  try {
    return parse_stage1_candidate(j, candidate, error_message);
  } catch (const std::exception& e) {
    set_error(error_message, std::string("Failed to parse candidate: ") + e.what());
    return false;
  }
}

}  // namespace

NLOHMANN_JSON_SERIALIZE_ENUM(CallbackType, {
    {CallbackType::SUBSCRIPTION, "SUBSCRIPTION"},
    {CallbackType::TIMER, "TIMER"},
    {CallbackType::SERVICE, "SERVICE"},
    {CallbackType::ACTION, "ACTION"},
    {CallbackType::LIFECYCLE, "LIFECYCLE"},
})

NLOHMANN_JSON_SERIALIZE_ENUM(CallbackGroupType, {
    {CallbackGroupType::MUTUALLY_EXCLUSIVE, "MUTUALLY_EXCLUSIVE"},
    {CallbackGroupType::REENTRANT, "REENTRANT"},
    {CallbackGroupType::DEFAULT, "DEFAULT"},
})

NLOHMANN_JSON_SERIALIZE_ENUM(AccessType, {
    {AccessType::READ, "READ"},
    {AccessType::WRITE, "WRITE"},
    {AccessType::READ_WRITE, "READ_WRITE"},
})

NLOHMANN_JSON_SERIALIZE_ENUM(SyncStatus, {
    {SyncStatus::PROTECTED, "PROTECTED"},
    {SyncStatus::UNKNOWN, "UNKNOWN"},
    {SyncStatus::UNPROTECTED, "UNPROTECTED"},
})

void to_json(nlohmann::json& j, const CallbackInfo& info) {
  j = nlohmann::json{
      {"name", info.name},
      {"source_file", info.source_file},
      {"line", info.line},
      {"type", info.type},
      {"topic_or_service", info.topic_or_service},
      {"callback_group", info.callback_group},
      {"group_type", info.group_type},
  };
}

void from_json(const nlohmann::json& j, CallbackInfo& info) {
  j.at("name").get_to(info.name);
  j.at("source_file").get_to(info.source_file);
  j.at("line").get_to(info.line);
  j.at("type").get_to(info.type);
  j.at("topic_or_service").get_to(info.topic_or_service);
  j.at("callback_group").get_to(info.callback_group);
  j.at("group_type").get_to(info.group_type);
}

void to_json(nlohmann::json& j, const AccessInfo& info) {
  j = nlohmann::json{
      {"variable_name", info.variable_name},
      {"variable_type", info.variable_type},
      {"access_type", info.access_type},
      {"source_file", info.source_file},
      {"line", info.line},
      {"sync_status", info.sync_status},
      {"protecting_mutex", info.protecting_mutex},
  };
}

void from_json(const nlohmann::json& j, AccessInfo& info) {
  j.at("variable_name").get_to(info.variable_name);
  j.at("variable_type").get_to(info.variable_type);
  j.at("access_type").get_to(info.access_type);
  j.at("source_file").get_to(info.source_file);
  j.at("line").get_to(info.line);
  j.at("sync_status").get_to(info.sync_status);
  j.at("protecting_mutex").get_to(info.protecting_mutex);
}

void to_json(nlohmann::json& j, const RaceCandidate& candidate) {
  j = nlohmann::json{
      {"id", candidate.id},
      {"priority", candidate.priority},
      {"callback_a", candidate.callback_a},
      {"callback_b", candidate.callback_b},
      {"shared_variable", candidate.shared_variable},
      {"variable_type", candidate.variable_type},
      {"access_a", candidate.access_a},
      {"access_b", candidate.access_b},
      {"line_a", candidate.line_a},
      {"line_b", candidate.line_b},
      {"sync_status", candidate.sync_status},
      {"node_class", candidate.node_class},
  };
}

void from_json(const nlohmann::json& j, RaceCandidate& candidate) {
  j.at("id").get_to(candidate.id);
  j.at("priority").get_to(candidate.priority);
  j.at("callback_a").get_to(candidate.callback_a);
  j.at("callback_b").get_to(candidate.callback_b);
  j.at("shared_variable").get_to(candidate.shared_variable);
  j.at("variable_type").get_to(candidate.variable_type);
  j.at("access_a").get_to(candidate.access_a);
  j.at("access_b").get_to(candidate.access_b);
  candidate.line_a = j.value("line_a", 0);
  candidate.line_b = j.value("line_b", 0);
  j.at("sync_status").get_to(candidate.sync_status);
  j.at("node_class").get_to(candidate.node_class);
}

std::string serialize_race_candidates(const std::vector<RaceCandidate>& candidates) {
  return nlohmann::json(candidates).dump(2);
}

std::vector<RaceCandidate> deserialize_race_candidates(const std::string& payload) {
  return nlohmann::json::parse(payload).get<std::vector<RaceCandidate>>();
}

bool load_race_candidates_from_file(const std::string& path,
                                    std::vector<RaceCandidate>* candidates,
                                    std::string* error_message) {
  if (candidates == nullptr) {
    set_error(error_message, "Candidates output pointer is null");
    return false;
  }
  candidates->clear();

  std::ifstream input(path);
  if (!input.good()) {
    set_error(error_message, "Unable to open candidates file: " + path);
    return false;
  }

  nlohmann::json root;
  try {
    input >> root;
  } catch (const std::exception& e) {
    set_error(error_message, std::string("Failed to parse candidates JSON: ") + e.what());
    return false;
  }

  const auto parse_array = [&](const nlohmann::json& array_json) -> bool {
    if (!array_json.is_array()) {
      set_error(error_message, "Expected race candidate array in JSON payload");
      return false;
    }

    candidates->reserve(array_json.size());
    for (size_t i = 0; i < array_json.size(); ++i) {
      RaceCandidate candidate;
      std::string candidate_error;
      if (!parse_any_candidate(array_json.at(i), &candidate, &candidate_error)) {
        set_error(error_message, "Failed to parse candidate at index " + std::to_string(i) +
                                     ": " + candidate_error);
        candidates->clear();
        return false;
      }
      candidates->push_back(std::move(candidate));
    }
    return true;
  };

  if (root.is_array()) {
    return parse_array(root);
  }
  if (root.is_object()) {
    if (root.contains("race_candidates")) {
      return parse_array(root.at("race_candidates"));
    }
    RaceCandidate candidate;
    std::string candidate_error;
    if (!parse_any_candidate(root, &candidate, &candidate_error)) {
      set_error(error_message, candidate_error);
      return false;
    }
    candidates->push_back(std::move(candidate));
    return true;
  }

  set_error(error_message, "Unsupported candidates JSON shape");
  return false;
}

}  // namespace scarab::common
