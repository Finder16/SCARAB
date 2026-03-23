#pragma once

#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "scarab/common/race_candidate.h"

namespace scarab::common {

void to_json(nlohmann::json& j, const CallbackInfo& info);
void from_json(const nlohmann::json& j, CallbackInfo& info);

void to_json(nlohmann::json& j, const AccessInfo& info);
void from_json(const nlohmann::json& j, AccessInfo& info);

void to_json(nlohmann::json& j, const RaceCandidate& candidate);
void from_json(const nlohmann::json& j, RaceCandidate& candidate);

std::string serialize_race_candidates(const std::vector<RaceCandidate>& candidates);
std::vector<RaceCandidate> deserialize_race_candidates(const std::string& payload);

bool load_race_candidates_from_file(const std::string& path,
                                    std::vector<RaceCandidate>* candidates,
                                    std::string* error_message = nullptr);

}  // namespace scarab::common
