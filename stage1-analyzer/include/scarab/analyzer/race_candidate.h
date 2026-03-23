#pragma once

#include <map>
#include <string>
#include <vector>

#include "scarab/common/race_candidate.h"

namespace scarab::analyzer {

using CallbackInfo = scarab::common::CallbackInfo;
using AccessInfo = scarab::common::AccessInfo;
using RaceCandidate = scarab::common::RaceCandidate;

class CallbackGroupAnalyzer;

class RaceCandidateGenerator {
 public:
  std::vector<RaceCandidate> generate(
      const std::vector<CallbackInfo>& callbacks,
      const std::map<std::string, std::vector<AccessInfo>>& access_map,
      const CallbackGroupAnalyzer& group_analyzer) const;

  bool write_json(const std::vector<RaceCandidate>& candidates, const std::string& output_path,
                  const std::string& project_name = "unknown",
                  int callbacks_found = 0) const;

 private:
  static bool is_write_access(scarab::common::AccessType access_type);
  static bool is_conflicting_pair(scarab::common::AccessType access_a,
                                  scarab::common::AccessType access_b);
  static scarab::common::SyncStatus merge_sync_status(const AccessInfo& access_a,
                                                      const AccessInfo& access_b);
  static int compute_priority(const CallbackInfo& callback_a, const CallbackInfo& callback_b,
                              const AccessInfo& access_a, const AccessInfo& access_b,
                              scarab::common::SyncStatus sync_status);
  static std::string make_candidate_id(int index);
};

}  // namespace scarab::analyzer
