#pragma once

#include <map>
#include <string>
#include <string_view>
#include <vector>

#include "scarab/analyzer/race_candidate.h"

namespace scarab::analyzer {

class SyncChecker {
 public:
  SyncChecker() = default;

  scarab::common::SyncStatus check(const AccessInfo& access,
                                   std::string* protecting_mutex = nullptr) const;
  AccessInfo annotate(const AccessInfo& access) const;

 private:
  struct LockScope {
    std::string mutex_name;
    int start_line = 0;
    int end_line = 0;
    int scope_depth = 0;
  };

  struct FileSyncInfo {
    std::vector<LockScope> lock_scopes;
    bool has_complex_sync_pattern = false;
  };

  const FileSyncInfo& get_file_sync_info(const std::string& source_file) const;
  FileSyncInfo build_file_sync_info(const std::string& source_file) const;
  bool is_atomic_type(std::string_view variable_type) const;
  bool is_within_lock_scope(int access_line, const std::vector<LockScope>& scopes,
                            std::string* protecting_mutex) const;

  mutable std::map<std::string, FileSyncInfo> file_cache_;
};

}  // namespace scarab::analyzer
