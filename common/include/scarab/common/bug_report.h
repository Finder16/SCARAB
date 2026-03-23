#pragma once

#include <string>

namespace scarab::common {

struct BugReport {
  std::string id;
  std::string candidate_id;
  std::string summary;
};

}  // namespace scarab::common
