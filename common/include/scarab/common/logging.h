#pragma once

#include <iostream>
#include <string_view>

namespace scarab::common {

inline void log_info(std::string_view message) {
  std::cout << "[INFO] " << message << '\n';
}

inline void log_error(std::string_view message) {
  std::cerr << "[ERROR] " << message << '\n';
}

}  // namespace scarab::common
