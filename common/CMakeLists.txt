add_library(scarab_common STATIC
  src/json_io.cpp
)

add_library(scarab::common ALIAS scarab_common)

target_include_directories(scarab_common
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(scarab_common
  PUBLIC
    nlohmann_json::nlohmann_json
)
