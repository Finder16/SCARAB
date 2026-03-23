cmake_minimum_required(VERSION 3.22)
project(scarab LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(SCARAB_BUILD_TESTS "Build SCARAB unit tests" OFF)
option(SCARAB_BUILD_LLVM_PASS "Build SCARAB LLVM instrumentation pass (libscarab_pass.so)" OFF)

include(FetchContent)

set(SCARAB_FETCHCONTENT_TIMESTAMP_ARGS)
if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.24)
  list(APPEND SCARAB_FETCHCONTENT_TIMESTAMP_ARGS DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
endif()

find_package(nlohmann_json CONFIG QUIET)
if(NOT nlohmann_json_FOUND)
  FetchContent_Declare(
    nlohmann_json
    URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
    ${SCARAB_FETCHCONTENT_TIMESTAMP_ARGS}
  )
  FetchContent_MakeAvailable(nlohmann_json)
endif()

if(SCARAB_BUILD_TESTS)
  enable_testing()

  find_package(GTest CONFIG QUIET)
  if(NOT GTest_FOUND)
    FetchContent_Declare(
      googletest
      URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
      ${SCARAB_FETCHCONTENT_TIMESTAMP_ARGS}
    )
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)
  endif()
endif()

add_subdirectory(common)
add_subdirectory(stage1-analyzer)
add_subdirectory(stage2-fuzzer)
