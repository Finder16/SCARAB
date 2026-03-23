if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  cmake_minimum_required(VERSION 3.22)
  project(scarab_stage2_fuzzer LANGUAGES CXX)

  set(CMAKE_CXX_STANDARD 17)
  set(CMAKE_CXX_STANDARD_REQUIRED ON)
  set(CMAKE_CXX_EXTENSIONS OFF)

  option(SCARAB_BUILD_TESTS "Build SCARAB stage2 tests" OFF)
endif()

set(SCARAB_STAGE2_AMENT_BUILD OFF)
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  find_package(ament_cmake QUIET)
  if(ament_cmake_FOUND)
    set(SCARAB_STAGE2_AMENT_BUILD ON)
  endif()
endif()

set(SCARAB_STAGE2_HAS_AMENT_TARGET_DEPS OFF)
find_package(ament_cmake_target_dependencies QUIET)
if(COMMAND ament_target_dependencies)
  set(SCARAB_STAGE2_HAS_AMENT_TARGET_DEPS ON)
endif()

if(NOT TARGET scarab_common)
  include(FetchContent)

  find_package(nlohmann_json CONFIG QUIET)
  if(NOT nlohmann_json_FOUND)
    FetchContent_Declare(
      nlohmann_json
      URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
    )
    FetchContent_MakeAvailable(nlohmann_json)
  endif()

  add_library(scarab_common STATIC
    ../common/src/json_io.cpp
  )

  target_include_directories(scarab_common
    PUBLIC
      ${CMAKE_CURRENT_SOURCE_DIR}/../common/include
  )

  target_link_libraries(scarab_common
    PUBLIC
      nlohmann_json::nlohmann_json
  )
endif()

if(SCARAB_STAGE2_HAS_AMENT_TARGET_DEPS)
  find_package(rclcpp REQUIRED)
  find_package(std_msgs REQUIRED)
else()
  find_package(rclcpp QUIET)
  find_package(std_msgs QUIET)
endif()

if(rclcpp_FOUND AND std_msgs_FOUND)
  set(SCARAB_STAGE2_HAVE_ROS2 ON)
else()
  set(SCARAB_STAGE2_HAVE_ROS2 OFF)
endif()

add_library(scarab_stage2_fuzzer STATIC
  src/seed.cpp
  src/mutation.cpp
  src/instrumented_executor.cpp
  src/directed_pct.cpp
  src/message_controller.cpp
  src/recorder.cpp
  src/replayer.cpp
  src/oracle.cpp
  src/dedup.cpp
  src/minimizer.cpp
  src/fuzzer_engine.cpp
  src/scarab_rt.cpp
)

target_include_directories(scarab_stage2_fuzzer
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(scarab_stage2_fuzzer
  scarab_common
)

if(SCARAB_STAGE2_HAVE_ROS2)
  target_compile_definitions(scarab_stage2_fuzzer
    PUBLIC
      SCARAB_FUZZER_HAS_ROS2
  )

  if(SCARAB_STAGE2_HAS_AMENT_TARGET_DEPS)
    ament_target_dependencies(scarab_stage2_fuzzer rclcpp std_msgs)
  elseif(TARGET rclcpp::rclcpp)
    target_link_libraries(scarab_stage2_fuzzer rclcpp::rclcpp)
    if(TARGET std_msgs::std_msgs__rosidl_generator_cpp)
      target_link_libraries(scarab_stage2_fuzzer
        std_msgs::std_msgs__rosidl_generator_cpp)
    endif()
    if(TARGET std_msgs::std_msgs__rosidl_typesupport_cpp)
      target_link_libraries(scarab_stage2_fuzzer
        std_msgs::std_msgs__rosidl_typesupport_cpp)
    endif()
    if(std_msgs_INCLUDE_DIRS)
      target_include_directories(scarab_stage2_fuzzer PRIVATE ${std_msgs_INCLUDE_DIRS})
    endif()
  endif()
endif()

# ── Stub runtime for instrumented targets ─────────────────────────────────────
# Provides weak no-op definitions of __scarab_before_access / __scarab_after_access.
# Link instrumented targets (e.g. nav2) against this so they can run standalone.
# At runtime under the SCARAB E2E runner, the strong definitions from
# scarab_rt.cpp override these stubs.
add_library(scarab_rt_stub SHARED
  src/scarab_rt_stub.c
)
set_target_properties(scarab_rt_stub PROPERTIES
  SOVERSION 0
  VERSION 0.1.0
)
# The stub must NOT be sanitized — it's a link-time dependency for targets
# that are themselves sanitized.
target_compile_options(scarab_rt_stub PRIVATE -fno-sanitize=all)
target_link_options(scarab_rt_stub PRIVATE -fno-sanitize=all)

add_executable(scarab-fuzzer
  src/main.cpp
)

target_link_libraries(scarab-fuzzer
  PRIVATE
    scarab_stage2_fuzzer
)

if(SCARAB_BUILD_TESTS)
  if(SCARAB_STAGE2_AMENT_BUILD)
    if(BUILD_TESTING)
      add_subdirectory(tests)
    endif()
  else()
    add_subdirectory(tests)
  endif()
endif()

# ── E2E integration runner ────────────────────────────────────────────────────
# Build with: cmake -DSCARAB_BUILD_E2E=ON
# Requires ROS2 and (optionally) -fsanitize=thread support.
option(SCARAB_BUILD_E2E "Build SCARAB end-to-end integration runner" OFF)
option(SCARAB_E2E_ENABLE_TSAN
  "Enable -fsanitize=thread for scarab_e2e_runner when available" ON)

if(SCARAB_BUILD_E2E AND SCARAB_STAGE2_HAVE_ROS2)
  include(CheckCXXSourceCompiles)
  set(_scarab_saved_required_flags "${CMAKE_REQUIRED_FLAGS}")
  set(_scarab_saved_required_link_options "${CMAKE_REQUIRED_LINK_OPTIONS}")
  string(APPEND CMAKE_REQUIRED_FLAGS " -fsanitize=thread")
  list(APPEND CMAKE_REQUIRED_LINK_OPTIONS "-fsanitize=thread")
  check_cxx_source_compiles("int main() { return 0; }" SCARAB_E2E_HAVE_TSAN)
  set(CMAKE_REQUIRED_FLAGS "${_scarab_saved_required_flags}")
  set(CMAKE_REQUIRED_LINK_OPTIONS "${_scarab_saved_required_link_options}")

  add_executable(scarab_e2e_runner
    ${CMAKE_CURRENT_SOURCE_DIR}/../scripts/e2e_runner.cpp
  )

  target_link_libraries(scarab_e2e_runner
    scarab_stage2_fuzzer
  )

  # Ensure __scarab_before_access / __scarab_after_access from scarab_rt.cpp are
  # included by the static linker and exported to the dynamic symbol table.
  # Without this, nav2 shared libraries would call the weak stubs instead.
  target_link_options(scarab_e2e_runner PRIVATE
    -rdynamic                          # export all symbols to dynamic table
    "LINKER:-u,__scarab_before_access" # force inclusion from static archive
    "LINKER:-u,__scarab_after_access"
  )

  if(SCARAB_STAGE2_HAS_AMENT_TARGET_DEPS)
    ament_target_dependencies(scarab_e2e_runner rclcpp std_msgs)
  elseif(TARGET rclcpp::rclcpp)
    target_link_libraries(scarab_e2e_runner rclcpp::rclcpp)
    if(TARGET std_msgs::std_msgs__rosidl_generator_cpp)
      target_link_libraries(scarab_e2e_runner
        std_msgs::std_msgs__rosidl_generator_cpp)
    endif()
    if(TARGET std_msgs::std_msgs__rosidl_typesupport_cpp)
      target_link_libraries(scarab_e2e_runner
        std_msgs::std_msgs__rosidl_typesupport_cpp)
    endif()
    if(std_msgs_INCLUDE_DIRS)
      target_include_directories(scarab_e2e_runner PRIVATE ${std_msgs_INCLUDE_DIRS})
    endif()
  endif()

  set(SCARAB_E2E_HAS_NAV2 OFF)
  find_package(nav2_costmap_2d QUIET)
  find_package(nav2_msgs QUIET)
  find_package(rclcpp_action QUIET)
  find_package(lifecycle_msgs QUIET)
  find_package(nav2_core QUIET)
  find_package(geometry_msgs QUIET)
  find_package(nav_msgs QUIET)
  find_package(tf2_msgs QUIET)
  if(nav2_costmap_2d_FOUND AND nav2_msgs_FOUND)
    set(SCARAB_E2E_HAS_NAV2 ON)
    target_compile_definitions(scarab_e2e_runner PRIVATE SCARAB_E2E_HAS_NAV2)
    if(SCARAB_STAGE2_HAS_AMENT_TARGET_DEPS)
      ament_target_dependencies(scarab_e2e_runner nav2_costmap_2d nav2_msgs)
    endif()
  endif()

  # nav2_controller target support
  set(SCARAB_E2E_HAS_NAV2_CONTROLLER OFF)
  find_package(nav2_controller QUIET)
  if(nav2_controller_FOUND AND nav2_core_FOUND AND nav2_msgs_FOUND AND
     lifecycle_msgs_FOUND AND rclcpp_action_FOUND AND geometry_msgs_FOUND AND
     nav_msgs_FOUND AND tf2_msgs_FOUND)
    set(SCARAB_E2E_HAS_NAV2_CONTROLLER ON)
    target_compile_definitions(scarab_e2e_runner PRIVATE SCARAB_HAS_NAV2_CONTROLLER)
    if(SCARAB_STAGE2_HAS_AMENT_TARGET_DEPS)
      ament_target_dependencies(
        scarab_e2e_runner
        nav2_controller
        nav2_core
        nav2_msgs
        lifecycle_msgs
        rclcpp_action
        geometry_msgs
        nav_msgs
        tf2_msgs
      )
    endif()
  endif()

  # nav2_planner target support
  set(SCARAB_E2E_HAS_NAV2_PLANNER OFF)
  find_package(nav2_planner QUIET)
  if(nav2_planner_FOUND AND nav2_core_FOUND AND nav2_msgs_FOUND AND
     lifecycle_msgs_FOUND AND rclcpp_action_FOUND AND geometry_msgs_FOUND AND
     nav_msgs_FOUND AND tf2_msgs_FOUND)
    set(SCARAB_E2E_HAS_NAV2_PLANNER ON)
    target_compile_definitions(scarab_e2e_runner PRIVATE SCARAB_HAS_NAV2_PLANNER)
    if(SCARAB_STAGE2_HAS_AMENT_TARGET_DEPS)
      ament_target_dependencies(
        scarab_e2e_runner
        nav2_planner
        nav2_core
        nav2_msgs
        lifecycle_msgs
        rclcpp_action
        geometry_msgs
        nav_msgs
        tf2_msgs
      )
    endif()
  endif()

  # nav2_behaviors target support
  set(SCARAB_E2E_HAS_NAV2_BEHAVIORS OFF)
  find_package(nav2_behaviors QUIET)
  if(nav2_behaviors_FOUND AND nav2_msgs_FOUND AND lifecycle_msgs_FOUND AND geometry_msgs_FOUND)
    set(SCARAB_E2E_HAS_NAV2_BEHAVIORS ON)
    target_compile_definitions(scarab_e2e_runner PRIVATE SCARAB_HAS_NAV2_BEHAVIORS)
    if(SCARAB_STAGE2_HAS_AMENT_TARGET_DEPS)
      ament_target_dependencies(
        scarab_e2e_runner
        nav2_behaviors
        nav2_msgs
        lifecycle_msgs
        geometry_msgs
      )
    endif()
  endif()

  # nav2_lifecycle_manager target support
  set(SCARAB_E2E_HAS_NAV2_LIFECYCLE_MANAGER OFF)
  find_package(nav2_lifecycle_manager QUIET)
  find_package(std_srvs QUIET)
  if(nav2_lifecycle_manager_FOUND AND nav2_msgs_FOUND AND std_srvs_FOUND)
    set(SCARAB_E2E_HAS_NAV2_LIFECYCLE_MANAGER ON)
    target_compile_definitions(
      scarab_e2e_runner PRIVATE SCARAB_HAS_NAV2_LIFECYCLE_MANAGER)
    if(SCARAB_STAGE2_HAS_AMENT_TARGET_DEPS)
      ament_target_dependencies(
        scarab_e2e_runner
        nav2_lifecycle_manager
        nav2_msgs
        std_srvs
      )
    endif()
  endif()

  # nav2 costmap filter target support (binary/keepout/speed filters)
  set(SCARAB_E2E_HAS_NAV2_FILTERS OFF)
  find_package(nav2_util QUIET)
  find_package(tf2_ros QUIET)
  if(nav2_costmap_2d_FOUND AND nav2_msgs_FOUND AND nav2_util_FOUND AND
     nav_msgs_FOUND AND tf2_ros_FOUND AND lifecycle_msgs_FOUND)
    set(SCARAB_E2E_HAS_NAV2_FILTERS ON)
    target_compile_definitions(
      scarab_e2e_runner PRIVATE SCARAB_E2E_HAS_NAV2_FILTERS)
    if(SCARAB_STAGE2_HAS_AMENT_TARGET_DEPS)
      ament_target_dependencies(
        scarab_e2e_runner
        nav2_costmap_2d
        nav2_msgs
        nav2_util
        nav_msgs
        tf2_ros
        lifecycle_msgs
      )
    endif()
  endif()

  # ros2_control (controller_manager) target support
  set(SCARAB_E2E_HAS_ROS2_CONTROL OFF)
  find_package(controller_manager QUIET)
  find_package(controller_manager_msgs QUIET)
  if(controller_manager_FOUND AND controller_manager_msgs_FOUND)
    set(SCARAB_E2E_HAS_ROS2_CONTROL ON)
    target_compile_definitions(
      scarab_e2e_runner PRIVATE SCARAB_HAS_ROS2_CONTROL)
    if(SCARAB_STAGE2_HAS_AMENT_TARGET_DEPS)
      ament_target_dependencies(
        scarab_e2e_runner
        controller_manager
        controller_manager_msgs
      )
    endif()
  endif()

  # MoveIt2 (moveit_ros_planning / rdf_loader) target support
  set(SCARAB_E2E_HAS_MOVEIT2 OFF)
  find_package(moveit_ros_planning QUIET)
  if(moveit_ros_planning_FOUND)
    set(SCARAB_E2E_HAS_MOVEIT2 ON)
    target_compile_definitions(
      scarab_e2e_runner PRIVATE SCARAB_HAS_MOVEIT2)
    if(SCARAB_STAGE2_HAS_AMENT_TARGET_DEPS)
      ament_target_dependencies(
        scarab_e2e_runner
        moveit_ros_planning
      )
    endif()
  endif()

  if(SCARAB_E2E_HAVE_TSAN AND SCARAB_E2E_ENABLE_TSAN)
    target_compile_options(scarab_e2e_runner PRIVATE
      -fsanitize=thread
      -g
      -fno-omit-frame-pointer
    )
    target_link_options(scarab_e2e_runner PRIVATE -fsanitize=thread)
    message(STATUS "scarab_e2e_runner: TSan enabled")
  elseif(NOT SCARAB_E2E_ENABLE_TSAN)
    message(STATUS "scarab_e2e_runner: TSan explicitly disabled")
  else()
    message(STATUS "scarab_e2e_runner: TSan not available — data races will not be detected at runtime")
  endif()
endif()

if(SCARAB_STAGE2_AMENT_BUILD)
  install(TARGETS scarab_stage2_fuzzer scarab-fuzzer
    DESTINATION lib/${PROJECT_NAME}
  )

  install(DIRECTORY include/
    DESTINATION include
  )

  install(DIRECTORY ../common/include/scarab/common
    DESTINATION include/scarab
  )

  ament_export_include_directories(include)
  ament_package()
endif()
