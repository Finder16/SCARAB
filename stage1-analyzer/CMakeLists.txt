add_library(scarab_stage1_analyzer STATIC
  src/analyzer_pipeline.cpp
  src/callback_extractor.cpp
  src/access_extractor.cpp
  src/sync_checker.cpp
  src/callback_group_analyzer.cpp
  src/alias_tracker.cpp
  src/race_candidate.cpp
)

target_include_directories(scarab_stage1_analyzer
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

set(_scarab_llvm_versions 18 17 16 15 14)
set(_scarab_clang_include_hints "")
set(_scarab_llvm_include_hints "")
set(_scarab_clang_lib_hints "")
foreach(version IN LISTS _scarab_llvm_versions)
  list(APPEND _scarab_clang_include_hints
    /usr/lib/llvm-${version}/include
    /tmp/clang${version}-root/usr/lib/llvm-${version}/include
    /tmp/clang18-root/usr/lib/llvm-${version}/include
  )
  list(APPEND _scarab_llvm_include_hints
    /usr/lib/llvm-${version}/include
    /usr/include/llvm-${version}
    /tmp/clang${version}-root/usr/lib/llvm-${version}/include
    /tmp/clang18-root/usr/lib/llvm-${version}/include
  )
  list(APPEND _scarab_clang_lib_hints
    /usr/lib/llvm-${version}/lib
    /tmp/clang${version}-root/usr/lib/llvm-${version}/lib
    /tmp/clang18-root/usr/lib/llvm-${version}/lib
  )
endforeach()
list(APPEND _scarab_clang_lib_hints
  /usr/lib/x86_64-linux-gnu
  /lib/x86_64-linux-gnu
)

if(NOT SCARAB_CLANG_INCLUDE_DIR)
  find_path(SCARAB_CLANG_INCLUDE_DIR
    clang/AST/RecursiveASTVisitor.h
    HINTS
      ${_scarab_clang_include_hints}
  )
endif()

if(NOT SCARAB_LLVM_INCLUDE_DIR)
  find_path(SCARAB_LLVM_INCLUDE_DIR
    llvm/ADT/BitmaskEnum.h
    HINTS
      ${_scarab_llvm_include_hints}
  )
endif()

if(NOT SCARAB_LLVM_INCLUDE_DIR AND SCARAB_CLANG_INCLUDE_DIR)
  if(EXISTS "${SCARAB_CLANG_INCLUDE_DIR}/llvm/ADT/BitmaskEnum.h")
    set(SCARAB_LLVM_INCLUDE_DIR "${SCARAB_CLANG_INCLUDE_DIR}")
  endif()
endif()

if(NOT SCARAB_CLANG_CPP_LIB)
  find_library(SCARAB_CLANG_CPP_LIB
    NAMES
      clang-cpp
      clang-cpp.so.18.1
      clang-cpp.so.18
      clang-cpp.so.17
      clang-cpp.so.16
      clang-cpp.so.15
      clang-cpp.so.14
      libclang-cpp.so.18.1
      libclang-cpp.so.18
      libclang-cpp.so.17
      libclang-cpp.so.16
      libclang-cpp.so.15
      libclang-cpp.so.14
    HINTS
      ${_scarab_clang_lib_hints}
  )
endif()

if(NOT SCARAB_CLANG_CPP_LIB)
  find_file(SCARAB_CLANG_CPP_LIB
    NAMES
      libclang-cpp.so.18.1
      libclang-cpp.so.18
      libclang-cpp.so.17
      libclang-cpp.so.16
      libclang-cpp.so.15
      libclang-cpp.so.14
    HINTS
      ${_scarab_clang_lib_hints}
  )
endif()

if(NOT SCARAB_LLVM_LIB)
  find_library(SCARAB_LLVM_LIB
    NAMES
      LLVM
      LLVM-18
      LLVM-17
      LLVM-16
      LLVM-15
      LLVM-14
      LLVM.so.18.1
      libLLVM.so.18.1
      libLLVM.so.18
      libLLVM.so.17
      libLLVM.so.16
      libLLVM.so.15
      libLLVM.so.14
    HINTS
      ${_scarab_clang_lib_hints}
  )
endif()

if(NOT SCARAB_LLVM_LIB)
  find_file(SCARAB_LLVM_LIB
    NAMES
      libLLVM.so.18.1
      libLLVM.so.18
      libLLVM.so.17
      libLLVM.so.16
      libLLVM.so.15
      libLLVM.so.14
    HINTS
      ${_scarab_clang_lib_hints}
  )
endif()

if(SCARAB_CLANG_INCLUDE_DIR AND SCARAB_LLVM_INCLUDE_DIR AND SCARAB_CLANG_CPP_LIB)
  target_compile_definitions(scarab_stage1_analyzer PUBLIC SCARAB_HAS_CLANG_TOOLING=1)
  target_include_directories(scarab_stage1_analyzer PUBLIC
    ${SCARAB_CLANG_INCLUDE_DIR}
    ${SCARAB_LLVM_INCLUDE_DIR}
  )
  target_link_libraries(scarab_stage1_analyzer PUBLIC ${SCARAB_CLANG_CPP_LIB})
  if(SCARAB_LLVM_LIB)
    target_link_libraries(scarab_stage1_analyzer PUBLIC ${SCARAB_LLVM_LIB})
  endif()
else()
  message(STATUS "Clang LibTooling disabled (missing Clang include, LLVM include, or libclang-cpp). "
                 "CallbackExtractor fallback parser enabled.")
  target_compile_definitions(scarab_stage1_analyzer PUBLIC SCARAB_HAS_CLANG_TOOLING=0)
endif()

target_link_libraries(scarab_stage1_analyzer
  PUBLIC
    scarab_common
)

add_executable(scarab-analyzer
  src/main.cpp
)

target_link_libraries(scarab-analyzer
  PRIVATE
    scarab_stage1_analyzer
)

if(SCARAB_BUILD_TESTS)
  add_subdirectory(tests)
endif()

# ── LLVM Instrumentation Pass (libscarab_pass.so) ─────────────────────────────
# Build with: cmake -DSCARAB_BUILD_LLVM_PASS=ON -DLLVM_DIR=...
# Usage:      clang -fpass-plugin=libscarab_pass.so \
#               -mllvm -scarab-access-points=access_points.json ...
if(SCARAB_BUILD_LLVM_PASS)
  find_package(LLVM REQUIRED CONFIG)

  message(STATUS "LLVM version: ${LLVM_VERSION_MAJOR}.${LLVM_VERSION_MINOR}")
  message(STATUS "LLVM include dirs: ${LLVM_INCLUDE_DIRS}")

  add_library(scarab_pass MODULE
    src/scarab_pass.cpp
  )

  target_include_directories(scarab_pass PRIVATE
    ${LLVM_INCLUDE_DIRS}
  )

  target_compile_definitions(scarab_pass PRIVATE
    ${LLVM_DEFINITIONS}
  )

  # LLVM pass plugins must NOT link against libLLVM — the host (opt/clang)
  # already provides those symbols.  Use LLVM_DEFINITIONS only.
  # The pass .so must NOT be built with sanitizers since it runs inside the
  # compiler process itself (not the target binary).
  set_target_properties(scarab_pass PROPERTIES
    PREFIX ""              # produce "scarab_pass.so" not "libscarab_pass.so"
    SUFFIX ".so"
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
  )
  # Strip any sanitizer flags from the pass target — they would introduce
  # undefined symbols (__tsan_init etc.) into the plugin .so.
  get_target_property(_pass_flags scarab_pass COMPILE_OPTIONS)
  if(_pass_flags)
    list(FILTER _pass_flags EXCLUDE REGEX "-fsanitize=")
    set_target_properties(scarab_pass PROPERTIES COMPILE_OPTIONS "${_pass_flags}")
  endif()
  target_compile_options(scarab_pass PRIVATE
    -fno-sanitize=all
  )
  target_link_options(scarab_pass PRIVATE
    -fno-sanitize=all
  )

  # On Linux, undefined symbols are resolved from the host at runtime.
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_options(scarab_pass PRIVATE
      "LINKER:--no-undefined-version"
    )
    set_target_properties(scarab_pass PROPERTIES
      LINK_FLAGS "-Wl,-undefined,dynamic_lookup"
    )
  endif()

  # On macOS, use -undefined dynamic_lookup.
  if(APPLE)
    set_target_properties(scarab_pass PROPERTIES
      LINK_FLAGS "-undefined dynamic_lookup"
    )
  endif()
endif()
