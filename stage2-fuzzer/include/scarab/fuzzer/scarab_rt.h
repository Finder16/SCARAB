#pragma once

#include <cstdint>
#include <memory>
#include <unordered_map>

#include "scarab/fuzzer/event.h"
#include "scarab/fuzzer/instrumented_executor.h"
#include "scarab/fuzzer/recorder.h"
#include "scarab/fuzzer/replayer.h"

namespace scarab::fuzzer {

/// Runtime state for the SCARAB instrumentation hooks.
///
/// The LLVM instrumentation pass inserts calls to __scarab_before_access /
/// __scarab_after_access around shared variable accesses identified by Stage 1.
/// These C-linkage hooks delegate to a process-global ScarabRuntime instance
/// that applies schedule-driven delays, records ACCESS events, or replays them.
///
/// Typical lifecycle:
///   1. FuzzerEngine (or test harness) calls ScarabRuntime::install() with the
///      current schedule and mode before spinning the executor.
///   2. Instrumented code hits hooks during callback execution.
///   3. After execution, call ScarabRuntime::uninstall() to detach.
class ScarabRuntime {
 public:
  enum class Mode { DISABLED, FUZZ, RECORD, REPLAY };

  /// Install the global runtime with the given schedule and mode.
  /// Thread-safe: uses a shared_mutex to synchronise with concurrent hook
  /// calls.  Ideally called before executor.spin() starts.
  static void install(Mode mode, const FuzzSchedule& schedule,
                      std::shared_ptr<Recorder> recorder = nullptr,
                      std::shared_ptr<Replayer> replayer = nullptr);

  /// Uninstall the global runtime, reverting hooks to no-ops.
  static void uninstall();

  /// Query whether the runtime is currently installed.
  static bool is_installed();

  /// Return the current mode.
  static Mode current_mode();

  /// Return the current schedule (read-only).  Only valid while installed.
  static const FuzzSchedule* current_schedule();

  /// Number of hook invocations since last install().
  static uint64_t hook_call_count();

  /// Called by __scarab_before_access.
  static void before_access(void* addr, int access_type, int source_line);

  /// Called by __scarab_after_access.
  static void after_access(void* addr, int access_type, int source_line);

 private:
  ScarabRuntime() = default;

  static void record_access_event(EventType type, int access_type,
                                  int source_line);
};

}  // namespace scarab::fuzzer

// ── C-linkage hooks inserted by the LLVM instrumentation pass ──────────────
// These are the actual symbols that appear in instrumented IR.  They must be
// callable from any translation unit without C++ name mangling.
extern "C" {

/// Called immediately before a shared variable access.
/// @param addr          Address of the accessed variable (for identity).
/// @param access_type   0=READ, 1=WRITE, 2=READ_WRITE.
/// @param source_line   Source line number of the access (from Stage 1).
void __scarab_before_access(void* addr, int access_type, int source_line);

/// Called immediately after a shared variable access.
void __scarab_after_access(void* addr, int access_type, int source_line);

}
