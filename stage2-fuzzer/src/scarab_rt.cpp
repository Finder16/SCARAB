#include "scarab/fuzzer/scarab_rt.h"

#include <atomic>
#include <chrono>
#include <shared_mutex>
#include <thread>

// SCARAB_RT_NOSANITIZE suppresses TSan instrumentation on the annotated
// function body itself.  Note: it does NOT propagate to callees (e.g. STL
// move-assign), which is why we also need proper synchronisation below.
#define SCARAB_RT_NOSANITIZE __attribute__((no_sanitize("thread")))

namespace scarab::fuzzer {

// ── Process-global runtime state ──────────────────────────────────────────────
// Protected by g_rw_mutex (std::shared_mutex):
//   - install() / uninstall() take a unique (exclusive) lock.
//   - before_access() / after_access() take a shared (reader) lock, snapshot
//     the data they need, then release the lock before any blocking work
//     (e.g. sleep_for).  This eliminates the data race on g_schedule that TSan
//     previously reported through STL internals (hashtable _M_move_assign).
//
// g_mode is still atomic so the fast-path DISABLED check avoids the lock
// entirely.

namespace {

std::shared_mutex g_rw_mutex;
std::atomic<ScarabRuntime::Mode> g_mode{ScarabRuntime::Mode::DISABLED};
FuzzSchedule g_schedule;
std::shared_ptr<Recorder> g_recorder;
std::shared_ptr<Replayer> g_replayer;
std::atomic<uint64_t> g_hook_call_count{0};

// Per-thread id inherited from InstrumentedExecutor::current_thread_id_ (TLS).
// The rt hooks don't have direct access to the executor's TLS, so we use a
// separate TLS that the executor or test harness may set via the install path.
thread_local uint16_t t_thread_id = 0;

SCARAB_RT_NOSANITIZE
uint64_t now_steady_ns() {
  const auto now = std::chrono::steady_clock::now().time_since_epoch();
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(now).count());
}

}  // namespace

SCARAB_RT_NOSANITIZE
void ScarabRuntime::install(Mode mode, const FuzzSchedule& schedule,
                            std::shared_ptr<Recorder> recorder,
                            std::shared_ptr<Replayer> replayer) {
  std::unique_lock lock(g_rw_mutex);
  g_schedule = schedule;
  g_recorder = std::move(recorder);
  g_replayer = std::move(replayer);
  g_hook_call_count.store(0, std::memory_order_relaxed);
  // Publish the mode last so concurrent hook calls see fully initialised state.
  g_mode.store(mode, std::memory_order_release);
}

SCARAB_RT_NOSANITIZE
void ScarabRuntime::uninstall() {
  std::unique_lock lock(g_rw_mutex);
  // Set DISABLED under the exclusive lock so no reader can observe DISABLED
  // while we are still mutating g_schedule / g_recorder / g_replayer.
  g_mode.store(Mode::DISABLED, std::memory_order_release);
  g_schedule = FuzzSchedule{};
  g_recorder.reset();
  g_replayer.reset();
}

SCARAB_RT_NOSANITIZE
bool ScarabRuntime::is_installed() {
  return g_mode.load(std::memory_order_acquire) != Mode::DISABLED;
}

SCARAB_RT_NOSANITIZE
ScarabRuntime::Mode ScarabRuntime::current_mode() {
  return g_mode.load(std::memory_order_acquire);
}

SCARAB_RT_NOSANITIZE
const FuzzSchedule* ScarabRuntime::current_schedule() {
  if (!is_installed()) return nullptr;
  return &g_schedule;
}

SCARAB_RT_NOSANITIZE
uint64_t ScarabRuntime::hook_call_count() {
  return g_hook_call_count.load(std::memory_order_relaxed);
}

SCARAB_RT_NOSANITIZE
void ScarabRuntime::before_access(void* /*addr*/, int access_type,
                                  int source_line) {
  // Fast path: atomic check without any lock.
  const Mode mode = g_mode.load(std::memory_order_acquire);
  if (mode == Mode::DISABLED) return;

  g_hook_call_count.fetch_add(1, std::memory_order_relaxed);

  // Snapshot all data we need under a shared (reader) lock, then release
  // the lock before doing any blocking work (sleep / replay wait).
  uint32_t delay_us = 0;
  std::shared_ptr<Recorder> recorder_snap;
  std::shared_ptr<Replayer> replayer_snap;

  {
    std::shared_lock lock(g_rw_mutex);
    // Re-check: uninstall() may have set DISABLED while we waited for the lock.
    const Mode mode2 = g_mode.load(std::memory_order_acquire);
    if (mode2 == Mode::DISABLED) return;

    if (mode2 == Mode::FUZZ || mode2 == Mode::RECORD) {
      delay_us = g_schedule.access_delay_for(source_line);
    }
    if (mode2 == Mode::RECORD) {
      recorder_snap = g_recorder;
    }
    if (mode2 == Mode::REPLAY) {
      replayer_snap = g_replayer;
    }
  }  // shared lock released here — safe to block below

  if (delay_us > 0) {
    std::this_thread::sleep_for(std::chrono::microseconds(delay_us));
  }

  if (recorder_snap) {
    Event event;
    event.timestamp_ns = now_steady_ns();
    event.event_type = EventType::ACCESS_BEFORE;
    event.thread_id = t_thread_id;
    event.callback_id = static_cast<uint32_t>(source_line);
    event.delay_duration_us = static_cast<uint32_t>(access_type);
    recorder_snap->record(event);
  }

  if (replayer_snap) {
    // In REPLAY mode, wait for the next ACCESS_BEFORE event to appear.
    // This serialises access-point-level interleaving deterministically.
    replayer_snap->next_decision(EventType::ACCESS_BEFORE, t_thread_id);
  }
}

SCARAB_RT_NOSANITIZE
void ScarabRuntime::after_access(void* /*addr*/, int access_type,
                                 int source_line) {
  const Mode mode = g_mode.load(std::memory_order_acquire);
  if (mode == Mode::DISABLED) return;

  g_hook_call_count.fetch_add(1, std::memory_order_relaxed);

  std::shared_ptr<Recorder> recorder_snap;
  std::shared_ptr<Replayer> replayer_snap;

  {
    std::shared_lock lock(g_rw_mutex);
    const Mode mode2 = g_mode.load(std::memory_order_acquire);
    if (mode2 == Mode::DISABLED) return;

    if (mode2 == Mode::RECORD) {
      recorder_snap = g_recorder;
    }
    if (mode2 == Mode::REPLAY) {
      replayer_snap = g_replayer;
    }
  }

  if (recorder_snap) {
    Event event;
    event.timestamp_ns = now_steady_ns();
    event.event_type = EventType::ACCESS_AFTER;
    event.thread_id = t_thread_id;
    event.callback_id = static_cast<uint32_t>(source_line);
    event.delay_duration_us = static_cast<uint32_t>(access_type);
    recorder_snap->record(event);
  }

  if (replayer_snap) {
    replayer_snap->next_decision(EventType::ACCESS_AFTER, t_thread_id);
  }
}

SCARAB_RT_NOSANITIZE
void ScarabRuntime::record_access_event(EventType type, int access_type,
                                        int source_line) {
  // Legacy path — kept for API compatibility but the hot-path hooks now
  // snapshot g_recorder under the shared lock and call recorder->record()
  // directly.  This method is only reached from test code.
  std::shared_lock lock(g_rw_mutex);
  if (!g_recorder) return;

  Event event;
  event.timestamp_ns = now_steady_ns();
  event.event_type = type;
  event.thread_id = t_thread_id;
  event.callback_id = static_cast<uint32_t>(source_line);
  event.delay_duration_us = static_cast<uint32_t>(access_type);
  g_recorder->record(event);
}

}  // namespace scarab::fuzzer

// ── C-linkage hook implementations ────────────────────────────────────────────

extern "C" {

SCARAB_RT_NOSANITIZE
void __scarab_before_access(void* addr, int access_type, int source_line) {
  scarab::fuzzer::ScarabRuntime::before_access(addr, access_type, source_line);
}

SCARAB_RT_NOSANITIZE
void __scarab_after_access(void* addr, int access_type, int source_line) {
  scarab::fuzzer::ScarabRuntime::after_access(addr, access_type, source_line);
}

}
