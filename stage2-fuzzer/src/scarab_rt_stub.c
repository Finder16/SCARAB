/// Minimal no-op stubs for __scarab_before_access / __scarab_after_access.
///
/// When nav2 (or any target) is compiled with the SCARAB instrumentation pass,
/// the pass inserts calls to these symbols.  This stub library provides default
/// no-op implementations so that the target can link and run independently.
///
/// At runtime, when launched via the SCARAB E2E runner, LD_PRELOAD (or the
/// fact that the runner's process already defines these symbols as strong) will
/// override these stubs with the real ScarabRuntime implementations.

__attribute__((weak))
void __scarab_before_access(void* addr, int access_type, int source_line) {
  (void)addr; (void)access_type; (void)source_line;
}

__attribute__((weak))
void __scarab_after_access(void* addr, int access_type, int source_line) {
  (void)addr; (void)access_type; (void)source_line;
}
