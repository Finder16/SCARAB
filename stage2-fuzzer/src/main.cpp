#include "scarab/common/logging.h"
#include "scarab/fuzzer/fuzzer_engine.h"

#include <string>

namespace {

bool parse_int_arg(const std::string& value, int* out) {
  if (out == nullptr) {
    return false;
  }
  try {
    *out = std::stoi(value);
    return true;
  } catch (...) {
    return false;
  }
}

}  // namespace

int main(int argc, char** argv) {
  scarab::fuzzer::FuzzerConfig config;

  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "--candidates" && i + 1 < argc) {
      config.candidates_path = argv[++i];
    } else if (arg == "--duration" && i + 1 < argc) {
      if (!parse_int_arg(argv[++i], &config.duration_sec)) {
        scarab::common::log_error("Invalid --duration value");
        return 2;
      }
    } else if (arg == "--corpus-dir" && i + 1 < argc) {
      config.corpus_dir = argv[++i];
    } else if (arg == "--output-dir" && i + 1 < argc) {
      config.output_dir = argv[++i];
    } else if (arg == "--threads" && i + 1 < argc) {
      if (!parse_int_arg(argv[++i], &config.num_threads)) {
        scarab::common::log_error("Invalid --threads value");
        return 2;
      }
    } else if (arg == "--iteration-ms" && i + 1 < argc) {
      if (!parse_int_arg(argv[++i], &config.iteration_runtime_ms)) {
        scarab::common::log_error("Invalid --iteration-ms value");
        return 2;
      }
    } else if (arg == "--help") {
      scarab::common::log_info(
          "Usage: scarab-fuzzer --candidates <path> --duration <sec> "
          "--corpus-dir <dir> --output-dir <dir> [--threads N] [--iteration-ms N]");
      return 0;
    } else {
      scarab::common::log_error("Unknown argument: " + arg);
      return 2;
    }
  }

  scarab::fuzzer::FuzzerEngine engine;
  scarab::fuzzer::FuzzerRunSummary summary;
  if (!engine.run(config, &summary)) {
    scarab::common::log_error("FuzzerEngine run failed");
    return 1;
  }

  scarab::common::log_info("FuzzerEngine completed: iterations=" +
                           std::to_string(summary.iterations) +
                           " crashes=" + std::to_string(summary.crashes) +
                           " unique_bugs=" + std::to_string(summary.bugs_found) +
                           " total_reports=" + std::to_string(summary.total_bug_reports) +
                           " internal_filtered=" +
                           std::to_string(summary.internal_races_filtered));
  return 0;
}
