#include "scarab/analyzer/analyzer_pipeline.h"

#include "scarab/common/logging.h"

#include <iostream>
#include <string>

namespace {

void print_usage() {
  std::cerr << "Usage:\n";
  std::cerr << "  scarab-analyzer --source <file.cpp> --compile-commands <compile_commands.json> "
               "--output <candidates.json> [--project <name>] "
               "[--interproc-depth <0..3>]\n";
}

bool parse_args(int argc, char** argv, scarab::analyzer::AnalyzerPipelineOptions* options) {
  if (options == nullptr) {
    return false;
  }

  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "--source" && i + 1 < argc) {
      options->source_file = argv[++i];
    } else if (arg == "--compile-commands" && i + 1 < argc) {
      options->compile_commands_path = argv[++i];
    } else if (arg == "--output" && i + 1 < argc) {
      options->output_path = argv[++i];
    } else if (arg == "--project" && i + 1 < argc) {
      options->project_name = argv[++i];
    } else if (arg == "--interproc-depth" && i + 1 < argc) {
      try {
        options->interproc_depth = std::stoi(argv[++i]);
      } catch (...) {
        return false;
      }
    } else {
      return false;
    }
  }

  if (options->interproc_depth < 0 || options->interproc_depth > 3) {
    return false;
  }

  return !options->source_file.empty() && !options->compile_commands_path.empty() &&
         !options->output_path.empty();
}

}  // namespace

int main(int argc, char** argv) {
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "--print-capabilities") {
#if defined(SCARAB_HAS_CLANG_TOOLING) && SCARAB_HAS_CLANG_TOOLING
      std::cout << "has_clang_tooling=1\n";
#else
      std::cout << "has_clang_tooling=0\n";
#endif
      std::cout << "interproc_depth_max=3\n";
      return 0;
    }
  }

  scarab::analyzer::AnalyzerPipelineOptions options;
  if (!parse_args(argc, argv, &options)) {
    print_usage();
    return 2;
  }

  scarab::analyzer::AnalyzerPipeline pipeline;
  const auto result = pipeline.run(options);
  if (!result.success) {
    scarab::common::log_error(result.error_message);
    return 1;
  }

  scarab::common::log_info("Stage 1 analysis completed");
  std::cout << "callbacks_found=" << result.callbacks.size() << "\n";
  std::cout << "race_candidates=" << result.candidates.size() << "\n";
  std::cout << "output=" << options.output_path << "\n";
  return 0;
}
