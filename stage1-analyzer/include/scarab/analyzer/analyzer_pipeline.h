#pragma once

#include <map>
#include <string>
#include <vector>

#include "scarab/analyzer/access_extractor.h"
#include "scarab/analyzer/race_candidate.h"

namespace scarab::analyzer {

struct AnalyzerPipelineOptions {
  std::string source_file;
  std::string compile_commands_path;
  std::string output_path;
  std::string project_name = "unknown";
  int interproc_depth = 1;
};

struct AnalyzerPipelineResult {
  bool success = false;
  std::string error_message;
  std::vector<CallbackInfo> callbacks;
  CallbackAccessMap access_map;
  std::vector<RaceCandidate> candidates;
};

class AnalyzerPipeline {
 public:
  AnalyzerPipeline() = default;

  AnalyzerPipelineResult run(const AnalyzerPipelineOptions& options) const;
};

}  // namespace scarab::analyzer
