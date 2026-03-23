#include "scarab/analyzer/analyzer_pipeline.h"

#include "scarab/analyzer/access_extractor.h"
#include "scarab/analyzer/callback_extractor.h"
#include "scarab/analyzer/callback_group_analyzer.h"
#include "scarab/analyzer/race_candidate.h"
#include "scarab/analyzer/sync_checker.h"

#include <filesystem>
#include <utility>

namespace scarab::analyzer {

AnalyzerPipelineResult AnalyzerPipeline::run(const AnalyzerPipelineOptions& options) const {
  AnalyzerPipelineResult result;

  if (options.source_file.empty() || options.compile_commands_path.empty() ||
      options.output_path.empty()) {
    result.error_message = "Missing required options: source_file, compile_commands_path, output_path";
    return result;
  }

  if (!std::filesystem::exists(options.source_file)) {
    result.error_message = "Source file not found: " + options.source_file;
    return result;
  }
  if (!std::filesystem::exists(options.compile_commands_path)) {
    result.error_message = "compile_commands.json not found: " + options.compile_commands_path;
    return result;
  }

  CallbackExtractor callback_extractor;
  result.callbacks =
      callback_extractor.extract_callbacks(options.compile_commands_path, options.source_file);

  AccessExtractor access_extractor;
  result.access_map = access_extractor.extract_accesses(
      options.compile_commands_path, options.source_file, result.callbacks, options.interproc_depth);

  SyncChecker sync_checker;
  CallbackAccessMap annotated_access_map;
  for (const auto& [callback_name, accesses] : result.access_map) {
    auto& annotated = annotated_access_map[callback_name];
    for (const auto& access : accesses) {
      annotated.push_back(sync_checker.annotate(access));
    }
  }
  result.access_map = std::move(annotated_access_map);

  CallbackGroupAnalyzer callback_group_analyzer;
  callback_group_analyzer.analyze(result.callbacks);
  RaceCandidateGenerator candidate_generator;
  result.candidates =
      candidate_generator.generate(result.callbacks, result.access_map, callback_group_analyzer);

  if (!candidate_generator.write_json(result.candidates, options.output_path, options.project_name,
                                      static_cast<int>(result.callbacks.size()))) {
    result.error_message = "Failed to write output JSON: " + options.output_path;
    return result;
  }

  result.success = true;
  return result;
}

}  // namespace scarab::analyzer
