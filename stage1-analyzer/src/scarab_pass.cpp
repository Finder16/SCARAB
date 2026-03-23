/// SCARAB LLVM Instrumentation Pass
///
/// Inserts calls to __scarab_before_access / __scarab_after_access around
/// load and store instructions whose debug-info source line matches an
/// access point from candidates.json (or a standalone access_points.json).
///
/// Build: cmake -DSCARAB_BUILD_LLVM_PASS=ON → produces libscarab_pass.so
/// Usage: clang -fpass-plugin=libscarab_pass.so
///              -mllvm -scarab-access-points=access_points.json
///              -c target.cpp -o target.o
///
/// The pass links at load-time against the LLVM shared library so it can be
/// used with `opt` or `clang -fpass-plugin`.

#include "llvm/IR/DIBuilder.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Pass.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/MemoryBuffer.h"

#include <cstdlib>
#include <set>
#include <string>

using namespace llvm;

// ── Command-line option for the access points file ────────────────────────────
// NOTE: -mllvm -scarab-access-points=... may not work with all clang versions
// when using -fpass-plugin (the option isn't registered early enough).
// As a robust fallback, the pass also reads $SCARAB_ACCESS_POINTS env var.
static cl::opt<std::string> AccessPointsFile(
    "scarab-access-points",
    cl::desc("Path to JSON file listing source lines to instrument"),
    cl::value_desc("filename"), cl::init(""));

static std::string resolve_access_points_path() {
  if (!AccessPointsFile.empty()) return AccessPointsFile;
  if (const char* env = std::getenv("SCARAB_ACCESS_POINTS"))
    return std::string(env);
  return "";
}

namespace {

/// An access point is identified by (source_file_suffix, line_number).
/// We match by suffix so that relative/absolute path differences don't matter.
struct AccessPoint {
  std::string source_file;
  int line;

  bool operator<(const AccessPoint& o) const {
    if (line != o.line) return line < o.line;
    return source_file < o.source_file;
  }
};

/// Parse access_points.json or candidates.json.
///
/// Supported formats:
///   1. Array of {source_file, line}
///   2. candidates.json → extracts line_a/line_b + callback source_file
std::set<AccessPoint> load_access_points(StringRef path) {
  std::set<AccessPoint> points;
  if (path.empty()) return points;

  auto buf_or_err = MemoryBuffer::getFile(path);
  if (!buf_or_err) {
    errs() << "scarab-pass: cannot open access points file: " << path << "\n";
    return points;
  }

  auto json_or_err = json::parse((*buf_or_err)->getBuffer());
  if (!json_or_err) {
    // Try candidates.json format — the file may be the full schema with
    // a "race_candidates" array.
    errs() << "scarab-pass: JSON parse error: "
           << toString(json_or_err.takeError()) << "\n";
    return points;
  }

  json::Value& root = *json_or_err;

  // Helper: extract from a single candidate object.
  auto extract_from_candidate = [&](const json::Object& obj) {
    // Try top-level line_a/line_b.
    if (auto la = obj.getInteger("line_a")) {
      std::string sf;
      if (auto s = obj.getString("source_file"))
        sf = s->str();
      else if (auto cba = obj.getObject("callback_a"))
        if (auto s2 = cba->getString("source_file"))
          sf = s2->str();
      if (*la > 0) points.insert({sf, static_cast<int>(*la)});
    }
    if (auto lb = obj.getInteger("line_b")) {
      std::string sf;
      if (auto s = obj.getString("source_file"))
        sf = s->str();
      else if (auto cbb = obj.getObject("callback_b"))
        if (auto s2 = cbb->getString("source_file"))
          sf = s2->str();
      if (*lb > 0) points.insert({sf, static_cast<int>(*lb)});
    }

    // Also check shared_variable.line_a/line_b.
    if (auto sv = obj.getObject("shared_variable")) {
      std::string sf;
      if (auto s = obj.getString("source_file")) sf = s->str();
      if (auto la2 = sv->getInteger("line_a"))
        if (*la2 > 0) points.insert({sf, static_cast<int>(*la2)});
      if (auto lb2 = sv->getInteger("line_b"))
        if (*lb2 > 0) points.insert({sf, static_cast<int>(*lb2)});
    }
  };

  // Format 1: plain array of {source_file, line}.
  if (auto* arr = root.getAsArray()) {
    for (auto& elem : *arr) {
      if (auto* obj = elem.getAsObject()) {
        // Candidate object?
        if (obj->get("callback_a") || obj->get("line_a")) {
          extract_from_candidate(*obj);
        } else {
          // Simple {source_file, line} entry.
          std::string sf;
          if (auto s = obj->getString("source_file")) sf = s->str();
          if (auto l = obj->getInteger("line"))
            if (*l > 0) points.insert({sf, static_cast<int>(*l)});
        }
      }
    }
  }
  // Format 2: {race_candidates: [...]} wrapper.
  else if (auto* obj = root.getAsObject()) {
    if (auto* rc = obj->getArray("race_candidates")) {
      for (auto& elem : *rc) {
        if (auto* cand = elem.getAsObject()) {
          extract_from_candidate(*cand);
        }
      }
    } else {
      // Single candidate object.
      extract_from_candidate(*obj);
    }
  }

  return points;
}

/// Check if a debug-info source location matches any access point.
/// Uses suffix matching on the file path.
bool matches_access_point(const std::set<AccessPoint>& points,
                          StringRef di_file, unsigned di_line) {
  for (const auto& ap : points) {
    if (static_cast<unsigned>(ap.line) != di_line) continue;
    // Suffix match: ap.source_file may be "costmap_subscriber.cpp" while
    // di_file is "/full/path/to/costmap_subscriber.cpp".
#if LLVM_VERSION_MAJOR >= 18
    if (ap.source_file.empty() || di_file.ends_with(ap.source_file) ||
        StringRef(ap.source_file).ends_with(di_file)) {
#else
    if (ap.source_file.empty() || di_file.endswith(ap.source_file) ||
        StringRef(ap.source_file).endswith(di_file)) {
#endif
      return true;
    }
  }
  return false;
}

// ── The pass itself ───────────────────────────────────────────────────────────

struct ScarabInstrumentationPass
    : public PassInfoMixin<ScarabInstrumentationPass> {
  PreservedAnalyses run(Module& M, ModuleAnalysisManager& /*MAM*/) {
    const std::set<AccessPoint> points =
        load_access_points(resolve_access_points_path());

    errs() << "scarab-pass: resolved path='" << resolve_access_points_path()
           << "' points=" << points.size() << "\n";
    for (const auto& p : points)
      errs() << "scarab-pass:   " << p.source_file << ":" << p.line << "\n";

    if (points.empty()) {
      // Nothing to instrument.
      return PreservedAnalyses::all();
    }

    LLVMContext& ctx = M.getContext();

    // Declare the hook functions.
    // void __scarab_before_access(i8* addr, i32 access_type, i32 source_line)
    Type* void_ty = Type::getVoidTy(ctx);
#if LLVM_VERSION_MAJOR >= 18
    Type* ptr_ty = PointerType::getUnqual(ctx);
#else
    Type* ptr_ty = Type::getInt8PtrTy(ctx);
#endif
    Type* i32_ty = Type::getInt32Ty(ctx);
    FunctionType* hook_ty =
        FunctionType::get(void_ty, {ptr_ty, i32_ty, i32_ty}, false);

    FunctionCallee before_fn =
        M.getOrInsertFunction("__scarab_before_access", hook_ty);
    FunctionCallee after_fn =
        M.getOrInsertFunction("__scarab_after_access", hook_ty);

    bool modified = false;

    for (Function& F : M) {
      if (F.isDeclaration()) continue;

      for (auto& BB : F) {
        // Collect instructions to instrument (can't modify while iterating).
        SmallVector<Instruction*, 8> targets;

        for (auto& I : BB) {
          if (!isa<LoadInst>(&I) && !isa<StoreInst>(&I)) continue;

          // Check debug location.
          const DebugLoc& DL = I.getDebugLoc();
          if (!DL) continue;

          StringRef file;
          if (auto* scope = DL->getScope()) {
            if (auto* f = scope->getFile()) {
              file = f->getFilename();
            }
          }

          if (matches_access_point(points, file, DL.getLine())) {
            targets.push_back(&I);
          }
        }

        for (Instruction* I : targets) {
          const DebugLoc& DL = I->getDebugLoc();
          IRBuilder<> builder(I);

          // Determine access type: 0=READ (load), 1=WRITE (store).
          int access_type = isa<LoadInst>(I) ? 0 : 1;

          // Get pointer operand.
          Value* ptr = nullptr;
          if (auto* load = dyn_cast<LoadInst>(I)) {
            ptr = load->getPointerOperand();
          } else if (auto* store = dyn_cast<StoreInst>(I)) {
            ptr = store->getPointerOperand();
          }

#if LLVM_VERSION_MAJOR >= 18
          Value* addr = ptr;  // opaque pointers — no cast needed
#else
          Value* addr = builder.CreateBitCast(ptr, ptr_ty);
#endif
          Value* at_val = ConstantInt::get(i32_ty, access_type);
          Value* line_val =
              ConstantInt::get(i32_ty, static_cast<int>(DL.getLine()));

          // Insert __scarab_before_access BEFORE the load/store.
          builder.CreateCall(before_fn, {addr, at_val, line_val});

          // Insert __scarab_after_access AFTER the load/store.
          IRBuilder<> after_builder(I->getNextNode());
          after_builder.CreateCall(after_fn, {addr, at_val, line_val});

          modified = true;
        }
      }
    }

    if (modified) {
      errs() << "scarab-pass: instrumented module '"
             << M.getModuleIdentifier() << "'\n";
    }
    return modified ? PreservedAnalyses::none() : PreservedAnalyses::all();
  }

  static bool isRequired() { return true; }
};

}  // namespace

// ── Plugin registration ───────────────────────────────────────────────────────

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "ScarabInstrumentationPass", "0.1",
          [](PassBuilder& PB) {
            // Register as an early module pass so it runs before optimizations
            // can fold away the instrumented loads/stores.
            PB.registerPipelineStartEPCallback(
                [](ModulePassManager& MPM, OptimizationLevel /*OL*/) {
                  MPM.addPass(ScarabInstrumentationPass());
                });
          }};
}
