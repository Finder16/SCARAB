# SCARAB

SCARAB (Static-guided Callback RAce Bug detector for ROS2) is a two-stage concurrency testing pipeline for ROS 2 C++ systems.

- Stage 1 statically extracts callbacks and shared-state accesses from ROS 2 code and emits race candidates.
- Stage 2 runs directed concurrency fuzzing with sanitizer-backed triage to expose races and memory-safety failures around those candidates.

This public repository focuses on the core tool implementation.

## Repository Layout

- `common/`: shared data structures and JSON I/O
- `stage1-analyzer/`: Clang/LLVM-based static analysis
- `stage2-fuzzer/`: directed concurrency fuzzing engine and runtime hooks

## Requirements

- Ubuntu 22.04
- ROS 2 Humble
- Clang/LLVM 14
- CMake 3.22+
- `nlohmann-json`

## Build

```bash
git clone <YOUR_FORK_OR_THIS_REPO_URL> SCARAB
cd SCARAB
```

Install dependencies:

```bash
sudo apt-get update
sudo apt-get install -y \
  build-essential cmake git python3 python3-pip jq \
  clang-14 llvm-14-dev libclang-14-dev libclang-cpp14-dev \
  nlohmann-json3-dev

source /opt/ros/humble/setup.bash
export CC=clang-14
export CXX=clang++-14

cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo -DSCARAB_BUILD_TESTS=OFF
cmake --build build -j"$(nproc)"
```

## Usage

### Stage 1: Static Analysis

Stage 1 expects a target project with a valid `compile_commands.json`.

```bash
source /opt/ros/humble/setup.bash

./build/stage1-analyzer/scarab-analyzer \
  --source /path/to/target/source.cpp \
  --compile-commands /path/to/compile_commands.json \
  --output /tmp/candidates.json
```

### Stage 2: Directed Concurrency Fuzzing

Stage 2 consumes the candidate file produced by Stage 1.

```bash
source /opt/ros/humble/setup.bash

./build/stage2-fuzzer/scarab-fuzzer \
  --candidates /tmp/candidates.json \
  --target nav2_costmap_subscriber \
  --duration 600 \
  --output-dir /tmp/stage2_out
```

## Notes

- Stage 1 relies on Clang/LLVM headers and `libclang-cpp`.
- Stage 2 requires a ROS 2 runtime environment and is designed for sanitizer-backed target execution.
