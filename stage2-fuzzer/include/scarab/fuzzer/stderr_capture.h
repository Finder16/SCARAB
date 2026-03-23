#pragma once

// RAII helper that redirects STDERR_FILENO to a pipe while the object is
// alive, then restores the original descriptor on finish() / destruction.
// Used to capture TSan / ASan output produced during in-process execution.
//
// Shared between fuzzer_engine.cpp and e2e_runner.cpp so that both FUZZ and
// REPLAY modes collect sanitizer output identically.

#if defined(SCARAB_FUZZER_HAS_ROS2)

#include <mutex>
#include <string>
#include <thread>

#include <unistd.h>

namespace scarab::fuzzer {

class ScopedStderrCapture {
 public:
  ScopedStderrCapture() {
    int pipefd[2];
    if (::pipe(pipefd) != 0) return;

    saved_fd_ = ::dup(STDERR_FILENO);
    if (saved_fd_ < 0) {
      ::close(pipefd[0]);
      ::close(pipefd[1]);
      return;
    }

    if (::dup2(pipefd[1], STDERR_FILENO) < 0) {
      ::close(pipefd[0]);
      ::close(pipefd[1]);
      ::close(saved_fd_);
      saved_fd_ = -1;
      return;
    }
    // pipefd[1] is now duplicated into STDERR_FILENO; close the original.
    ::close(pipefd[1]);
    pipe_read_ = pipefd[0];
    active_ = true;

    // Drain stderr continuously to avoid pipe-buffer deadlock when TSan prints
    // large reports.
    reader_thread_ = std::thread([this]() {
      char buf[4096];
      for (;;) {
        const ssize_t n = ::read(pipe_read_, buf, sizeof(buf));
        if (n <= 0) {
          break;
        }
        std::lock_guard<std::mutex> lock(buffer_mutex_);
        buffer_.append(buf, static_cast<size_t>(n));
        if (buffer_.size() > 1u * 1024u * 1024u) {
          buffer_.erase(0, buffer_.size() - 1u * 1024u * 1024u);
        }
      }
    });
  }

  /// Restores stderr and returns all data written to it since construction.
  /// Safe to call multiple times; subsequent calls return an empty string.
  std::string finish() {
    if (!active_) return {};
    active_ = false;

    // Flush the C-library stderr buffer into the pipe write-end (fd 2).
    ::fflush(stderr);

    // Restore original stderr.  dup2 closes the pipe's write-end (old fd 2).
    ::dup2(saved_fd_, STDERR_FILENO);
    ::close(saved_fd_);
    saved_fd_ = -1;

    if (reader_thread_.joinable()) {
      reader_thread_.join();
    }
    ::close(pipe_read_);
    pipe_read_ = -1;

    std::lock_guard<std::mutex> lock(buffer_mutex_);
    return buffer_;
  }

  ~ScopedStderrCapture() {
    if (active_) finish();
  }

  ScopedStderrCapture(const ScopedStderrCapture&) = delete;
  ScopedStderrCapture& operator=(const ScopedStderrCapture&) = delete;

 private:
  int saved_fd_  = -1;
  int pipe_read_ = -1;
  bool active_   = false;
  std::thread reader_thread_;
  std::mutex buffer_mutex_;
  std::string buffer_;
};

}  // namespace scarab::fuzzer

#endif  // SCARAB_FUZZER_HAS_ROS2
