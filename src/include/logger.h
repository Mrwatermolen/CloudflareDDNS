#ifndef __CLOUDFLARE_DDNS_LOGGER_H__
#define __CLOUDFLARE_DDNS_LOGGER_H__

#include <chrono>
#include <format>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <source_location>
#include <sstream>
#include <string_view>

namespace cfd {

enum class LogLevel { Debug, Info, Warn, Error };

class Logger {
 public:
  static void log(LogLevel level, std::string_view msg,
                  std::source_location loc = std::source_location::current()) {
    std::scoped_lock lock{mutex};
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  now.time_since_epoch()) %
              1000;

    std::string_view level_str = "UNKNOWN";
    switch (level) {
      case LogLevel::Debug:
        level_str = "DEBUG";
        break;
      case LogLevel::Info:
        level_str = "INFO";
        break;
      case LogLevel::Warn:
        level_str = "WARN";
        break;
      case LogLevel::Error:
        level_str = "ERROR";
        break;
    }

    auto& out = (level == LogLevel::Error || level == LogLevel::Warn)
                    ? std::cerr
                    : std::cout;

    std::ostringstream oss;
    oss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    std::string time_str = oss.str();

    try {
      std::println(out, "[{}.{:03}] [{}] [{}:{}] {}", time_str, ms.count(),
                   level_str, loc.file_name(), loc.line(), msg);
    } catch (...) {
      out << std::format("[{}.{:03}] [{}] [{}:{}] {}\n", time_str, ms.count(),
                         level_str, loc.file_name(), loc.line(), msg);
    }

    if (level == LogLevel::Error) {
      out.flush();
    }
  }

  static void debug(std::string_view msg, std::source_location loc =
                                              std::source_location::current()) {
    log(LogLevel::Debug, msg, loc);
  }
  static void info(std::string_view msg,
                   std::source_location loc = std::source_location::current()) {
    log(LogLevel::Info, msg, loc);
  }
  static void warn(std::string_view msg,
                   std::source_location loc = std::source_location::current()) {
    log(LogLevel::Warn, msg, loc);
  }
  static void error(std::string_view msg, std::source_location loc =
                                              std::source_location::current()) {
    log(LogLevel::Error, msg, loc);
  }

 private:
  static inline std::mutex mutex;
};

}  // namespace cfd

#define LOG_DEBUG(msg) cfd::Logger::debug(msg)
#define LOG_INFO(msg) cfd::Logger::info(msg)
#define LOG_WARN(msg) cfd::Logger::warn(msg)
#define LOG_ERROR(msg) cfd::Logger::error(msg)

#endif  // __CLOUDFLARE_DDNS_LOGGER_H__
