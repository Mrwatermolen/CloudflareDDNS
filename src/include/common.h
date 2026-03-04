#ifndef __CLOUDFLARE_DDNS_COMMON_H__
#define __CLOUDFLARE_DDNS_COMMON_H__

#include <expected>
#include <functional>
#include <memory>
#include <regex>
#include <string>
#include <utility>
namespace cfd {

struct Error {
  std::string message;
};

#define CHECK_HTTP_RESULT(res, msg)                                            \
  do {                                                                         \
    if (!(res)) {                                                              \
      auto __err_msg = std::format("{}: network error: {}", msg,               \
                                   httplib::to_string((res).error()));         \
      LOG_ERROR(__err_msg);                                                    \
      return std::unexpected<Error>{Error{.message = __err_msg}};              \
    }                                                                          \
    if ((res)->status != 200) {                                                \
      LOG_ERROR(std::format("{}: http status: {}", msg, (res)->status));       \
      auto __err_msg = std::format("{}: request failed, status: {}, body: {}", \
                                   msg, (res)->status, (res)->body);           \
      return std::unexpected<Error>{Error{.message = __err_msg}};              \
    }                                                                          \
  } while (0)

class IpResolver {
 public:
  IpResolver() = default;
  IpResolver(const IpResolver&) = delete;
  IpResolver& operator=(const IpResolver&) = delete;
  IpResolver(IpResolver&&) = delete;
  virtual ~IpResolver() = default;
  virtual auto resolve() -> std::expected<std::string, Error> = 0;
  virtual auto resolveAsync(
      std::function<void(std::expected<std::string, Error>)> callback)
      -> void = 0;
};

template <typename T>
class IpResolverWrapper : public IpResolver {
 public:
  template <typename... Args>
  explicit IpResolverWrapper(Args&&... args)
      : impl(std::make_unique<T>(std::forward<Args>(args)...)) {}

  auto resolve() -> std::expected<std::string, Error> override {
    return impl->resolve();
  }

  auto resolveAsync(
      std::function<void(std::expected<std::string, Error>)> callback)
      -> void override {
    impl->resolveAsync(std::move(callback));
  }

  std::unique_ptr<T> impl;
};

inline auto validateIpv4(std::string_view ip) -> bool {
  static const std::regex ip_pattern{
      R"(^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$)"};

  std::match_results<std::string_view::const_iterator> match;
  if (!std::regex_match(ip.begin(), ip.end(), match, ip_pattern)) {
    return false;
  }
  for (int i = 1; i <= 4; ++i) {
    std::string_view part = {match[i].first, match[i].second};
    if (part.length() > 3) {
      return false;
    }
    int val = std::stoi(std::string(part));
    if (val < 0 || val > 255) {
      return false;
    }
  }
  return true;
}

}  // namespace cfd

#endif  // __CLOUDFLARE_DDNS_COMMON_H__
