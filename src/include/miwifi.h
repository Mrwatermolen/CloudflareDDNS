#ifndef __CLOUDFLARE_DDNS_MIWIFI_H__
#define __CLOUDFLARE_DDNS_MIWIFI_H__

#include <expected>
#include <memory>
#include <mutex>
#include <random>
#include <string>
#include <string_view>

#include "common.h"

namespace httplib {
class Client;
}

namespace cfd {

class MiWiFi {
 public:
  explicit MiWiFi(std::string_view host);

  ~MiWiFi();

  MiWiFi(const MiWiFi&) = delete;
  MiWiFi& operator=(const MiWiFi&) = delete;
  MiWiFi(MiWiFi&&) = delete;
  MiWiFi& operator=(MiWiFi&&) = delete;

  auto login(std::string_view username, std::string_view password)
      -> std::expected<void, Error>;

  auto apiEndpoint(std::string endpoint) -> std::expected<std::string, Error>;

  auto getPublicIp() -> std::expected<std::string, Error>;

 private:
  std::unique_ptr<httplib::Client> client_;
  mutable std::mutex client_mutex_;
  std::string token_;

  static auto getRng() -> std::mt19937& {
    thread_local std::mt19937 gen{std::random_device{}()};
    return gen;
  }

  auto fetchWebContent() -> std::expected<std::string, Error>;

  static auto extractKey(std::string_view web_content)
      -> std::expected<std::string, Error>;

  static auto extractDeviceId(std::string_view web_content)
      -> std::expected<std::string, Error>;

  static auto generateNonce(std::string_view device_id) -> std::string;

  static auto hashPassword(std::string_view password, std::string_view key,
                           std::string_view nonce) -> std::string;

  auto requestToken(std::string_view username, std::string_view password,
                    std::string_view nonce, std::string_view key)
      -> std::expected<std::string, Error>;
};

}  // namespace cfd

#endif  // __CLOUDFLARE_DDNS_MIWIFI_H__
