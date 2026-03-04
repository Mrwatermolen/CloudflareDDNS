#ifndef __CLOUDFLARE_DDNS_MIWIFI_H__
#define __CLOUDFLARE_DDNS_MIWIFI_H__

#include <expected>
#include <memory>
#include <mutex>
#include <random>
#include <string>
#include <string_view>

#include "common.h"
#include "swsc/asio_compatibility.hpp"
#include "swsc/client_http.hpp"

namespace cfd {

class MiWiFi : public std::enable_shared_from_this<MiWiFi> {
 public:
  explicit MiWiFi(std::string_view host, std::string_view key = {},
                  std::string_view device_id = {},
                  std::shared_ptr<SimpleWeb::io_context> io_context = nullptr);

  ~MiWiFi();

  MiWiFi(const MiWiFi&) = delete;
  MiWiFi& operator=(const MiWiFi&) = delete;
  MiWiFi(MiWiFi&&) = delete;
  MiWiFi& operator=(MiWiFi&&) = delete;

  auto login(std::string_view username, std::string_view password)
      -> std::expected<void, Error>;

  auto apiEndpoint(std::string_view endpoint)
      -> std::expected<std::string, Error>;

  auto getPublicIp() -> std::expected<std::string, Error>;

  auto resolve() -> std::expected<std::string, Error>;

  auto loginAsync(std::string_view username, std::string_view password,
                  std::function<void(std::expected<void, Error>)> callback)
      -> void;

  auto apiEndpointAsync(
      std::string endpoint,
      std::function<void(std::expected<std::string, Error>)> callback) -> void;

  auto getPublicIpAsync(
      std::function<void(std::expected<std::string, Error>)> callback) -> void;

  auto resolveAsync(
      std::function<void(std::expected<std::string, Error>)> callback) -> void;

 private:
  std::shared_ptr<SimpleWeb::io_context> io_context_{nullptr};
  std::unique_ptr<SimpleWeb::Client<SimpleWeb::HTTP>> client_;
  mutable std::mutex token_mutex_;
  std::string token_;
  std::string key_;
  std::string device_id_;

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
                    std::string_view nonce)
      -> std::expected<std::string, Error>;

  auto fetchWebContentAsync(
      std::function<void(std::expected<std::string, Error>)> callback) -> void;

  auto requestTokenAsync(
      std::string_view username, std::string_view password,
      std::string_view nonce,
      std::function<void(std::expected<std::string, Error>)> callback) -> void;
};

}  // namespace cfd

#endif  // __CLOUDFLARE_DDNS_MIWIFI_H__
