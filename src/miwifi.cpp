#include "miwifi.h"

#include <openssl/sha.h>

#include <cctype>
#include <chrono>
#include <expected>
#include <format>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <random>
#include <regex>
#include <string>
#include <string_view>
#include <swsc/status_code.hpp>
#include <utility>

#include "common.h"
#include "crypto.hpp"
#include "http_utils.h"
#include "logger.h"

namespace cfd {
static constexpr auto WEB_PATH = "/cgi-bin/luci/web";
static constexpr auto LOGIN_PATH = "/cgi-bin/luci/api/xqsystem/login";
static constexpr std::string_view DEVICE_ID_PATTERN_STR =
    R"(deviceId\s*=\s*['\"]([^'\"]+)['\"])";
static constexpr std::string_view KEY_PATTERN_STR = R"(key\s*:\s*'([^']*)')";
static const std::regex DEVICE_ID_REGEX{DEVICE_ID_PATTERN_STR.data(),
                                        DEVICE_ID_PATTERN_STR.size()};
static const std::regex KEY_REGEX{KEY_PATTERN_STR.data(),
                                  KEY_PATTERN_STR.size()};

using HttpClient = SimpleWeb::Client<SimpleWeb::HTTP>;
using HttpResponse = HttpClient::Response;

MiWiFi::MiWiFi(std::string_view host, std::string_view key,
               std::string_view device_id,
               std::shared_ptr<SimpleWeb::io_context> io_context)
    : io_context_{std::move(io_context)},
      client_{std::make_unique<HttpClient>(std::string{host})},
      key_{key},
      device_id_{device_id} {
  if (io_context_) {
    client_->io_service = io_context_;
  } else {
    LOG_DEBUG("No io_context provided, using internal");
    io_context_ = std::make_shared<SimpleWeb::io_context>();
    client_->io_service = io_context_;
  }
  LOG_DEBUG(std::format("Init MiWiFi client: {}", host));
}

MiWiFi::~MiWiFi() = default;

auto MiWiFi::fetchWebContent() -> std::expected<std::string, Error> {
  LOG_DEBUG("Fetching web content");
  std::shared_ptr<HttpResponse> res;

  try {
    res = client_->request("GET", WEB_PATH);
  } catch (const std::exception& e) {
    auto err_msg =
        std::format("Fetch MiWiFi web content: network error: {}", e.what());
    LOG_ERROR(err_msg);
    return std::unexpected{Error{.message = std::move(err_msg)}};
  }

  if (auto status = ensureSuccessStatus(res, "Fetch MiWiFi web content");
      !status) {
    return std::unexpected{status.error()};
  }

  LOG_DEBUG("Web content fetched");
  return res->content.string();
}

auto MiWiFi::extractKey(std::string_view web_content)
    -> std::expected<std::string, Error> {
  std::match_results<std::string_view::const_iterator> match;
  if (std::regex_search(web_content.begin(), web_content.end(), match,
                        KEY_REGEX)) {
    LOG_DEBUG("Key extracted");
    return std::string{match[1].first, match[1].second};
  }
  LOG_WARN("Key extraction failed");
  return std::unexpected{
      Error{.message = "Failed to extract key from web content"}};
}

auto MiWiFi::extractDeviceId(std::string_view web_content)
    -> std::expected<std::string, Error> {
  std::match_results<std::string_view::const_iterator> match;
  if (std::regex_search(web_content.begin(), web_content.end(), match,
                        DEVICE_ID_REGEX)) {
    LOG_DEBUG("Device ID extracted");
    return std::string{match[1].first, match[1].second};
  }
  LOG_WARN("Device ID extraction failed");
  return std::unexpected{
      Error{.message = "Failed to extract device ID from web content"}};
}

auto MiWiFi::generateNonce(std::string_view device_id) -> std::string {
  auto now = std::chrono::duration_cast<std::chrono::seconds>(
                 std::chrono::system_clock::now().time_since_epoch())
                 .count();
  auto& gen = getRng();
  std::uniform_int_distribution dist{1000, 10000};
  int random_val = dist(gen);
  return std::format("0_{}_{}_{}", device_id, now, random_val);
}

auto MiWiFi::hashPassword(std::string_view password, std::string_view key,
                          std::string_view nonce) -> std::string {
  return crypto::miwifiEncryptPassword(password, key, nonce);
}

auto MiWiFi::requestToken(std::string_view username, std::string_view password,
                          std::string_view nonce)
    -> std::expected<std::string, Error> {
  LOG_DEBUG("Requesting token");

  auto body = encodeFormBody({{"username", username},
                              {"password", password},
                              {"nonce", nonce},
                              {"logtype", "2"}});

  SimpleWeb::CaseInsensitiveMultimap headers;
  headers.emplace("Content-Type", "application/x-www-form-urlencoded");

  std::shared_ptr<HttpResponse> res;

  try {
    res = client_->request("POST", LOGIN_PATH, body, headers);
  } catch (const std::exception& e) {
    auto err_msg = std::format("Request Token: network error: {}", e.what());
    LOG_ERROR(err_msg);
    return std::unexpected{Error{.message = std::move(err_msg)}};
  }

  if (auto status = ensureSuccessStatus(res, "Request Token"); !status) {
    return std::unexpected{status.error()};
  }

  auto json_res = nlohmann::json::parse(res->content.string(), nullptr, false);
  if (json_res.is_discarded()) {
    LOG_ERROR("Invalid JSON in token response");
    return std::unexpected{
        Error{.message = "Invalid JSON response from login"}};
  }
  if (!json_res.contains("token")) {
    LOG_ERROR("Token missing in response");
    return std::unexpected{Error{.message = "Token missing in login response"}};
  }
  const auto& token_val = json_res["token"];
  if (!token_val.is_string()) {
    LOG_ERROR("Token is not a string");
    return std::unexpected{Error{.message = "Token is not a string"}};
  }
  LOG_INFO("Login successful");
  return token_val.get<std::string>();
}

auto MiWiFi::login(std::string_view username, std::string_view password)
    -> std::expected<void, Error> {
  LOG_INFO(std::format("Login start: {}", username));
  if (!key_.empty() && !device_id_.empty()) {
    LOG_DEBUG("Use key/device_id from config, skip web content fetch");
    const auto nonce = generateNonce(device_id_);
    const auto pwd_hash = hashPassword(password, key_, nonce);
    return requestToken(username, pwd_hash, nonce)
        .and_then([this](std::string token) -> std::expected<void, Error> {
          token_ = std::move(token);
          return {};
        });
  }

  return fetchWebContent()
      .and_then(
          [&](const std::string& content) -> std::expected<std::string, Error> {
            auto key_res = extractKey(content);
            if (!key_res) {
              return std::unexpected(key_res.error());
            }

            auto dev_res = extractDeviceId(content);
            if (!dev_res) {
              return std::unexpected(dev_res.error());
            }

            const auto nonce = generateNonce(*dev_res);
            const auto pwd_hash = hashPassword(password, *key_res, nonce);
            return requestToken(username, pwd_hash, nonce);
          })
      .and_then([this](std::string token) -> std::expected<void, Error> {
        std::scoped_lock lock(token_mutex_);
        token_ = std::move(token);
        return {};
      });
}

auto MiWiFi::apiEndpoint(std::string_view endpoint)
    -> std::expected<std::string, Error> {
  std::scoped_lock lock(token_mutex_);
  if (token_.empty()) {
    LOG_ERROR("API called without token");
    return std::unexpected(Error{.message = "Not logged in"});
  }
  auto path = std::format("/cgi-bin/luci/;stok={}/api/{}", token_, endpoint);
  LOG_DEBUG(std::format("API Call: {}", endpoint));

  std::shared_ptr<HttpResponse> res;

  try {
    res = client_->request("GET", path);
  } catch (const std::exception& e) {
    auto err_msg =
        std::format("API for {}: network error: {}", endpoint, e.what());
    LOG_ERROR(err_msg);
    return std::unexpected{Error{.message = std::move(err_msg)}};
  }

  if (auto status =
          ensureSuccessStatus(res, std::format("API for {}", endpoint));
      !status) {
    return std::unexpected{status.error()};
  }

  return res->content.string();
}

auto MiWiFi::getPublicIp() -> std::expected<std::string, Error> {
  return apiEndpoint("xqnetwork/wan_info")
      .and_then(
          [&](const std::string& content) -> std::expected<std::string, Error> {
            auto json_res = nlohmann::json::parse(content, nullptr, false);
            if (json_res.is_discarded()) {
              LOG_ERROR("Failed to parse WAN JSON");
              return std::unexpected{
                  Error{.message = "Failed to parse WAN info JSON"}};
            }
            if (!json_res.contains("info") ||
                !json_res["info"].contains("ipv4")) {
              LOG_ERROR("WAN info structure invalid");
              return std::unexpected{
                  Error{.message = "WAN info structure invalid"}};
            }
            const auto& ipv4 = json_res["info"]["ipv4"];
            if (!ipv4.is_array() || ipv4.empty()) {
              LOG_ERROR("IPv4 array empty");
              return std::unexpected{
                  Error{.message = "IPv4 array empty or invalid"}};
            }
            const auto& first_entry = ipv4[0];
            if (!first_entry.contains("ip")) {
              LOG_ERROR("IP field missing");
              return std::unexpected{Error{.message = "IP field missing"}};
            }
            const auto& ip_val = first_entry["ip"];
            if (!ip_val.is_string()) {
              LOG_ERROR("IP is not a string");
              return std::unexpected{Error{.message = "IP is not a string"}};
            }
            std::string ip = ip_val.get<std::string>();
            LOG_INFO(std::format("Public IP from MiWiFi: {}", ip));
            return ip;
          });
}

auto MiWiFi::resolve() -> std::expected<std::string, Error> {
  return getPublicIp();
}

auto MiWiFi::loginAsync(
    std::string_view username, std::string_view password,
    std::function<void(std::expected<void, Error>)> callback) -> void {
  LOG_INFO(std::format("Login start: {}", username));
  if (!key_.empty() && !device_id_.empty()) {
    LOG_DEBUG("Use key/device_id from config, skip web content fetch");
    const auto nonce = generateNonce(device_id_);
    const auto pwd_hash = hashPassword(password, key_, nonce);
    requestTokenAsync(username, pwd_hash, nonce,
                      [this, callback = std::move(callback)](
                          std::expected<std::string, Error> res) {
                        if (res) {
                          LOG_INFO("Login successful");
                          {
                            std::scoped_lock lock(token_mutex_);
                            token_ = std::move(*res);
                          }
                          callback({});
                        } else {
                          callback(std::unexpected{res.error()});
                        }
                      });
    return;
  }

  fetchWebContentAsync(
      [this, username = std::string(username), password = std::string(password),
       callback = std::move(callback)](std::expected<std::string, Error> res) {
        if (!res) {
          callback(std::unexpected{res.error()});
          return;
        }
        auto content = std::move(*res);
        auto key_res = extractKey(content);
        if (!key_res) {
          LOG_ERROR(std::format("Key extraction failed: {}",
                                key_res.error().message));
          callback(std::unexpected{key_res.error()});
          return;
        }

        auto dev_res = extractDeviceId(content);
        if (!dev_res) {
          LOG_ERROR(std::format("Device ID extraction failed: {}",
                                dev_res.error().message));
          callback(std::unexpected{dev_res.error()});
          return;
        }

        const auto nonce = generateNonce(*dev_res);
        const auto pwd_hash = hashPassword(password, *key_res, nonce);
        requestTokenAsync(
            username, pwd_hash, nonce,
            [this, callback = callback](std::expected<std::string, Error> res) {
              if (res) {
                {
                  std::scoped_lock lock(token_mutex_);
                  token_ = std::move(*res);
                }
                LOG_INFO("Login successful");
                callback({});
              } else {
                callback(std::unexpected{res.error()});
              }
            });
      });
}

auto MiWiFi::apiEndpointAsync(
    std::string endpoint,
    std::function<void(std::expected<std::string, Error>)> callback) -> void {
  std::scoped_lock lock(token_mutex_);
  if (token_.empty()) {
    LOG_ERROR("API called without token");
    callback(std::unexpected(Error{.message = "Not logged in"}));  // dead lock?
    return;
  }
  client_->request(
      "GET", std::format("/cgi-bin/luci/;stok={}/api/{}", token_, endpoint),
      [callback = std::move(callback)](auto&& res, auto&& err) {
        if (err) {
          LOG_ERROR(std::format("API request error: {}", err.message()));
          callback(std::unexpected{Error{.message = err.message()}});
          return;
        }
        if (auto status = ensureSuccessStatus(res, "API request"); !status) {
          LOG_ERROR(
              std::format("API request failed: {}", status.error().message));
          callback(std::unexpected{status.error()});
          return;
        }

        callback(res->content.string());
      });
}

auto MiWiFi::getPublicIpAsync(
    std::function<void(std::expected<std::string, Error>)> callback) -> void {
  apiEndpointAsync(
      "xqnetwork/wan_info",
      [callback = std::move(callback)](std::expected<std::string, Error> res) {
        if (!res) {
          callback(std::unexpected{res.error()});
          return;
        }
        auto content = std::move(*res);
        auto json_res = nlohmann::json::parse(content, nullptr, false);
        if (json_res.is_discarded()) {
          LOG_ERROR("Failed to parse WAN JSON");
          callback(std::unexpected{
              Error{.message = "Failed to parse WAN info JSON"}});
          return;
        }
        if (!json_res.contains("info") || !json_res["info"].contains("ipv4")) {
          LOG_ERROR("WAN info structure invalid");
          callback(
              std::unexpected{Error{.message = "WAN info structure invalid"}});
          return;
        }
        const auto& ipv4 = json_res["info"]["ipv4"];
        if (!ipv4.is_array() || ipv4.empty()) {
          LOG_ERROR("IPv4 array empty");
          callback(
              std::unexpected{Error{.message = "IPv4 array empty or invalid"}});
          return;
        }
        const auto& first_entry = ipv4[0];
        if (!first_entry.contains("ip")) {
          LOG_ERROR("IP field missing");
          callback(std::unexpected{Error{.message = "IP field missing"}});
          return;
        }
        const auto& ip_val = first_entry["ip"];
        if (!ip_val.is_string()) {
          LOG_ERROR("IP is not a string");
          callback(std::unexpected{Error{.message = "IP is not a string"}});
          return;
        }
        std::string ip = ip_val.get<std::string>();
        LOG_INFO(std::format("Public IP from MiWiFi: {}", ip));
        callback(ip);
      });
}

auto MiWiFi::resolveAsync(
    std::function<void(std::expected<std::string, Error>)> callback) -> void {
  getPublicIpAsync(std::move(callback));
}

auto MiWiFi::fetchWebContentAsync(
    std::function<void(std::expected<std::string, Error>)> callback) -> void {
  client_->request(
      "GET", WEB_PATH,
      [callback = std::move(callback)](auto&& res, auto&& err) {
        if (err) {
          LOG_ERROR(std::format("Fetch web content error: {}", err.message()));
          callback(std::unexpected{Error{.message = err.message()}});
          return;
        }
        if (auto status = ensureSuccessStatus(res, "Fetch web content");
            !status) {
          LOG_ERROR(std::format("Fetch web content failed: {}",
                                status.error().message));
          callback(std::unexpected{status.error()});
          return;
        }

        LOG_DEBUG("Web content fetched");
        callback(res->content.string());
      });
}

auto MiWiFi::requestTokenAsync(
    std::string_view username, std::string_view password,
    std::string_view nonce,
    std::function<void(std::expected<std::string, Error>)> callback) -> void {
  auto body = encodeFormBody({{"username", username},
                              {"password", password},
                              {"nonce", nonce},
                              {"logtype", "2"}});

  SimpleWeb::CaseInsensitiveMultimap headers;
  headers.emplace("Content-Type", "application/x-www-form-urlencoded");

  client_->request(
      "POST", LOGIN_PATH, body, headers,
      [this, callback = std::move(callback)](auto&& res, auto&& err) {
        if (err) {
          LOG_ERROR(std::format("Request Token error: {}", err.message()));
          callback(std::unexpected{Error{.message = err.message()}});
          return;
        }
        if (auto status = ensureSuccessStatus(res, "Request Token"); !status) {
          callback(std::unexpected{status.error()});
          return;
        }

        auto json_res =
            nlohmann::json::parse(res->content.string(), nullptr, false);
        if (json_res.is_discarded()) {
          LOG_ERROR("Invalid JSON in token response");
          callback(std::unexpected{
              Error{.message = "Invalid JSON response from login"}});
          return;
        }
        if (!json_res.contains("token")) {
          LOG_ERROR("Token missing in response");
          callback(std::unexpected{
              Error{.message = "Token missing in login response"}});
          return;
        }
        const auto& token_val = json_res["token"];
        if (!token_val.is_string()) {
          LOG_ERROR("Token is not a string");
          callback(std::unexpected{Error{.message = "Token is not a string"}});
          return;
        }
        LOG_INFO("Login successful");
        callback(token_val.template get<std::string>());
      });
}

}  // namespace cfd
