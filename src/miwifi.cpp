#include "miwifi.h"

#include <httplib.h>
#include <openssl/sha.h>

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

#include "common.h"
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

static auto sha1Hex(std::string_view input) {
  unsigned char hash[SHA_DIGEST_LENGTH];
  SHA1(reinterpret_cast<const unsigned char*>(input.data()), input.length(),
       hash);
  std::string result;
  result.reserve(SHA_DIGEST_LENGTH * 2);
  for (auto i : hash) {
    result += std::format("{:02x}", i);
  }
  return result;
}

MiWiFi::MiWiFi(std::string_view host)
    : client_{
          std::make_unique<httplib::Client>(std::format("http://{}", host))} {
  LOG_DEBUG(std::format("Init MiWiFi client: {}", host));
}

MiWiFi::~MiWiFi() = default;

auto MiWiFi::fetchWebContent() -> std::expected<std::string, Error> {
  LOG_DEBUG("Fetching web content");
  std::scoped_lock lock{client_mutex_};
  auto res = client_->Get(WEB_PATH);
  CHECK_HTTP_RESULT(res, "Fetch MiWiFi web content");
  LOG_DEBUG("Web content fetched");
  return res->body;
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
  auto first_hash = sha1Hex(std::format("{}{}", password, key));
  return sha1Hex(std::format("{}{}", nonce, first_hash));
}

auto MiWiFi::requestToken(std::string_view username, std::string_view password,
                          std::string_view nonce, std::string_view key)
    -> std::expected<std::string, Error> {
  LOG_DEBUG("Requesting token");
  httplib::Params params;
  params.emplace("username", username);
  params.emplace("password", password);
  params.emplace("nonce", nonce);
  params.emplace("logtype", "2");

  std::scoped_lock lock(client_mutex_);
  auto res = client_->Post(LOGIN_PATH, params);
  CHECK_HTTP_RESULT(res, "Request Token");

  auto json_res = nlohmann::json::parse(res->body, nullptr, false);
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

struct LoginContext {
  std::string content;
  std::string key;
  std::string device_id;
  std::string nonce;
  std::string password_hash;
};

auto MiWiFi::login(std::string_view username, std::string_view password)
    -> std::expected<void, Error> {
  LOG_INFO(std::format("Login start: {}", username));
  return fetchWebContent()
      .and_then([&](const std::string& content)
                    -> std::expected<LoginContext, Error> {
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
        return LoginContext{.key = std::move(*key_res),
                            .device_id = std::move(*dev_res),
                            .nonce = nonce,
                            .password_hash = pwd_hash};
      })
      .and_then(
          [&](const LoginContext& ctx) -> std::expected<std::string, Error> {
            return requestToken(username, ctx.password_hash, ctx.nonce,
                                ctx.key);
          })
      .and_then([this](std::string token) -> std::expected<void, Error> {
        token_ = std::move(token);
        return {};
      });
}

auto MiWiFi::apiEndpoint(std::string endpoint)
    -> std::expected<std::string, Error> {
  if (token_.empty()) {
    LOG_ERROR("API called without token");
    return std::unexpected(Error{.message = "Not logged in"});
  }
  auto path = std::format("/cgi-bin/luci/;stok={}/api/{}", token_, endpoint);
  LOG_DEBUG(std::format("API Call: {}", endpoint));
  std::scoped_lock lock(client_mutex_);
  auto res = client_->Get(path);
  CHECK_HTTP_RESULT(res, std::format("API for {}", endpoint));
  return res->body;
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
}  // namespace cfd
