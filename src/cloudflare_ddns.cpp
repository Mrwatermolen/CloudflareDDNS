#include "cloudflare_ddns.h"

#include <httplib.h>
#include <openssl/ssl.h>

#include <array>
#include <expected>
#include <format>
#include <fstream>
#include <mutex>
#include <nlohmann/json.hpp>
#include <regex>
#include <string>
#include <string_view>
#include <utility>

#include "common.h"
#include "logger.h"
#include "miwifi.h"

namespace cfd {

static const std::regex IP_PATTERN{
    R"(^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$)"};

static constexpr std::array<std::string_view, 4> IP_SERVICES = {
    "ip.sb", "ipv4.icanhazip.com", "ifconfig.me/ip"};

CloudflareDDNS::CloudflareDDNS(Config config)
    : config_(std::move(config)),
      cf_client_{
          std::make_unique<httplib::Client>("https://api.cloudflare.com")} {
  LOG_DEBUG("Init Cloudflare client");
  cf_client_->enable_server_certificate_verification(true);
  cf_client_->set_connection_timeout(10, 0);
  cf_client_->set_read_timeout(10, 0);
  cf_client_->set_default_headers({{"X-Auth-Email", config_.email},
                                   {"X-Auth-Key", config_.api_key},
                                   {"Content-Type", "application/json"}});
}

CloudflareDDNS::~CloudflareDDNS() = default;

void CloudflareDDNS::setMiwifi(std::shared_ptr<MiWiFi> miwifi) {
  miwifi_ = std::move(miwifi);
}

auto CloudflareDDNS::validateIp(std::string_view ip) -> bool {
  std::match_results<std::string_view::const_iterator> match;
  if (!std::regex_match(ip.begin(), ip.end(), match, IP_PATTERN)) {
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

auto CloudflareDDNS::getPublicIpFromServices()
    -> std::expected<std::string, Error> {
  LOG_DEBUG("Fetching IP from external services");
  for (const auto& host : IP_SERVICES) {
    httplib::Client service_client(std::format("https://{}", host));
    service_client.enable_server_certificate_verification(true);
    service_client.set_connection_timeout(5, 0);
    auto res = service_client.Get("/");
    CHECK_HTTP_RESULT(res, std::format("Get IP from service {}", host));
    std::string ip = res->body;
    ip.erase(0, ip.find_first_not_of(" \n\r\t"));
    ip.erase(ip.find_last_not_of(" \n\r\t") + 1);
    if (validateIp(ip)) {
      LOG_INFO(std::format("Public IP from service: {}", ip));
      return ip;
    }
  }
  LOG_ERROR("All external IP services failed");
  return std::unexpected{Error{.message = "All IP services failed"}};
}

auto CloudflareDDNS::getPublicIp() -> std::expected<std::string, Error> {
  if (miwifi_) {
    LOG_DEBUG("Trying MiWiFi for IP");
    auto res = miwifi_->getPublicIp();
    if (res && validateIp(*res)) {
      return *res;
    }
    LOG_WARN("MiWiFi IP failed, fallback to services");
  }
  return getPublicIpFromServices();
}

auto CloudflareDDNS::readLastIp() -> std::expected<std::string, Error> {
  if (!std::filesystem::exists(config_.ip_file)) {
    LOG_DEBUG("IP file not found");
    return std::unexpected{Error{.message = "IP file not found"}};
  }
  try {
    std::ifstream file(config_.ip_file);
    if (!file) {
      return std::unexpected{Error{.message = "Failed to open IP file"}};
    }
    std::string ip((std::istreambuf_iterator<char>(file)),
                   std::istreambuf_iterator<char>());
    ip.erase(0, ip.find_first_not_of(" \n\r\t"));
    ip.erase(ip.find_last_not_of(" \n\r\t") + 1);
    if (validateIp(ip)) {
      LOG_DEBUG(std::format("Last IP: {}", ip));
      return ip;
    }
    return std::unexpected{Error{.message = "Invalid IP in file"}};
  } catch (...) {
    return std::unexpected{Error{.message = "Exception reading IP file"}};
  }
}

auto CloudflareDDNS::writeCurrentIp(std::string_view ip)
    -> std::expected<void, Error> {
  try {
    std::filesystem::create_directories(config_.ip_file.parent_path());
    std::ofstream file(config_.ip_file);
    if (!file) {
      return std::unexpected{
          Error{.message = "Failed to open IP file for writing"}};
    }
    file << ip;
    LOG_DEBUG("IP saved");
    return {};
  } catch (...) {
    return std::unexpected{Error{.message = "Exception writing IP file"}};
  }
}

auto CloudflareDDNS::getDnsRecord() -> std::expected<nlohmann::json, Error> {
  std::string path = std::format("/client/v4/zones/{}/dns_records/{}",
                                 config_.zone_id, config_.dns_record_id);
  std::scoped_lock lock{client_mutex_};
  auto res = cf_client_->Get(path);
  CHECK_HTTP_RESULT(res, "Get DNS record");
  auto json_res = nlohmann::json::parse(res->body, nullptr, false);
  if (json_res.is_discarded() || !json_res.value("success", false)) {
    LOG_ERROR("Cloudflare API GET error");
    return std::unexpected{Error{.message = "Cloudflare API error on GET"}};
  }
  return json_res["result"];
}

auto CloudflareDDNS::updateDnsRecord(std::string_view new_ip)
    -> std::expected<void, Error> {
  auto record_res = getDnsRecord();
  if (!record_res) {
    return std::unexpected(record_res.error());
  }

  const auto& record = *record_res;
  std::string current_ip = record.value("content", "");
  if (current_ip == new_ip) {
    return {};
  }

  LOG_INFO(std::format("Update DNS: {} -> {}", current_ip, new_ip));
  nlohmann::json payload;
  payload["type"] = record.value("type", "A");
  payload["name"] = record.value("name", "");
  payload["content"] = new_ip;
  payload["ttl"] = record.value("ttl", 1);
  payload["proxied"] = record.value("proxied", false);

  std::string path = std::format("/zones/{}/dns_records/{}", config_.zone_id,
                                 config_.dns_record_id);
  std::string body = payload.dump();
  {
    std::scoped_lock lock{client_mutex_};
    auto res = cf_client_->Put(path, body, "application/json");
    CHECK_HTTP_RESULT(res, "Update DNS record");
    auto json_res = nlohmann::json::parse(res->body, nullptr, false);
    if (json_res.is_discarded() || !json_res.value("success", false)) {
      LOG_ERROR("Cloudflare API PUT error");
      return std::unexpected{Error{.message = "Cloudflare API error on PUT"}};
    }
  }
  return {};
}

auto CloudflareDDNS::run() -> std::expected<void, Error> {
  LOG_INFO("DDNS run start");
  return getPublicIp().and_then(
      [this](const std::string& current_ip) -> std::expected<void, Error> {
        auto last_ip_res = readLastIp();
        if (last_ip_res && *last_ip_res == current_ip) {
          LOG_INFO("IP unchanged");
          return {};
        }
        LOG_INFO("IP changed");
        auto res = updateDnsRecord(current_ip);
        if (!res) {
          return std::unexpected(res.error());
        }
        return writeCurrentIp(current_ip);
      });
}
}  // namespace cfd
