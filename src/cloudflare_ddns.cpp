#include "cloudflare_ddns.h"

#include <expected>
#include <format>
#include <fstream>
#include <mutex>
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "common.h"
#include "http_utils.h"
#include "logger.h"

namespace cfd {

using HttpsClient = SimpleWeb::Client<SimpleWeb::HTTPS>;
using HttpResponse = HttpsClient::Response;

static auto makeCloudflareHeadersGlobalApi(std::string_view email,
                                           std::string_view api_key)
    -> SimpleWeb::CaseInsensitiveMultimap {
  SimpleWeb::CaseInsensitiveMultimap headers;
  headers.emplace("X-Auth-Email", std::string{email});
  headers.emplace("X-Auth-Key", std::string{api_key});
  headers.emplace("Content-Type", "application/json");
  return headers;
}

CloudflareDDNS::CloudflareDDNS(
    Config config, std::shared_ptr<SimpleWeb::io_context> io_context)
    : config_(std::move(config)),
      io_context_(std::move(io_context)),
      cf_client_{std::make_unique<HttpsClient>("api.cloudflare.com")} {
  if (io_context_) {
    cf_client_->io_service = io_context_;
  } else {
    LOG_DEBUG("No io_context provided, using internal");
    io_context_ = std::make_shared<SimpleWeb::io_context>();
    cf_client_->io_service = io_context_;
  }
  cf_client_->config.timeout_connect = 10;
  cf_client_->config.timeout = 10;
}

CloudflareDDNS::~CloudflareDDNS() = default;

auto CloudflareDDNS::addIpResolver(std::shared_ptr<IpResolver> resolver)
    -> void {
  resolvers_.push_back(std::move(resolver));
}

auto CloudflareDDNS::getPublicIp() -> std::expected<std::string, Error> {
  LOG_DEBUG("Resolving public IP");
  for (const auto& resolver : resolvers_) {
    if (!resolver) {
      LOG_WARN("Null IP resolver");
      continue;
    }
    auto ip_res = resolver->resolve();
    if (ip_res) {
      const std::string& ip = *ip_res;
      LOG_INFO(std::format("Public IP resolved: {}", ip));
      return ip;
    }
    LOG_WARN(std::format("IP resolver failed: {}", ip_res.error().message));
  }

  return std::unexpected{Error{.message = "All IP resolvers failed"}};
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
    ip = trimCopy(std::move(ip));
    if (validateIpv4(ip)) {
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
  auto headers = makeCloudflareHeadersGlobalApi(config_.email, config_.api_key);

  std::shared_ptr<HttpResponse> res;
  std::scoped_lock lock{client_mutex_};
  try {
    res = cf_client_->request("GET", path, "", headers);
  } catch (const std::exception& e) {
    auto err_msg = std::format("Get DNS record: network error: {}", e.what());
    LOG_ERROR(err_msg);
    return std::unexpected{Error{.message = std::move(err_msg)}};
  }

  if (auto status = ensureSuccessStatus(res, "Get DNS record"); !status) {
    return std::unexpected{status.error()};
  }

  auto json_res = nlohmann::json::parse(res->content.string(), nullptr, false);
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

  std::string path = std::format("/client/v4/zones/{}/dns_records/{}",
                                 config_.zone_id, config_.dns_record_id);
  std::string body = payload.dump();
  auto headers = makeCloudflareHeadersGlobalApi(config_.email, config_.api_key);

  {
    std::shared_ptr<HttpResponse> res;
    std::scoped_lock lock{client_mutex_};
    try {
      res = cf_client_->request("PUT", path, body, headers);
    } catch (const std::exception& e) {
      auto err_msg =
          std::format("Update DNS record: network error: {}", e.what());
      LOG_ERROR(err_msg);
      return std::unexpected{Error{.message = std::move(err_msg)}};
    }

    if (auto status = ensureSuccessStatus(res, "Update DNS record"); !status) {
      return std::unexpected{status.error()};
    }

    auto json_res =
        nlohmann::json::parse(res->content.string(), nullptr, false);
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

auto CloudflareDDNS::runAsync(
    std::function<void(std::expected<void, Error>)> callback) -> void {
  getpublicIpAsync([this, callback = std::move(callback)](
                       std::expected<std::string, Error> res) {
    if (!res) {
      callback(std::unexpected{res.error()});
      return;
    }
    const std::string& current_ip = *res;
    auto last_ip_res = readLastIp();

    if (last_ip_res && *last_ip_res == current_ip) {
      LOG_INFO("IP unchanged");
      callback({});
      return;
    }
    LOG_INFO("IP changed");
    updateDnsRecordAsync(current_ip,
                         [this, current_ip, callback = callback](
                             std::expected<void, Error> update_res) {
                           if (!update_res) {
                             callback(std::unexpected{update_res.error()});
                             return;
                           }
                           auto res = writeCurrentIp(current_ip);
                           if (!res) {
                             callback(std::unexpected(res.error()));
                             return;
                           }
                           callback({});
                         });
  });

  LOG_DEBUG("Starting IO context loop");
  io_context_->run();
  LOG_DEBUG("IO context loop ended");
}

auto CloudflareDDNS::getpublicIpAsync(
    std::function<void(std::expected<std::string, Error>)> callback) -> void {
  for (const auto& resolver : resolvers_) {
    if (!resolver) {
      LOG_WARN("Null IP resolver");
      continue;
    }

    resolver->resolveAsync(
        [callback = std::move(callback)](
            std::expected<std::string, Error> ip_res) mutable {
          callback(std::move(ip_res));
        });
    return;
  }

  callback(std::unexpected{Error{.message = "All IP resolvers failed"}});
}

auto CloudflareDDNS::updateDnsRecordAsync(
    std::string_view new_ip,
    std::function<void(std::expected<void, Error>)> callback) -> void {
  // TODO(franzero):
  callback(updateDnsRecord(new_ip));
}

}  // namespace cfd
