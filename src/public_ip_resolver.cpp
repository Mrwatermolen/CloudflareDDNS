#include "public_ip_resolver.h"

#include <format>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

#include "http_utils.h"
#include "swsc/client_https.hpp"

namespace cfd {

struct ParsedHttpRequest {
  std::string scheme;
  std::string host;
  std::string target;
};

static auto parseUrlToHttpRequest(std::string_view url)
    -> std::expected<ParsedHttpRequest, Error> {
  if (url.empty()) {
    return std::unexpected{Error{.message = "Empty url"}};
  }

  ParsedHttpRequest req;
  std::string_view rest = url;

  if (rest.starts_with("https://")) {
    req.scheme = "https";
    rest.remove_prefix(std::string_view{"https://"}.size());
  } else if (rest.starts_with("http://")) {
    req.scheme = "http";
    rest.remove_prefix(std::string_view{"http://"}.size());
  } else {
    req.scheme = "https";
  }

  const auto slash_pos = rest.find('/');
  if (slash_pos == std::string_view::npos) {
    req.host = std::string{rest};
    req.target = "/";
  } else {
    req.host = std::string{rest.substr(0, slash_pos)};
    req.target = std::string{rest.substr(slash_pos)};
    if (req.target.empty()) {
      req.target = "/";
    }
  }

  if (req.host.empty()) {
    return std::unexpected{Error{.message = "Invalid url host"}};
  }

  return req;
}

using HttpsClient = SimpleWeb::Client<SimpleWeb::HTTPS>;
using HttpsResponse = HttpsClient::Response;
using HttpResponse = HttpsResponse;
using HttpClient = SimpleWeb::Client<SimpleWeb::HTTP>;

PublicIpResolver::PublicIpResolver(
    std::vector<std::string> services,
    std::shared_ptr<SimpleWeb::io_context> io_context)
    : ip_services_(std::move(services)), io_context_{std::move(io_context)} {
  if (ip_services_.empty()) {
    ip_services_ = {"https://ip.sb/ip", "https://ipv4.icanhazip.com/",
                    "https://ifconfig.me/ip"};
  }
}

auto PublicIpResolver::resolve() const -> std::expected<std::string, Error> {
  for (const auto& host : ip_services_) {
    const auto req_res = parseUrlToHttpRequest(host);
    if (!req_res) {
      LOG_WARN(std::format("Invalid IP service URL {}: {}", host,
                           req_res.error().message));
      continue;
    }
    const auto& req = *req_res;
    if (req.scheme == "http") {
      LOG_ERROR(std::format("Insecure IP service URL (http): {}", host));
      continue;
    }
    HttpsClient service_client(req.host, true);
    service_client.config.timeout_connect = 5;
    service_client.config.timeout = 5;
    LOG_DEBUG(std::format("Querying IP service: {}", req.host));

    std::shared_ptr<HttpResponse> res;
    try {
      res = service_client.request("GET", req.target);
    } catch (const std::exception& e) {
      LOG_WARN(
          std::format("Get IP from service {} failed: {}", host, e.what()));
      continue;
    }

    if (auto status = ensureSuccessStatus(
            res, std::format("Get IP from service {}", host));
        !status) {
      continue;
    }

    std::string ip = trimCopy(res->content.string());
    if (!validateIpv4(ip)) {
      LOG_WARN(std::format("Invalid IP format from service {}: {}", host, ip));
      continue;
    }
    LOG_INFO(std::format("Public IP from service {}: {}", host, ip));
    return ip;
  }
  LOG_ERROR("All external IP services failed");
  return std::unexpected{Error{.message = "All IP services failed"}};
}

auto PublicIpResolver::resolveAsync(
    std::function<void(std::expected<std::string, Error>)> callback) const
    -> void {
  for (const auto& host : ip_services_) {
    const auto req_res = parseUrlToHttpRequest(host);
    if (!req_res) {
      LOG_WARN(std::format("Invalid IP service URL {}: {}", host,
                           req_res.error().message));
      continue;
    }
    const auto& req = *req_res;
    if (req.scheme == "http") {
      LOG_ERROR(std::format("Insecure IP service URL (http): {}", host));
      continue;
    }
    LOG_DEBUG(std::format("Querying IP service: {}", req.host));
    auto client = std::make_shared<HttpsClient>(req.host, true);
    client->config.timeout_connect = 5;
    client->config.timeout = 5;
    client->io_service = io_context_;

    client->request(
        "GET", req.target,
        [host, callback = std::move(callback), client = client](auto&& res,
                                                                auto&& err) {
          if (err) {
            LOG_WARN(std::format("Get IP from service {} failed: {}", host,
                                 err.message()));
            callback(std::unexpected{Error{.message = err.message()}});
            return;
          }
          if (auto status = ensureSuccessStatus(
                  res, std::format("Get IP from service {}", host));
              !status) {
            callback(std::unexpected{status.error()});
            return;
          }

          std::string ip = trimCopy(res->content.string());
          if (!validateIpv4(ip)) {
            LOG_WARN(
                std::format("Invalid IP format from service {}: {}", host, ip));
            callback(std::unexpected{Error{.message = "Invalid IP format"}});
            return;
          }
          LOG_INFO(std::format("Public IP from service {}: {}", host, ip));
          callback(ip);
        });
  }
}

}  // namespace cfd
