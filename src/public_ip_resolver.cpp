#include "public_ip_resolver.h"

#include <atomic>
#include <format>
#include <memory>
#include <mutex>
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
    ip_services_ = {"https://api.ip.sb/ip", "https://ipv4.icanhazip.com/",
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
  struct ServiceRequest {
    std::string host;
    ParsedHttpRequest req;
  };

  std::vector<ServiceRequest> services;
  services.reserve(ip_services_.size());
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

    services.push_back(ServiceRequest{.host = host, .req = req});
  }

  if (services.empty()) {
    callback(std::unexpected{Error{.message = "All IP services failed"}});
    return;
  }

  auto done = std::make_shared<std::atomic_bool>(false);
  auto pending = std::make_shared<std::atomic_size_t>(services.size());
  auto last_error =
      std::make_shared<Error>(Error{.message = "All IP services failed"});
  auto error_mutex = std::make_shared<std::mutex>();
  auto shared_callback =
      std::make_shared<std::function<void(std::expected<std::string, Error>)>>(
          std::move(callback));

  for (const auto& service : services) {
    const auto& host = service.host;
    const auto& req = service.req;
    LOG_DEBUG(std::format("Querying IP service: {}", req.host));
    auto client = std::make_shared<HttpsClient>(req.host, true);
    client->config.timeout_connect = 5;
    client->config.timeout = 5;
    client->io_service = io_context_;

    client->request(
        "GET", req.target,
        [host, done, pending, last_error, error_mutex, shared_callback,
         client = client](auto&& res, auto&& err) {
          if (err) {
            LOG_WARN(std::format("Get IP from service {} failed: {}", host,
                                 err.message()));
            std::scoped_lock lock(*error_mutex);
            *last_error = Error{.message = err.message()};
          } else if (auto status = ensureSuccessStatus(
                         res, std::format("Get IP from service {}", host));
                     !status) {
            std::scoped_lock lock(*error_mutex);
            *last_error = status.error();
          } else {
            std::string ip = trimCopy(res->content.string());
            if (!validateIpv4(ip)) {
              LOG_WARN(std::format("Invalid IP format from service {}: {}",
                                   host, ip));
              std::scoped_lock lock(*error_mutex);
              *last_error = Error{.message = "Invalid IP format"};
            } else {
              LOG_INFO(std::format("Public IP from service {}: {}", host, ip));
              bool expected = false;
              if (done->compare_exchange_strong(expected, true,
                                                std::memory_order_acq_rel)) {
                (*shared_callback)(std::move(ip));
              }
            }
          }

          const auto remain = pending->fetch_sub(1, std::memory_order_acq_rel);
          if (remain == 1) {
            bool expected = false;
            if (done->compare_exchange_strong(expected, true,
                                              std::memory_order_acq_rel)) {
              (*shared_callback)(std::unexpected{*last_error});
            }
          }
        });
  }
}

}  // namespace cfd
