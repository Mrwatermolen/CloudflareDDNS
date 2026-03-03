#include "public_ip_resolver.h"

#include <format>
#include <string>
#include <string_view>

#include "http_utils.h"
#include "swsc/client_https.hpp"

namespace cfd {

using HttpsClient = SimpleWeb::Client<SimpleWeb::HTTPS>;
using HttpResponse = HttpsClient::Response;

PublicIpResolver::PublicIpResolver(std::vector<std::string> services)
    : ip_services_(std::move(services)) {
  if (ip_services_.empty()) {
    ip_services_ = {"ip.sb", "ipv4.icanhazip.com", "ifconfig.me"};
  }
}

auto PublicIpResolver::resolve() const -> std::expected<std::string, Error> {
  LOG_DEBUG("Fetching IP from external services");
  for (const auto& host : ip_services_) {
    HttpsClient service_client(std::string{host}, true);
    service_client.config.timeout_connect = 5;
    service_client.config.timeout = 5;
    LOG_DEBUG(std::format("Querying IP service: {}", host));

    std::shared_ptr<HttpResponse> res;
    try {
      res = service_client.request("GET", "/");
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

}  // namespace cfd
