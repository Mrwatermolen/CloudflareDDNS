#ifndef __CLOUDFLARE_DDNS_CLOUDFLARE_DDNS_H__
#define __CLOUDFLARE_DDNS_CLOUDFLARE_DDNS_H__

#include <expected>
#include <filesystem>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>
#include <vector>

#include "common.h"
#include "swsc/asio_compatibility.hpp"
#include "swsc/client_https.hpp"

namespace cfd {

// Forward declaration
class MiWiFi;

class CloudflareDDNS {
 public:
  struct Config {
    std::string email;
    std::string api_key;
    std::string zone_id;
    std::string dns_record_id;
    std::filesystem::path ip_file;
  };

  explicit CloudflareDDNS(
      Config config,
      std::shared_ptr<SimpleWeb::io_context> io_context = nullptr);
  ~CloudflareDDNS();

  CloudflareDDNS(const CloudflareDDNS&) = delete;
  CloudflareDDNS& operator=(const CloudflareDDNS&) = delete;

  auto addIpResolver(std::shared_ptr<IpResolver> resolver) -> void;

  auto run() -> std::expected<void, Error>;

  auto runAsync(std::function<void(std::expected<void, Error>)> callback)
      -> void;

  std::shared_ptr<SimpleWeb::io_context> io_context{nullptr};

 private:
  auto getPublicIp() -> std::expected<std::string, Error>;

  auto readLastIp() -> std::expected<std::string, Error>;
  auto writeCurrentIp(std::string_view ip) -> std::expected<void, Error>;

  auto getDnsRecord() -> std::expected<nlohmann::json, Error>;
  auto updateDnsRecord(std::string_view new_ip) -> std::expected<void, Error>;

  auto getPublicIpAsync(
      std::function<void(std::expected<std::string, Error>)> callback) -> void;

  auto getDnsRecordAsync(
      std::function<void(std::expected<nlohmann::json, Error>)> callback)
      -> void;

  auto updateDnsRecordAsync(
      std::string new_ip,
      std::function<void(std::expected<void, Error>)> callback) -> void;

  Config config_;
  std::vector<std::shared_ptr<IpResolver>> resolvers_;
  std::unique_ptr<SimpleWeb::Client<SimpleWeb::HTTPS>> cf_client_;
  mutable std::mutex client_mutex_;
};

}  // namespace cfd

#endif  // __CLOUDFLARE_DDNS_CLOUDFLARE_DDNS_H__
