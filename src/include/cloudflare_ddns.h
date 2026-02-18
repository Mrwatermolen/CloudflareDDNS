#ifndef __CLOUDFLARE_DDNS_CLOUDFLARE_DDNS_H__
#define __CLOUDFLARE_DDNS_CLOUDFLARE_DDNS_H__

#include <expected>
#include <filesystem>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>

#include "common.h"

namespace httplib {
class Client;
}
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

  explicit CloudflareDDNS(Config config);
  ~CloudflareDDNS();

  CloudflareDDNS(const CloudflareDDNS&) = delete;
  CloudflareDDNS& operator=(const CloudflareDDNS&) = delete;

  void setMiwifi(std::shared_ptr<MiWiFi> miwifi);

  auto run() -> std::expected<void, Error>;

 private:
  static auto validateIp(std::string_view ip) -> bool;
  auto getPublicIp() -> std::expected<std::string, Error>;
  auto getPublicIpFromServices() -> std::expected<std::string, Error>;

  auto readLastIp() -> std::expected<std::string, Error>;
  auto writeCurrentIp(std::string_view ip) -> std::expected<void, Error>;

  auto getDnsRecord() -> std::expected<nlohmann::json, Error>;
  auto updateDnsRecord(std::string_view new_ip) -> std::expected<void, Error>;

  Config config_;
  std::shared_ptr<MiWiFi> miwifi_;
  std::unique_ptr<httplib::Client> cf_client_;
  mutable std::mutex client_mutex_;
};

}  // namespace cfd

#endif  // __CLOUDFLARE_DDNS_CLOUDFLARE_DDNS_H__
