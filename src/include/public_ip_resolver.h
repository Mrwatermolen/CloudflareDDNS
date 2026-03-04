#ifndef __CLOUDFLARE_DDNS_PUBLIC_IP_RESOLVER_H__
#define __CLOUDFLARE_DDNS_PUBLIC_IP_RESOLVER_H__

#include <expected>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "common.h"
#include "swsc/asio_compatibility.hpp"

namespace cfd {

class PublicIpResolver {
 public:
  explicit PublicIpResolver(
      std::vector<std::string> services = {},
      std::shared_ptr<SimpleWeb::io_context> io_context = nullptr);

  auto resolve() const -> std::expected<std::string, Error>;

  auto resolveAsync(
      std::function<void(std::expected<std::string, Error>)> callback) const
      -> void;

 private:
  std::vector<std::string> ip_services_;
  std::shared_ptr<SimpleWeb::io_context> io_context_{nullptr};
};

}  // namespace cfd

#endif  // __CLOUDFLARE_DDNS_PUBLIC_IP_RESOLVER_H__
