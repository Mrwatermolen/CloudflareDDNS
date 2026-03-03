#ifndef __CLOUDFLARE_DDNS_PUBLIC_IP_RESOLVER_H__
#define __CLOUDFLARE_DDNS_PUBLIC_IP_RESOLVER_H__

#include <expected>
#include <string>
#include <vector>

#include "common.h"

namespace cfd {

class PublicIpResolver {
 public:
  explicit PublicIpResolver(std::vector<std::string> services = {});

  auto resolve() const -> std::expected<std::string, Error>;

 private:
  std::vector<std::string> ip_services_;
};

}  // namespace cfd

#endif  // __CLOUDFLARE_DDNS_PUBLIC_IP_RESOLVER_H__
