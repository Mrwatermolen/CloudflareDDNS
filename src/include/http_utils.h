#ifndef __CLOUDFLARE_DDNS_HTTP_UTILS_H__
#define __CLOUDFLARE_DDNS_HTTP_UTILS_H__

#include <expected>
#include <format>
#include <memory>
#include <string>
#include <string_view>
#include <swsc/status_code.hpp>
#include <utility>

#include "common.h"
#include "logger.h"

namespace cfd {

template <typename HttpResponse>
auto ensureSuccessStatus(const std::shared_ptr<HttpResponse>& res,
                         std::string_view operation)
    -> std::expected<void, Error> {
  if (!res) {
    auto err_msg = std::format("{}: network error (no response)", operation);
    LOG_ERROR(err_msg);
    return std::unexpected{Error{.message = std::move(err_msg)}};
  }

  if (SimpleWeb::status_code(res->status_code) !=
      SimpleWeb::StatusCode::success_ok) {
    auto err_msg = std::format("{}: request failed, status: {}", operation,
                               res->status_code);
    LOG_ERROR(err_msg);
    return std::unexpected{Error{.message = std::move(err_msg)}};
  }

  return {};
}

inline auto trimCopy(std::string value) -> std::string {
  value.erase(0, value.find_first_not_of(" \n\r\t"));
  value.erase(value.find_last_not_of(" \n\r\t") + 1);
  return value;
}

inline auto urlEncode(std::string_view value) -> std::string {
  std::string encoded;
  encoded.reserve(value.size());
  for (const auto c : value) {
    if ((std::isalnum(static_cast<unsigned char>(c)) != 0) || c == '-' ||
        c == '_' || c == '.' || c == '~') {
      encoded.push_back(c);
    } else {
      encoded += std::format("%{:02X}", static_cast<unsigned char>(c));
    }
  }
  return encoded;
}

inline auto encodeFormBody(
    const std::initializer_list<std::pair<std::string_view, std::string_view>>&
        fields) -> std::string {
  std::string body;
  bool first = true;
  for (const auto& [key, value] : fields) {
    if (!first) {
      body.push_back('&');
    }
    first = false;
    body += urlEncode(key);
    body.push_back('=');
    body += urlEncode(value);
  }
  return body;
}

}  // namespace cfd

#endif  // __CLOUDFLARE_DDNS_HTTP_UTILS_H__
