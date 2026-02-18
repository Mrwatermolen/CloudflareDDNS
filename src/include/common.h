#ifndef __CLOUDFLARE_DDNS_COMMON_H__
#define __CLOUDFLARE_DDNS_COMMON_H__

#include <string>
namespace cfd {

struct Error {
  std::string message;
};

#define CHECK_HTTP_RESULT(res, msg)                                            \
  do {                                                                         \
    if (!(res)) {                                                              \
      auto __err_msg = std::format("{}: network error: {}", msg,               \
                                   httplib::to_string((res).error()));         \
      LOG_ERROR(__err_msg);                                                    \
      return std::unexpected<Error>{Error{.message = __err_msg}};              \
    }                                                                          \
    if ((res)->status != 200) {                                                \
      LOG_ERROR(std::format("{}: http status: {}", msg, (res)->status));       \
      auto __err_msg = std::format("{}: request failed, status: {}, body: {}", \
                                   msg, (res)->status, (res)->body);           \
      return std::unexpected<Error>{Error{.message = __err_msg}};              \
    }                                                                          \
  } while (0)

}  // namespace cfd

#endif  // __CLOUDFLARE_DDNS_COMMON_H__
