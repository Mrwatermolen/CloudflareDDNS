#include <format>
#include <iostream>
#include <print>
#include <string_view>

#include "crypto.hpp"

#if defined(USE_SWSCLIB)
#include "swsc/client_http.hpp"
#include "swsc/status_code.hpp"

using Param = std::vector<std::pair<std::string, std::string>>;

auto encodeParam(const Param& params) {
  std::string result;
  auto url_encode = [](const std::string& value) {
    std::string encoded;
    for (char c : value) {
      if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
        encoded += c;
      } else {
        encoded += '%' + std::format("{:02X}", static_cast<unsigned char>(c));
      }
    }
    return encoded;
  };
  for (const auto& [key, value] : params) {
    if (!result.empty()) {
      result += '&';
    } else {
      result += '?';
    }
    result += url_encode(key) + '=' + url_encode(value);
  }
  return result;
}

#define CHECK_HTTP_RESPONSE(res, msg)                                      \
  do {                                                                     \
    if (SimpleWeb::status_code((res)->status_code) !=                      \
        SimpleWeb::StatusCode::success_ok) {                               \
      auto __error_code =                                                  \
          static_cast<int>(SimpleWeb::status_code((res)->status_code));    \
      std::println(std::cerr, "HTTP request failed: {} (status code: {})", \
                   msg, __error_code);                                     \
      return;                                                              \
    }                                                                      \
  } while (0)
#endif

constexpr auto ROUTER_HOST = "192.168.1.1";
constexpr auto ROUTER_LOGIN_PATH = "/aoaform/web_login_exe.cgi";

auto testHttpClient(std::string_view encrypted_password) {
  std::println("Testing with unified http wrapper...");
#if defined(USE_SWSCLIB)
  using HttpClient = SimpleWeb::Client<SimpleWeb::HTTP>;
  HttpClient client{ROUTER_HOST};
  Param fields;
  fields.emplace_back("mode_name", "/aoaform/web_login_exe");
  fields.emplace_back("web_login_name", "user");
  fields.emplace_back("web_login_password", std::string(encrypted_password));

  auto res = client.request("POST", ROUTER_LOGIN_PATH, encodeParam(fields));
  CHECK_HTTP_RESPONSE(res, "Login request failed");
  std::println("Login successful, response: {}", res->content.string());
#else
  std::println("HTTP client library not defined. Skipping HTTP test.");
#endif
}

int main(int argc, char* argv[]) {
  std::string password;
  if (argc > 1) {
    password = argv[1];
  } else {
    std::println("Usage: {} <password>", argv[0]);
    return 1;
  }

  auto encrypted_result = crypto::unionmanEncryptPassword(password);
  if (!encrypted_result) {
    std::println(std::cerr, "Encryption failed: {}", encrypted_result.error());
    return 1;
  }

  std::string_view encrypted_password = encrypted_result.value();
  std::println("Encrypted password: {}", encrypted_password);
  testHttpClient(encrypted_password);
  return 0;
}