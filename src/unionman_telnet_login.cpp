#include <algorithm>
#include <asio.hpp>
#include <cctype>
#include <cstdlib>
#include <expected>
#include <filesystem>
#include <format>
#include <fstream>
#include <iostream>
#include <memory>
#include <nlohmann/json.hpp>
#include <print>
#include <string>
#include <string_view>

// #include "http_utils.h"
#include "swsc/client_http.hpp"
#include "swsc/status_code.hpp"
#include "telnet/telnet_client.hpp"

#define LOG_LEVEL_TRACE 4
#define LOG_LEVEL_DEBUG 3
#define LOG_LEVEL_INFO 2
#define LOG_LEVEL_WARN 1
#define LOG_LEVEL_ERROR 0

#define LOG_LEVEL LOG_LEVEL_TRACE
#define LOG_TAG "UnionmanTelnetLogin"

#define LOG(os, level, fmt, ...)                                               \
  std::println(os, "{} [{}] [{}] [{}] " fmt, std::chrono::system_clock::now(), \
               level, LOG_TAG, __func__ __VA_OPT__(, ) __VA_ARGS__)
#if LOG_LEVEL >= LOG_LEVEL_TRACE
#define LOG_TRACE(...) LOG(std::cout, "TRACE", __VA_ARGS__)
#else
#define LOG_TRACE(...) \
  do {                 \
  } while (0)
#endif
#if LOG_LEVEL >= LOG_LEVEL_DEBUG
#define LOG_DEBUG(...) LOG(std::cout, "DEBUG", __VA_ARGS__)
#else
#define LOG_DEBUG(...) \
  do {                 \
  } while (0)
#endif
#if LOG_LEVEL >= LOG_LEVEL_INFO
#define LOG_INFO(...) LOG(std::cout, "INFO", __VA_ARGS__)
#else
#define LOG_INFO(...) \
  do {                \
  } while (0)
#endif
#if LOG_LEVEL >= LOG_LEVEL_WARN
#define LOG_WARN(...) LOG(std::cout, "WARN", __VA_ARGS__)
#else
#define LOG_WARN(...) \
  do {                \
  } while (0)
#endif
#if LOG_LEVEL >= LOG_LEVEL_ERROR
#define LOG_ERROR(...) LOG(std::cerr, "ERROR", __VA_ARGS__)
#else
#define LOG_ERROR(...) \
  do {                 \
  } while (0)
#endif

namespace {

// telnet login to unionman, get super account info

struct UnionmanConfig {
  std::string host;
  std::string username;
  std::string password;
};

auto trim(std::string_view input) -> std::string_view {
  while (!input.empty() &&
         (input.back() == '\r' || input.back() == '\n' ||
          std::isspace(static_cast<unsigned char>(input.back())) != 0)) {
    input.remove_suffix(1);
  }
  while (!input.empty() &&
         std::isspace(static_cast<unsigned char>(input.front())) != 0) {
    input.remove_prefix(1);
  }
  return input;
}

auto toLower(std::string_view input) -> std::string {
  std::string output;
  std::ranges::transform(input, std::back_inserter(output),
                         [](unsigned char c) { return std::tolower(c); });
  return output;
}

auto loadUnionmanConfig(const std::filesystem::path& config_path)
    -> std::expected<UnionmanConfig, std::string> {
  if (!std::filesystem::exists(config_path)) {
    return std::unexpected(
        std::format("Config not found: {}", config_path.string()));
  }

  std::ifstream file(config_path);
  if (!file) {
    return std::unexpected(
        std::format("Failed to open config file: {}", config_path.string()));
  }

  const auto json = nlohmann::json::parse(file, nullptr, false);
  if (json.is_discarded()) {
    return std::unexpected("Invalid JSON config");
  }

  if (!json.contains("unionman") || !json["unionman"].is_object()) {
    return std::unexpected("Missing object: unionman");
  }

  const auto& section = json["unionman"];
  auto get_field =
      [&](std::string_view key) -> std::expected<std::string, std::string> {
    if (!section.contains(key.data()) || !section[key.data()].is_string()) {
      return std::unexpected(
          std::format("Missing string field: unionman.{}", key));
    }
    return section[key.data()].get<std::string>();
  };

  auto host = get_field("host");
  if (!host) {
    return std::unexpected(host.error());
  }

  auto username = get_field("username");
  if (!username) {
    return std::unexpected(username.error());
  }

  auto password = get_field("password");
  if (!password) {
    return std::unexpected(password.error());
  }

  return UnionmanConfig{.host = std::move(*host),
                        .username = std::move(*username),
                        .password = std::move(*password)};
}

auto readUntil(cfd::telnet::TelnetClient& client, char delimiter)
    -> asio::awaitable<std::expected<std::string, std::string>> {
  std::string data;
  while (true) {
    auto byte_res = co_await client.readSome();
    if (!byte_res) {
      co_return std::unexpected(byte_res.error());
    }
    const auto& bytes = *byte_res;
    data.append(bytes);
    if (bytes.back() == delimiter) {
      break;
    }
  }
  co_return data;
};

auto loginUnionman(cfd::telnet::TelnetClient& client, const UnionmanConfig& cfg)
    -> asio::awaitable<std::expected<void, std::string>> {
  auto conn = co_await client.connect(cfg.host, "23");
  if (!conn) {
    co_return std::unexpected(conn.error());
  }

  LOG_INFO("Connected to {}", cfg.host);

  bool username_sent = false;

  LOG_DEBUG("Waiting for username prompt");
  while (true) {
    auto res = co_await readUntil(client, ':');
    if (!res) {
      co_return std::unexpected(res.error());
    }

    const auto line = trim(*res);
    LOG_TRACE("Received: {}", *res);

    const auto lower_line = toLower(line);
    if (!lower_line.ends_with("login:")) {
      LOG_TRACE("Received line does not end with username/login prompt: {}",
                line);
      continue;
    }

    auto write_res = co_await client.writeLine(cfg.username);
    if (!write_res) {
      LOG_ERROR("Failed to send username: {}", write_res.error());
      co_return std::unexpected(write_res.error());
    }

    username_sent = true;
    break;
  }

  if (!username_sent) {
    co_return std::unexpected("Did not receive username prompt");
  }

  LOG_DEBUG("Username sent, waiting for password prompt");
  bool password_sent = false;
  while (true) {
    auto res = co_await readUntil(client, ':');
    if (!res) {
      co_return std::unexpected(res.error());
    }

    const auto line = trim(*res);
    LOG_TRACE("Received: {}", *res);
    const auto lower_line = toLower(line);

    if (!lower_line.ends_with("password:")) {
      LOG_TRACE("Received line does not end with password prompt: {}", line);
      continue;
    }

    auto write_res = co_await client.writeLine(cfg.password);
    if (!write_res) {
      LOG_ERROR("Failed to send password: {}", write_res.error());
      co_return std::unexpected(write_res.error());
    }
    password_sent = true;
    break;
  }

  LOG_DEBUG(
      "Completed login process. Status - username sent: {}, password sent: {}",
      username_sent, password_sent);

  if (!password_sent) {
    co_return std::unexpected("Did not receive password prompt");
  }

  co_return std::expected<void, std::string>{};
}

auto extractKeyValue(std::string_view line, std::string_view key_prefix,
                     std::string_view key_suffix)
    -> std::optional<std::string> {
  auto start_pos = line.find(key_prefix);
  if (start_pos == std::string_view::npos) {
    return std::nullopt;
  }

  auto end_pos = line.find(key_suffix, start_pos + key_prefix.length());
  if (end_pos == std::string_view::npos) {
    return std::nullopt;
  }

  auto value_start = start_pos + key_prefix.length();
  return std::string(line.substr(value_start, end_pos - value_start));
}

auto sendCommandAndExtractValue(cfd::telnet::TelnetClient& client,
                                std::string_view command,
                                std::string_view target_key,
                                std::string_view value_prefix,
                                std::string_view value_suffix)
    -> asio::awaitable<std::expected<std::string, std::string>> {
  auto res_write = co_await client.writeLine(command);
  if (!res_write) {
    co_return std::unexpected(res_write.error());
  }

  while (true) {
    auto res = co_await readUntil(client, '$');
    if (!res) {
      co_return std::unexpected(res.error());
    }

    std::string_view data_view(*res);
    auto lines = data_view | std::views::split('\n') |
                 std::views::transform([](auto&& line) {
                   return std::string_view(line.begin(), line.end());
                 });
    for (const auto& line : lines) {
      LOG_TRACE("Line: {}", line);
      if (!line.contains(target_key)) {
        LOG_TRACE("Line does not contain target: {}", target_key);
        continue;
      }
      auto value_opt = extractKeyValue(line, value_prefix, value_suffix);
      if (!value_opt) {
        LOG_TRACE(
            "Failed to extract value for key from line: {}, prefix: {}, "
            "suffix: {}",
            line, value_prefix, value_suffix);
        continue;
      }
      co_return *value_opt;
    }
  }
}

auto getSuperAccountInfo(cfd::telnet::TelnetClient& client) -> asio::awaitable<
    std::expected<std::pair<std::string, std::string>, std::string>> {
  std::string username_data;
  std::string password_data;

  constexpr std::string_view cat_super_username_cmd =
      "cat /config/workb/backup_lastgood.xml | grep "
      "aucTeleAccountName";

  constexpr std::string_view cat_super_password_cmd =
      "cat /config/workb/backup_lastgood.xml | grep "
      "aucTeleAccountPassword";

  constexpr std::string_view super_user_target = "aucTeleAccountName";
  constexpr std::string_view super_pass_target = "aucTeleAccountPassword";
  constexpr std::string_view value_prefix = "Value=\"";
  constexpr std::string_view value_suffix = "\"/>";

  LOG_DEBUG("Starting process to retrieve super account info");
  auto username_res = co_await sendCommandAndExtractValue(
      client, cat_super_username_cmd, super_user_target, value_prefix,
      value_suffix);

  auto password_res = co_await sendCommandAndExtractValue(
      client, cat_super_password_cmd, super_pass_target, value_prefix,
      value_suffix);
  if (!username_res) {
    LOG_ERROR("Failed to retrieve super username: {}", username_res.error());
    co_return std::unexpected(username_res.error());
  }
  if (!password_res) {
    LOG_ERROR("Failed to retrieve super password: {}", password_res.error());
    co_return std::unexpected(password_res.error());
  }
  username_data = *username_res;
  password_data = *password_res;

  LOG_DEBUG(
      "Retrieved super account info. Username length: {}, Password length: {}",
      username_data.size(), password_data.size());

  if (username_data.empty() || password_data.empty()) {
    co_return std::unexpected("Failed to extract super username or password");
  }

  co_return std::expected<std::pair<std::string, std::string>, std::string>{
      {std::move(username_data), std::move(password_data)}};
}

auto run(auto&& client, const auto& cfg)
    -> asio::awaitable<std::expected<void, std::string>> {
  auto login_res = co_await loginUnionman(client, cfg);
  if (!login_res) {
    co_return std::unexpected(login_res.error());
  }
  LOG_INFO("Login successful");
  auto super_info_res = co_await getSuperAccountInfo(client);
  if (!super_info_res) {
    LOG_ERROR("Failed to get super account info: {}", super_info_res.error());
    co_return std::unexpected(super_info_res.error());
  }
  const auto& [super_username, super_password] = *super_info_res;
  LOG_INFO("Super account username: {}", super_username);
  LOG_INFO("Super account password: {}", super_password);
  co_return std::expected<void, std::string>{};
}

// http request to enable telnet, then use telnet to login and get super account
// info

auto checkHttpOk(const auto& response) -> std::expected<void, std::string> {
  auto status_code_str = response->status_code;
  auto code = SimpleWeb::status_code(status_code_str);
  if (code != SimpleWeb::StatusCode::success_ok) {
    return std::unexpected(std::format(
        "HTTP request failed with status code: {}", status_code_str));
  }

  return {};
};

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

auto encodeFormBody(
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

auto openTelnet(const auto& cfg) -> std::expected<void, std::string> {
  using HttpClient = SimpleWeb::Client<SimpleWeb::HTTP>;
  using HttpResponse = HttpClient::Response;
  constexpr std::string_view unionman_enable_telnet_path =
      "/webcmcc/telnet.html";

  auto http_client = SimpleWeb::Client<SimpleWeb::HTTP>{cfg.host};
  http_client.config.timeout = 5;
  http_client.config.timeout_connect = 5;
  LOG_INFO("Enabling telnet on the device via HTTP request");
  std::shared_ptr<HttpResponse> response;
  try {
    response =
        http_client.request("GET", std::string{unionman_enable_telnet_path});
  } catch (const std::exception& e) {
    return std::unexpected(
        std::format("Failed to enable telnet: {}", e.what()));
  }

  LOG_TRACE("HTTP response status: {}, content length: {}",
            response->status_code, response->content.size());
  LOG_TRACE("HTTP response headers:");
  for ([[maybe_unused]] const auto& header : response->header) {
    LOG_TRACE("{}: {}", header.first, header.second);
  }
  LOG_TRACE("HTTP response content: {}", response->content.string());
  if (auto http_check_res = checkHttpOk(response); !http_check_res) {
    return std::unexpected(http_check_res.error());
  }

  constexpr std::string_view telnet_config_path =
      "/boaform/set_telnet_enabled_url";

  struct TelnetEnablePayload {
    std::string port = "23";
    std::string lan_enabled = "1";
    std::string wan_enabled = "0";
    std::string default_flag = "1";
    std::string mode_name;
    std::string nonedata;
  };

  {
    auto obj = TelnetEnablePayload{};
    if (obj.mode_name.empty()) {
      obj.mode_name = telnet_config_path;
      obj.nonedata = std::to_string(std::rand());
    }

    auto body = encodeFormBody({{"mode_name", obj.mode_name},
                                {"nonedata", obj.nonedata},
                                {"port", obj.port},
                                {"lan_enabled", obj.lan_enabled},
                                {"wan_enabled", obj.wan_enabled},
                                {"default_flag", obj.default_flag}});
    std::shared_ptr<HttpResponse> config_response;
    try {
      config_response = http_client.request(
          "POST", std::format("{}.cgi", telnet_config_path), body,
          {{"Content-Type", "application/x-www-form-urlencoded"},
           {"Cache-Control", "no-cache"}});
    } catch (const std::exception& e) {
      return std::unexpected(
          std::format("Failed to send telnet config request: {}", e.what()));
    }

    LOG_TRACE("Telnet config HTTP response status: {}, content length: {}",
              config_response->status_code, config_response->content.size());
    LOG_TRACE("Telnet config HTTP response headers:");
    for (const auto& header : config_response->header) {
      LOG_TRACE("{}: {}", header.first, header.second);
    }
    LOG_TRACE("Telnet config HTTP response content: {}",
              config_response->content.string());
    // to json
    if (auto http_check_res = checkHttpOk(config_response); !http_check_res) {
      return std::unexpected(http_check_res.error());
    }

    LOG_INFO("Telnet configuration updated successfully via HTTP request");
    auto json_res = nlohmann::json::parse(config_response->content.string(),
                                          nullptr, false);
    if (json_res.is_discarded() || !json_res.contains("data") ||
        !json_res["data"].contains("result") ||
        json_res["data"]["result"] != "SUCCESS") {
      LOG_ERROR("Failed to enable telnet: unexpected response content");
      return std::unexpected(
          "Failed to enable telnet: unexpected response content");
    }

    LOG_INFO("Telnet enabled successfully with response: {}",
             config_response->content.string());
  }

  return std::expected<void, std::string>{};
}

}  // namespace

auto main(int argc, char* argv[]) -> int {
  // #ifdef _WIN32
  //   SetConsoleOutputCP(CP_UTF8);
  //   SetConsoleCP(CP_UTF8);
  // #endif
  const auto config_path = argc > 1 ? std::filesystem::path(argv[1])
                                    : std::filesystem::path{"config.json"};

  auto cfg_res = loadUnionmanConfig(config_path);
  if (!cfg_res) {
    LOG_ERROR("Config error: {}", cfg_res.error());
    return EXIT_FAILURE;
  }

  bool enable_telnet = false;  // Set to false to skip telnet enabling step

  if (enable_telnet) {
    auto open_telnet_res = openTelnet(*cfg_res);
    if (!open_telnet_res) {
      LOG_ERROR("Failed to open telnet: {}", open_telnet_res.error());
      return EXIT_FAILURE;
    }
  }

  asio::io_context io;
  cfd::telnet::TelnetClient client(io);

  asio::co_spawn(
      io,
      [&client, cfg = *cfg_res]() -> asio::awaitable<void> {
        auto res = co_await run(client, cfg);
        if (!res) {
          LOG_ERROR("Error: {}", res.error());
        } else {
          LOG_INFO("Process completed successfully");
        }
      },
      asio::detached);

  io.run();
  return EXIT_SUCCESS;
}
