#include <cstdlib>
#include <expected>
#include <filesystem>
#include <format>
#include <fstream>
#include <iostream>
#include <memory>
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>

#include "cloudflare_ddns.h"
#include "logger.h"
#include "miwifi.h"

namespace {
struct AppConfig {
  std::string miwifi_host;
  std::string miwifi_username;
  std::string miwifi_password;
  std::string cf_email;
  std::string cf_api_key;
  std::string cf_zone_id;
  std::string cf_dns_record_id;
  std::filesystem::path ip_file;
};

auto printUsage(std::string_view program_name) -> void {
  std::cerr << std::format(
      "Usage: {} [OPTIONS]\n"
      "Options:\n"
      "  --config <path>    Path to JSON config file (required)\n"
      "  --help             Show this help message\n",
      program_name);
}

auto loadConfigFromFile(const std::filesystem::path& config_path)
    -> std::expected<AppConfig, std::string> {
  LOG_DEBUG(std::format("Loading config: {}", config_path.string()));
  if (!std::filesystem::exists(config_path)) {
    LOG_ERROR(std::format("Config not found: {}", config_path.string()));
    return std::unexpected{
        std::format("Config file not found: {}", config_path.string())};
  }
  try {
    std::ifstream file(config_path);
    if (!file) {
      LOG_ERROR(std::format("Failed to open config: {}", config_path.string()));
      return std::unexpected{
          std::format("Failed to open config file: {}", config_path.string())};
    }
    auto json = nlohmann::json::parse(file, nullptr, false);
    if (json.is_discarded()) {
      LOG_ERROR("Invalid JSON config");
      return std::unexpected{"Invalid JSON in config file"};
    }
    AppConfig config;
    auto get_nested_string =
        [&json](
            std::string_view section, std::string_view key,
            bool required = true) -> std::expected<std::string, std::string> {
      if (!json.contains(section.data())) {
        if (required) {
          return std::unexpected{std::format("Missing section: {}", section)};
        }
        return std::string{};
      }
      const auto& section_obj = json[section.data()];
      if (!section_obj.is_object()) {
        return std::unexpected{
            std::format("Section '{}' must be object", section)};
      }
      if (!section_obj.contains(key.data())) {
        if (required) {
          return std::unexpected{
              std::format("Missing field: {}.{}", section, key)};
        }
        return std::string{};
      }
      const auto& val = section_obj[key.data()];
      if (!val.is_string()) {
        return std::unexpected{
            std::format("Field '{}.{}' must be string", section, key)};
      }
      return val.get<std::string>();
    };

    auto host_res = get_nested_string("MiWiFi", "host");
    if (!host_res) {
      return std::unexpected(host_res.error());
    }
    config.miwifi_host = std::move(*host_res);

    auto username_res = get_nested_string("MiWiFi", "username");
    if (!username_res) {
      return std::unexpected(username_res.error());
    }
    config.miwifi_username = std::move(*username_res);

    auto password_res = get_nested_string("MiWiFi", "password");
    if (!password_res) {
      return std::unexpected(password_res.error());
    }
    config.miwifi_password = std::move(*password_res);

    auto email_res = get_nested_string("cloudflare", "email");
    if (!email_res) {
      return std::unexpected(email_res.error());
    }
    config.cf_email = std::move(*email_res);

    auto api_key_res = get_nested_string("cloudflare", "api_key");
    if (!api_key_res) {
      return std::unexpected(api_key_res.error());
    }
    config.cf_api_key = std::move(*api_key_res);

    auto zone_res = get_nested_string("cloudflare", "zone_id");
    if (!zone_res) {
      return std::unexpected(zone_res.error());
    }
    config.cf_zone_id = std::move(*zone_res);

    auto record_res = get_nested_string("cloudflare", "dns_record_id");
    if (!record_res) {
      return std::unexpected(record_res.error());
    }
    config.cf_dns_record_id = std::move(*record_res);

    auto ip_file_res = get_nested_string("cloudflare", "ip_file", false);
    if (ip_file_res && !ip_file_res->empty()) {
      config.ip_file = std::move(*ip_file_res);
    } else {
      config.ip_file = "/tmp/ddns-ip.txt";
    }
    LOG_INFO("Config loaded");
    return config;
  } catch (const std::exception& e) {
    LOG_ERROR(std::format("Config parse error: {}", e.what()));
    return std::unexpected{std::format("Error parsing config: {}", e.what())};
  }
}

auto parseArgs(int argc, char* argv[])
    -> std::expected<std::filesystem::path, std::string> {
  std::filesystem::path config_path;
  for (int i = 1; i < argc; ++i) {
    std::string_view arg = argv[i];
    if (arg == "--help") {
      return std::unexpected{"help_requested"};
    }
    if (arg == "--config") {
      if (i + 1 >= argc) {
        return std::unexpected{"Missing value for --config"};
      }
      config_path = argv[++i];
      LOG_DEBUG(std::format("Config arg: {}", config_path.string()));
    } else {
      return std::unexpected{std::format("Unknown option: {}", arg)};
    }
  }
  if (config_path.empty()) {
    return std::unexpected{"Missing required option: --config"};
  }
  return config_path;
}
}  // namespace

auto main(int argc, char* argv[]) -> int {
  LOG_INFO("DDNS Service Start");

  auto config_path_res = parseArgs(argc, argv);
  if (!config_path_res) {
    if (config_path_res.error() == "help_requested") {
      printUsage(argv[0]);
      return EXIT_SUCCESS;
    }
    LOG_ERROR(std::format("Arg error: {}", config_path_res.error()));
    printUsage(argv[0]);
    return EXIT_FAILURE;
  }

  auto config_res = loadConfigFromFile(*config_path_res);
  if (!config_res) {
    LOG_ERROR(std::format("Config error: {}", config_res.error()));
    return EXIT_FAILURE;
  }
  const auto& config = *config_res;

  auto miwifi = std::make_shared<cfd::MiWiFi>(config.miwifi_host);
  auto login_res =
      miwifi->login(config.miwifi_username, config.miwifi_password);
  if (!login_res) {
    LOG_ERROR(
        std::format("MiWiFi login failed: {}", login_res.error().message));
    return EXIT_FAILURE;
  }

  cfd::CloudflareDDNS::Config cf_config{
      .email = config.cf_email,
      .api_key = config.cf_api_key,
      .zone_id = config.cf_zone_id,
      .dns_record_id = config.cf_dns_record_id,
      .ip_file = config.ip_file,
  };
  auto ddns = std::make_unique<cfd::CloudflareDDNS>(cf_config);
  ddns->setMiwifi(miwifi);

  auto result = ddns->run();
  if (!result) {
    LOG_ERROR(std::format("DDNS run failed: {}", result.error().message));
    return EXIT_FAILURE;
  }

  LOG_INFO("DDNS Service End");
  return EXIT_SUCCESS;
}
