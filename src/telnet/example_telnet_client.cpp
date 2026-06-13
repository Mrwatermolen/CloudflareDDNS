#include <asio.hpp>
#include <cstdlib>
#include <format>
#include <iostream>
#include <print>
#include <ranges>
#include <string>

#include "telnet_client.hpp"

auto main(int argc, char* argv[]) -> int {
  if (argc < 2) {
    std::print("Usage: {} <host> [port]\n", argv[0]);
    return EXIT_FAILURE;
  }

  const std::string host = argv[1];
  const std::string port = argc > 2 ? argv[2] : "23";

  asio::io_context io;
  cfd::telnet::TelnetClient client(io);

  asio::co_spawn(
      io,
      [&client, host, port]() -> asio::awaitable<void> {
        auto conn_res = co_await client.connect(host, port);
        if (!conn_res) {
          std::print(std::cerr, "Connection failed: {}\n", conn_res.error());
          co_return;
        }

        std::println("Connected to {}:{}", host, port);

        while (client.isOpen()) {
          auto line_res = co_await client.readLine();
          if (!line_res) {
            std::println(std::cerr, "Read failed: {}", line_res.error());
            break;
          }

          auto char_to_binary = [](char ch) {
            if (std::isprint(static_cast<unsigned char>(ch))) {
              return std::string(1, ch);
            }
            return std::format("\\x{:02x}", static_cast<unsigned char>(ch));
          };
          std::println("#############################################");
          std::println("Received line ({} bytes)", (*line_res).length());
          std::println("Received: {}", *line_res);
          std::println("Received (binary): {}",
                       (*line_res | std::views::transform(char_to_binary) |
                        std::views::join));
          std::println("#############################################");

          // input from user and send to server
          std::string input;
          std::getline(std::cin, input);
          if (input == "exit") {
            break;
          }

          auto write_res = co_await client.writeLine(input);
          if (!write_res) {
            std::println(std::cerr, "Write failed: {}", write_res.error());
            break;
          }

          std::println("Sent: {}", input);
        }
      },
      asio::detached);

  io.run();
  return EXIT_SUCCESS;
}