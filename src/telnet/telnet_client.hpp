#ifndef __CLOUDFLARE_DDNS_TELNET_CLIENT_HPP__
#define __CLOUDFLARE_DDNS_TELNET_CLIENT_HPP__

#include <array>
#include <asio.hpp>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>

namespace cfd::telnet {

enum class TelnetCommand : std::uint8_t {
  Se = 240,
  Nop = 241,
  DataMark = 242,
  Break = 243,
  InterruptProcess = 244,
  AbortOutput = 245,
  AreYouThere = 246,
  EraseCharacter = 247,
  EraseLine = 248,
  GoAhead = 249,
  Sb = 250,
  Will = 251,
  Wont = 252,
  Do = 253,
  Dont = 254,
  Iac = 255,
};

struct NegotiationPolicy {
  std::array<bool, 256> accept_remote_options{};
  std::array<bool, 256> accept_local_options{};

  static auto defaultPolicy() -> NegotiationPolicy;
};

class TelnetClient {
 public:
  explicit TelnetClient(
      asio::io_context& io,
      NegotiationPolicy policy = NegotiationPolicy::defaultPolicy());

  auto connect(std::string host, std::string service = "23")
      -> asio::awaitable<std::expected<void, std::string>>;

  auto write(std::string_view data)
      -> asio::awaitable<std::expected<std::size_t, std::string>>;

  auto writeLine(std::string_view line, std::string_view line_ending = "\r\n")
      -> asio::awaitable<std::expected<std::size_t, std::string>>;

  auto readLine(std::size_t max_bytes = 4096)
      -> asio::awaitable<std::expected<std::string, std::string>>;

  auto readSome(std::size_t max_bytes = 4096)
      -> asio::awaitable<std::expected<std::string, std::string>>;

  auto cancel() -> void;

  auto close() -> void;

  [[nodiscard]] auto isOpen() const -> bool;

 private:
  auto readRawByte()
      -> asio::awaitable<std::expected<std::uint8_t, std::string>>;

  auto readDataByte()
      -> asio::awaitable<std::expected<std::uint8_t, std::string>>;

  auto handleIac() -> asio::awaitable<
      std::expected<std::optional<std::uint8_t>, std::string>>;

  auto handleNegotiation(TelnetCommand command, std::uint8_t option)
      -> asio::awaitable<std::expected<void, std::string>>;

  auto sendNegotiation(TelnetCommand command, std::uint8_t option)
      -> asio::awaitable<std::expected<void, std::string>>;

  NegotiationPolicy policy_;
  asio::ip::tcp::resolver resolver_;
  asio::ip::tcp::socket socket_;

  std::array<std::uint8_t, 2048> raw_buffer_{};
  std::size_t raw_buffer_size_{0};
  std::size_t raw_buffer_pos_{0};
};

}  // namespace cfd::telnet

#endif  // __CLOUDFLARE_DDNS_TELNET_CLIENT_HPP__