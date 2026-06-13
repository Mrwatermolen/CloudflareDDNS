#include "telnet_client.hpp"

#include <algorithm>
#include <array>
#include <asio/as_tuple.hpp>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>

namespace cfd::telnet {

namespace {
auto toError(std::string_view prefix, const std::error_code& ec)
    -> std::string {
  return std::string(prefix) + ": " + ec.message();
}

auto toCommand(std::uint8_t code) -> TelnetCommand {
  return static_cast<TelnetCommand>(code);
}

auto asByte(TelnetCommand command) -> std::uint8_t {
  return static_cast<std::uint8_t>(command);
}

auto isNegotiationCommand(TelnetCommand command) -> bool {
  return command == TelnetCommand::Will || command == TelnetCommand::Wont ||
         command == TelnetCommand::Do || command == TelnetCommand::Dont;
}
}  // namespace

auto NegotiationPolicy::defaultPolicy() -> NegotiationPolicy {
  NegotiationPolicy policy{};
  policy.accept_remote_options[1] = true;
  policy.accept_remote_options[3] = true;
  policy.accept_local_options[3] = true;
  return policy;
}

TelnetClient::TelnetClient(asio::io_context& io, NegotiationPolicy policy)
  : policy_(policy), resolver_(io), socket_(io) {}

auto TelnetClient::connect(std::string host, std::string service)
    -> asio::awaitable<std::expected<void, std::string>> {
  auto [resolve_ec, endpoints] = co_await resolver_.async_resolve(
      std::move(host), std::move(service), asio::as_tuple(asio::use_awaitable));
  if (resolve_ec) {
    co_return std::unexpected(toError("Resolve failed", resolve_ec));
  }

  auto [connect_ec, endpoint] = co_await asio::async_connect(
      socket_, endpoints, asio::as_tuple(asio::use_awaitable));
  (void)endpoint;
  if (connect_ec) {
    co_return std::unexpected(toError("Connect failed", connect_ec));
  }

  co_return std::expected<void, std::string>{};
}

auto TelnetClient::write(std::string_view data)
    -> asio::awaitable<std::expected<std::size_t, std::string>> {
  auto [ec, written] = co_await asio::async_write(
      socket_, asio::buffer(data), asio::as_tuple(asio::use_awaitable));
  if (ec) {
    co_return std::unexpected(toError("Write failed", ec));
  }
  co_return written;
}

auto TelnetClient::writeLine(std::string_view line,
                             std::string_view line_ending)
    -> asio::awaitable<std::expected<std::size_t, std::string>> {
  auto payload = std::string(line);
  payload.append(line_ending);
  co_return co_await write(payload);
}

auto TelnetClient::readLine(std::size_t max_bytes)
    -> asio::awaitable<std::expected<std::string, std::string>> {
  std::string line;
  line.reserve(std::min<std::size_t>(max_bytes, 256));

  while (line.size() < max_bytes) {
    auto byte_res = co_await readDataByte();
    if (!byte_res) {
      co_return std::unexpected(byte_res.error());
    }

    auto ch = static_cast<char>(*byte_res);
    line.push_back(ch);
    if (ch == '\n') {
      break;
    }
  }

  co_return line;
}

auto TelnetClient::readSome(std::size_t max_bytes)
    -> asio::awaitable<std::expected<std::string, std::string>> {
  if (max_bytes == 0) {
    co_return std::string{};
  }

  std::string data;
  data.reserve(std::min<std::size_t>(max_bytes, 512));

  while (data.size() < max_bytes) {
    auto byte_res = co_await readDataByte();
    if (!byte_res) {
      if (!data.empty()) {
        co_return data;
      }
      co_return std::unexpected(byte_res.error());
    }
    data.push_back(static_cast<char>(*byte_res));

    if (raw_buffer_pos_ < raw_buffer_size_) {
      break;
    }
  }

  co_return data;
}

auto TelnetClient::cancel() -> void {
  std::error_code ec;
  const auto cancel_result = socket_.cancel(ec);
  (void)cancel_result;
}

auto TelnetClient::close() -> void {
  std::error_code ec;
  const auto shutdown_result =
      socket_.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
  const auto close_result = socket_.close(ec);
  (void)shutdown_result;
  (void)close_result;
}

auto TelnetClient::isOpen() const -> bool { return socket_.is_open(); }

auto TelnetClient::readRawByte()
    -> asio::awaitable<std::expected<std::uint8_t, std::string>> {
  if (raw_buffer_pos_ >= raw_buffer_size_) {
    auto [ec, nread] = co_await socket_.async_read_some(
        asio::buffer(raw_buffer_), asio::as_tuple(asio::use_awaitable));
    if (ec) {
      co_return std::unexpected(toError("Read failed", ec));
    }
    if (nread == 0) {
      co_return std::unexpected(std::string{"Read failed: connection closed"});
    }
    raw_buffer_pos_ = 0;
    raw_buffer_size_ = nread;
  }

  co_return raw_buffer_[raw_buffer_pos_++];
}

auto TelnetClient::readDataByte()
    -> asio::awaitable<std::expected<std::uint8_t, std::string>> {
  while (true) {
    auto byte_res = co_await readRawByte();
    if (!byte_res) {
      co_return std::unexpected(byte_res.error());
    }

    if (*byte_res != asByte(TelnetCommand::Iac)) {
      co_return *byte_res;
    }

    auto iac_res = co_await handleIac();
    if (!iac_res) {
      co_return std::unexpected(iac_res.error());
    }
    if (iac_res->has_value()) {
      co_return **iac_res;
    }
  }
}

auto TelnetClient::handleIac() -> asio::awaitable<
    std::expected<std::optional<std::uint8_t>, std::string>> {
  auto cmd_res = co_await readRawByte();
  if (!cmd_res) {
    co_return std::unexpected(cmd_res.error());
  }

  const auto command = toCommand(*cmd_res);
  if (command == TelnetCommand::Iac) {
    co_return std::optional<std::uint8_t>{asByte(TelnetCommand::Iac)};
  }

  if (isNegotiationCommand(command)) {
    auto opt_res = co_await readRawByte();
    if (!opt_res) {
      co_return std::unexpected(opt_res.error());
    }
    auto res = co_await handleNegotiation(command, *opt_res);
    if (!res) {
      co_return std::unexpected(res.error());
    }
    co_return std::optional<std::uint8_t>{};
  }

  if (command == TelnetCommand::Sb) {
    while (true) {
      auto b = co_await readRawByte();
      if (!b) {
        co_return std::unexpected(b.error());
      }
      if (*b != asByte(TelnetCommand::Iac)) {
        continue;
      }

      auto next = co_await readRawByte();
      if (!next) {
        co_return std::unexpected(next.error());
      }
      if (toCommand(*next) == TelnetCommand::Se) {
        break;
      }
      if (toCommand(*next) != TelnetCommand::Iac) {
        continue;
      }
    }
  }

  co_return std::optional<std::uint8_t>{};
}

auto TelnetClient::handleNegotiation(TelnetCommand command, std::uint8_t option)
    -> asio::awaitable<std::expected<void, std::string>> {
  switch (command) {
    case TelnetCommand::Will:
      if (policy_.accept_remote_options[option]) {
        co_return co_await sendNegotiation(TelnetCommand::Do, option);
      }
      co_return co_await sendNegotiation(TelnetCommand::Dont, option);
    case TelnetCommand::Wont:
    case TelnetCommand::Dont:
      co_return std::expected<void, std::string>{};
    case TelnetCommand::Do:
      if (policy_.accept_local_options[option]) {
        co_return co_await sendNegotiation(TelnetCommand::Will, option);
      }
      co_return co_await sendNegotiation(TelnetCommand::Wont, option);
    default:
      co_return std::expected<void, std::string>{};
  }
}

auto TelnetClient::sendNegotiation(TelnetCommand command, std::uint8_t option)
    -> asio::awaitable<std::expected<void, std::string>> {
  const std::array<std::uint8_t, 3> frame = {asByte(TelnetCommand::Iac),
                                             asByte(command), option};
  auto [ec, written] = co_await asio::async_write(
      socket_, asio::buffer(frame), asio::as_tuple(asio::use_awaitable));
  (void)written;
  if (ec) {
    co_return std::unexpected(toError("Negotiate failed", ec));
  }
  co_return std::expected<void, std::string>{};
}

}  // namespace cfd::telnet