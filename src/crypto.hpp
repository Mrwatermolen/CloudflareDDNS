#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <array>
#include <cstring>
#include <expected>
#include <memory>
#include <print>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace crypto {

inline constexpr bool DEBUG_MODE = false;

// Constants
inline constexpr std::size_t AES_KEY_SIZE = 32;    // 256-bit key for AES-256
inline constexpr std::size_t AES_BLOCK_SIZE = 16;  // AES block size in bytes
inline constexpr std::size_t IV_SIZE = 16;         // IV size for CBC mode
inline constexpr std::size_t KEY_HEX_LENGTH =
    64;  // 32 bytes = 64 hex characters

[[nodiscard]] constexpr std::string toHexByte(unsigned char byte) {
  constexpr char hex_digits[] = "0123456789abcdef";
  return std::string{hex_digits[byte >> 4], hex_digits[byte & 0x0F]};
}

[[nodiscard]] std::string stringToHex(std::string_view input) {
  std::string result;
  result.reserve(input.size() * 2);
  for (unsigned char c : input) {
    result += toHexByte(c);
  }
  return result;
}

[[nodiscard]] std::string bytesToHex(std::span<const unsigned char> bytes) {
  std::string result;
  result.reserve(bytes.size() * 2);
  for (unsigned char byte : bytes) {
    result += toHexByte(byte);
  }
  return result;
}

void printHex(std::string_view label, std::span<const unsigned char> bytes) {
  if constexpr (DEBUG_MODE) {
    std::print("[DEBUG] {}: {}\n", label, bytesToHex(bytes));
  }
}

[[nodiscard]] std::array<unsigned char, AES_KEY_SIZE> deriveKeyFromPassword(
    std::string_view password) {
  // Convert password to hex representation
  std::string key_hex = stringToHex(password);

  // Truncate or pad to KEY_HEX_LENGTH (64 characters = 32 bytes)
  if (key_hex.length() > KEY_HEX_LENGTH) {
    key_hex = key_hex.substr(0, KEY_HEX_LENGTH);
  } else {
    key_hex.append(KEY_HEX_LENGTH - key_hex.length(), '0');
  }

  // Convert hex string to byte array
  std::array<unsigned char, AES_KEY_SIZE> key{};
  for (std::size_t i = 0; i < AES_KEY_SIZE; ++i) {
    std::string byte_str = key_hex.substr(i * 2, 2);
    key[i] = static_cast<unsigned char>(std::stoi(byte_str, nullptr, 16));
  }

  if constexpr (DEBUG_MODE) {
    std::print("[KeyDerive] Input password: \"{}\"\n", password);
    std::print("[KeyDerive] Raw hex: {}\n", stringToHex(password));
    std::print("[KeyDerive] Padded/Truncated key_hex: {}\n", key_hex);
    printHex("[KeyDerive] Final key (bytes)", key);
  }

  return key;
}

[[nodiscard]] std::expected<std::array<unsigned char, IV_SIZE>, std::string>
generateRandomIv() {
  std::array<unsigned char, IV_SIZE> iv{};

  if (RAND_bytes(iv.data(), static_cast<int>(iv.size())) != 1) {
    auto err = ERR_get_error();
    return std::unexpected{ERR_error_string(err, nullptr)};
  }

  if constexpr (DEBUG_MODE) {
    printHex("[IV] Generated random IV", iv);
    std::print("[IV] Python:\n");
    std::print("    iv = bytes.fromhex(\"{}\")\n", bytesToHex(iv));
  }

  return iv;
}

// AES-CBC encryption using OpenSSL EVP API
[[nodiscard]] std::expected<std::string, std::string> aesCbcEncrypt(
    std::string_view plaintext,
    std::span<const unsigned char, AES_KEY_SIZE> key,
    std::span<const unsigned char, IV_SIZE> iv) {
  if constexpr (DEBUG_MODE) {
    std::print("[Encrypt] Starting AES-256-CBC encryption\n");
    std::print("[Encrypt] Plaintext: \"{}\"\n", plaintext);
    std::print("[Encrypt] Plaintext (hex): {}\n", stringToHex(plaintext));
    printHex("[Encrypt] Key", key);
    printHex("[Encrypt] IV", iv);
  }
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (ctx == nullptr) {
    return std::unexpected{"Failed to create cipher context"};
  }

  // Cleanup RAII wrapper
  auto cleanup = [](EVP_CIPHER_CTX* c) { EVP_CIPHER_CTX_free(c); };
  std::unique_ptr<EVP_CIPHER_CTX, decltype(cleanup)> ctx_guard(ctx, cleanup);

  // Initialize encryption operation
  if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(),
                         iv.data()) != 1) {
    auto err = ERR_get_error();
    return std::unexpected{ERR_error_string(err, nullptr)};
  }

  // Buffer for ciphertext
  std::vector<unsigned char> ciphertext;
  ciphertext.resize(plaintext.size() +
                    AES_BLOCK_SIZE);  // Max size with padding

  int len{};
  int ciphertext_len{};

  // Encrypt plaintext
  if (EVP_EncryptUpdate(
          ctx, ciphertext.data(), &len,
          reinterpret_cast<const unsigned char*>(plaintext.data()),
          static_cast<int>(plaintext.size())) != 1) {
    auto err = ERR_get_error();
    return std::unexpected{ERR_error_string(err, nullptr)};
  }
  ciphertext_len = len;

  // Finalize encryption (handles padding)
  if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
    auto err = ERR_get_error();
    return std::unexpected{ERR_error_string(err, nullptr)};
  }
  ciphertext_len += len;

  if constexpr (DEBUG_MODE) {
    printHex("[Encrypt] Raw ciphertext", ciphertext);
    std::print("[Encrypt] Ciphertext length: {} bytes\n", ciphertext.size());
  }

  // Resize to actual length
  ciphertext.resize(static_cast<std::size_t>(ciphertext_len));

  // Convert IV to hex and ciphertext to base64, then concatenate
  std::string iv_hex = bytesToHex(iv);
  std::string ciphertext_hex = bytesToHex(ciphertext);

  if constexpr (DEBUG_MODE) {
    std::print("[Output] IV (hex): {}\n", iv_hex);
    std::print("[Output] Ciphertext (hex): {}\n", ciphertext_hex);
    std::print("[Output] Final result (IV+ciphertext): {}\n",
               iv_hex + ciphertext_hex);

    std::print("[Python Copy-Paste]\n");
    std::print("    \n");
    std::print("    iv = bytes.fromhex(\"{}\")\n", iv_hex);
    std::print("    expected_output = \"{}\"\n", iv_hex + ciphertext_hex);
  }

  return iv_hex + ciphertext_hex;
}

// Unionman's encryption method that combines all steps

/**
 * @brief Unionman's encryption method. Step 1: Derive a 256-bit key from the
 * password using the custom method Step 2: Generate a random 16-byte IV Step 3:
 * Perform AES-256-CBC encryption with PKCS#7 padding
 *
 * @param password
 * @param iv Optional IV (if not provided, a random one will be generated)
 * @return std::expected<std::string, std::string>
 */
[[nodiscard]] std::expected<std::string, std::string> unionmanEncryptPassword(
    std::string_view password, std::string_view iv = "") {
  auto key = deriveKeyFromPassword(password);
  if (iv.empty()) {
    return generateRandomIv().and_then(
        [&](auto iv) { return aesCbcEncrypt(password, key, iv); });
  }

  if (iv.length() != IV_SIZE * 2) {
    return std::unexpected{"Invalid IV length"};
  }

  std::array<unsigned char, IV_SIZE> iv_bytes{};
  for (std::size_t i = 0; i < IV_SIZE; ++i) {
    auto byte_str = iv.substr(i * 2, 2);
    iv_bytes[i] = static_cast<unsigned char>(
        std::stoi(std::string(byte_str), nullptr, 16));
  }

  return aesCbcEncrypt(password, key, iv_bytes);
}

/**
 * @brief MiWiFi's original encryption method. Step 1: Compute SHA-1 hash of
 * (password + key) Step 2: Compute SHA-1 hash of (nonce + first_hash)
 *
 * @param password
 * @param key
 * @param nonce
 * @return std::string
 */
[[nodiscard]] std::string miwifiEncryptPassword(std::string_view password,
                                                std::string_view key,
                                                std::string_view nonce) {
  auto sha1_hex = [](std::string_view input) {
    std::array<unsigned char, SHA_DIGEST_LENGTH> hash{};
    SHA1(reinterpret_cast<const unsigned char*>(input.data()), input.length(),
         hash.data());
    return bytesToHex(hash);
  };

  auto first_hash = sha1_hex(std::string(password) + std::string(key));
  return sha1_hex(std::string(nonce) + first_hash);
}

}  // namespace crypto
