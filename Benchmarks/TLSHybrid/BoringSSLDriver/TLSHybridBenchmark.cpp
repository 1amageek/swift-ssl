#include <openssl/bytestring.h>
#include <openssl/curve25519.h>
#include <openssl/mem.h>
#include <openssl/ssl.h>

#include "ssl/internal.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace {

enum class Operation {
  kClientOffer,
  kServerAccept,
  kRoundTrip,
  kX25519Public,
  kX25519Shared,
};

struct Measurement {
  int64_t nanoseconds;
  uint64_t checksum;
};

std::string Hex(bssl::Span<const uint8_t> bytes) {
  static constexpr char kAlphabet[] = "0123456789abcdef";
  std::string result;
  result.resize(bytes.size() * 2);
  for (size_t index = 0; index < bytes.size(); index++) {
    result[index * 2] = kAlphabet[bytes[index] >> 4];
    result[index * 2 + 1] = kAlphabet[bytes[index] & 0x0f];
  }
  return result;
}

uint8_t HexNibble(char value) {
  if (value >= '0' && value <= '9') {
    return static_cast<uint8_t>(value - '0');
  }
  if (value >= 'a' && value <= 'f') {
    return static_cast<uint8_t>(value - 'a' + 10);
  }
  throw std::runtime_error("invalid lowercase hexadecimal input");
}

std::vector<uint8_t> DecodeHex(std::string_view encoded) {
  if (encoded.size() % 2 != 0) {
    throw std::runtime_error("odd hexadecimal input length");
  }
  std::vector<uint8_t> result(encoded.size() / 2);
  for (size_t index = 0; index < result.size(); index++) {
    result[index] = static_cast<uint8_t>(
        (HexNibble(encoded[index * 2]) << 4) |
        HexNibble(encoded[index * 2 + 1]));
  }
  return result;
}

Operation ParseOperation(std::string_view value) {
  if (value == "client-offer") {
    return Operation::kClientOffer;
  }
  if (value == "server-accept") {
    return Operation::kServerAccept;
  }
  if (value == "roundtrip") {
    return Operation::kRoundTrip;
  }
  if (value == "x25519-public") {
    return Operation::kX25519Public;
  }
  if (value == "x25519-shared") {
    return Operation::kX25519Shared;
  }
  throw std::runtime_error("invalid operation");
}

std::vector<uint8_t> GenerateClientShare(
    bssl::UniquePtr<bssl::SSLKeyShare> *out_client) {
  auto client = bssl::SSLKeyShare::Create(SSL_GROUP_X25519_MLKEM768);
  if (!client) {
    throw std::runtime_error("could not create client key share");
  }
  CBB builder;
  if (!CBB_init(&builder, 1216) || !client->Generate(&builder)) {
    CBB_cleanup(&builder);
    throw std::runtime_error("could not generate client key share");
  }
  uint8_t *encoded = nullptr;
  size_t encoded_length = 0;
  if (!CBB_finish(&builder, &encoded, &encoded_length) ||
      encoded_length != 1216) {
    OPENSSL_free(encoded);
    throw std::runtime_error("invalid client key-share output");
  }
  std::vector<uint8_t> result(encoded, encoded + encoded_length);
  OPENSSL_free(encoded);
  *out_client = std::move(client);
  return result;
}

std::vector<uint8_t> AcceptClientShare(
    bssl::Span<const uint8_t> client_share,
    bssl::Array<uint8_t> *out_secret) {
  auto server = bssl::SSLKeyShare::Create(SSL_GROUP_X25519_MLKEM768);
  if (!server) {
    throw std::runtime_error("could not create server key share");
  }
  CBB builder;
  if (!CBB_init(&builder, 1120)) {
    throw std::runtime_error("could not initialize server key-share output");
  }
  uint8_t alert = 0;
  if (!server->Encap(&builder, out_secret, &alert, client_share)) {
    CBB_cleanup(&builder);
    throw std::runtime_error("server key-share encapsulation failed");
  }
  uint8_t *encoded = nullptr;
  size_t encoded_length = 0;
  if (!CBB_finish(&builder, &encoded, &encoded_length) ||
      encoded_length != 1120 || out_secret->size() != 64) {
    OPENSSL_free(encoded);
    throw std::runtime_error("invalid server key-share output");
  }
  std::vector<uint8_t> result(encoded, encoded + encoded_length);
  OPENSSL_free(encoded);
  return result;
}

void PrintInteropServer(std::string_view encoded_client_share) {
  const std::vector<uint8_t> client_share = DecodeHex(encoded_client_share);
  bssl::Array<uint8_t> secret;
  const std::vector<uint8_t> server_share = AcceptClientShare(
      bssl::Span<const uint8_t>(client_share.data(), client_share.size()),
      &secret);
  std::cout << "SERVER,"
            << Hex(bssl::Span<const uint8_t>(server_share.data(),
                                             server_share.size()))
            << ',' << Hex(secret) << '\n';
}

void RunInteropClient() {
  bssl::UniquePtr<bssl::SSLKeyShare> client;
  const std::vector<uint8_t> client_share = GenerateClientShare(&client);
  std::cout << "CLIENT,"
            << Hex(bssl::Span<const uint8_t>(client_share.data(),
                                             client_share.size()))
            << std::endl;

  std::string encoded_server_share;
  if (!std::getline(std::cin, encoded_server_share)) {
    throw std::runtime_error("missing server share on standard input");
  }
  const std::vector<uint8_t> server_share = DecodeHex(encoded_server_share);
  bssl::Array<uint8_t> secret;
  uint8_t alert = 0;
  if (!client->Decap(
          &secret, &alert,
          bssl::Span<const uint8_t>(server_share.data(), server_share.size())) ||
      secret.size() != 64) {
    throw std::runtime_error("client key-share decapsulation failed");
  }
  std::cout << "SECRET," << Hex(secret) << '\n';
}

Measurement Run(Operation operation, int iterations) {
  bssl::UniquePtr<bssl::SSLKeyShare> setup_client;
  const std::vector<uint8_t> setup_share = GenerateClientShare(&setup_client);
  uint8_t private_key[32];
  uint8_t peer_private_key[32];
  uint8_t peer_public_key[32];
  std::fill(std::begin(private_key), std::end(private_key), 0x42);
  std::fill(std::begin(peer_private_key), std::end(peer_private_key), 0x24);
  X25519_public_from_private(peer_public_key, peer_private_key);
  const auto start = std::chrono::steady_clock::now();
  uint64_t checksum = 0;
  for (int iteration = 0; iteration < iterations; iteration++) {
    switch (operation) {
      case Operation::kClientOffer: {
        bssl::UniquePtr<bssl::SSLKeyShare> client;
        const std::vector<uint8_t> share = GenerateClientShare(&client);
        checksum += share[static_cast<size_t>(iteration) % share.size()];
        break;
      }
      case Operation::kServerAccept: {
        bssl::Array<uint8_t> secret;
        const std::vector<uint8_t> ciphertext = AcceptClientShare(
            bssl::Span<const uint8_t>(setup_share.data(), setup_share.size()),
            &secret);
        checksum += ciphertext[static_cast<size_t>(iteration) %
                               ciphertext.size()];
        checksum += secret[static_cast<size_t>(iteration) % secret.size()];
        break;
      }
      case Operation::kRoundTrip: {
        bssl::UniquePtr<bssl::SSLKeyShare> client;
        const std::vector<uint8_t> share = GenerateClientShare(&client);
        bssl::Array<uint8_t> server_secret;
        const std::vector<uint8_t> ciphertext = AcceptClientShare(
            bssl::Span<const uint8_t>(share.data(), share.size()),
            &server_secret);
        bssl::Array<uint8_t> client_secret;
        uint8_t alert = 0;
        if (!client->Decap(
                &client_secret, &alert,
                bssl::Span<const uint8_t>(ciphertext.data(),
                                          ciphertext.size())) ||
            client_secret.size() != server_secret.size()) {
          throw std::runtime_error("client key-share decapsulation failed");
        }
        checksum += ciphertext[static_cast<size_t>(iteration) %
                               ciphertext.size()];
        checksum += client_secret[static_cast<size_t>(iteration) %
                                  client_secret.size()];
        break;
      }
      case Operation::kX25519Public: {
        uint8_t public_key[32];
        X25519_public_from_private(public_key, private_key);
        checksum += public_key[static_cast<size_t>(iteration) %
                               sizeof(public_key)];
        break;
      }
      case Operation::kX25519Shared: {
        uint8_t secret[32];
        if (!X25519(secret, private_key, peer_public_key)) {
          throw std::runtime_error("X25519 failed");
        }
        checksum += secret[static_cast<size_t>(iteration) % sizeof(secret)];
        break;
      }
    }
  }
  const auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
      std::chrono::steady_clock::now() - start);
  return {elapsed.count(), checksum};
}

}  // namespace

int main(int argc, char **argv) {
  try {
    if (argc >= 2 && std::string_view(argv[1]) == "interop-server") {
      if (argc != 3) {
        throw std::runtime_error("interop-server expects a client share");
      }
      PrintInteropServer(argv[2]);
      return EXIT_SUCCESS;
    }
    if (argc >= 2 && std::string_view(argv[1]) == "interop-client") {
      if (argc != 2) {
        throw std::runtime_error("interop-client takes no arguments");
      }
      RunInteropClient();
      return EXIT_SUCCESS;
    }
    if (argc != 4) {
      throw std::runtime_error("expected operation, iterations, and warmup");
    }
    const Operation operation = ParseOperation(argv[1]);
    const int iterations = std::stoi(argv[2]);
    const int warmup_iterations = std::stoi(argv[3]);
    if (iterations <= 0 || warmup_iterations < 0) {
      throw std::runtime_error("invalid iteration count");
    }
    (void)Run(operation, warmup_iterations);
    const Measurement result = Run(operation, iterations);
    std::cout << "RESULT," << result.nanoseconds << ',' << result.checksum
              << '\n';
    return EXIT_SUCCESS;
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return EXIT_FAILURE;
  }
}
