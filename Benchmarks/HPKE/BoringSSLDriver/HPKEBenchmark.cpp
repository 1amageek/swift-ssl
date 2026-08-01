#include <openssl/hpke.h>
#include <openssl/curve25519.h>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace {

enum class Operation {
  kFirstSeal,
  kFirstOpen,
  kRecipientSetup,
  kX25519Shared
};

void Check(bool condition, const char *message) {
  if (!condition) {
    throw std::runtime_error(message);
  }
}

std::vector<uint8_t> DeterministicBytes(size_t count, uint8_t seed) {
  std::vector<uint8_t> bytes(count);
  for (size_t index = 0; index < count; index++) {
    bytes[index] = static_cast<uint8_t>(seed + index * 29);
  }
  return bytes;
}

uint64_t Run(Operation operation, size_t payload_size, size_t aad_size,
             size_t iterations, int64_t *nanoseconds) {
  const std::vector<uint8_t> recipient_scalar(32, 0x41);
  const std::vector<uint8_t> ephemeral_scalar(32, 0x53);
  const std::vector<uint8_t> info = DeterministicBytes(77, 0x20);
  const std::vector<uint8_t> plaintext = DeterministicBytes(payload_size, 0x30);
  const std::vector<uint8_t> aad = DeterministicBytes(aad_size, 0x40);
  EVP_HPKE_KEY recipient_key;
  EVP_HPKE_KEY_zero(&recipient_key);
  Check(EVP_HPKE_KEY_init(&recipient_key, EVP_hpke_x25519_hkdf_sha256(),
                          recipient_scalar.data(), recipient_scalar.size()) == 1,
        "failed to initialize recipient key");
  std::vector<uint8_t> recipient_public(EVP_HPKE_MAX_PUBLIC_KEY_LENGTH);
  size_t recipient_public_len = 0;
  Check(EVP_HPKE_KEY_public_key(&recipient_key, recipient_public.data(),
                                &recipient_public_len,
                                recipient_public.size()) == 1,
        "failed to export recipient public key");
  recipient_public.resize(recipient_public_len);

  if (operation == Operation::kX25519Shared) {
    uint8_t shared_secret[32];
    uint64_t checksum = 0;
    const auto start = std::chrono::steady_clock::now();
    for (size_t iteration = 0; iteration < iterations; iteration++) {
      Check(X25519(shared_secret, ephemeral_scalar.data(),
                   recipient_public.data()) == 1,
            "failed to derive X25519 shared secret");
      checksum += shared_secret[iteration & 31];
    }
    const auto end = std::chrono::steady_clock::now();
    *nanoseconds =
        std::chrono::duration_cast<std::chrono::nanoseconds>(end - start)
            .count();
    EVP_HPKE_KEY_cleanup(&recipient_key);
    return checksum;
  }

  std::vector<uint8_t> encapsulation(EVP_HPKE_MAX_ENC_LENGTH);
  size_t encapsulation_len = 0;
  EVP_HPKE_CTX fixture_context;
  EVP_HPKE_CTX_zero(&fixture_context);
  Check(EVP_HPKE_CTX_setup_sender_with_seed_for_testing(
            &fixture_context, encapsulation.data(), &encapsulation_len,
            encapsulation.size(), EVP_hpke_x25519_hkdf_sha256(),
            EVP_hpke_hkdf_sha256(), EVP_hpke_aes_128_gcm(),
            recipient_public.data(), recipient_public.size(), info.data(),
            info.size(), ephemeral_scalar.data(), ephemeral_scalar.size()) == 1,
        "failed to initialize fixture sender");
  encapsulation.resize(encapsulation_len);
  std::vector<uint8_t> ciphertext(payload_size + EVP_HPKE_MAX_OVERHEAD);
  size_t ciphertext_len = 0;
  Check(EVP_HPKE_CTX_seal(&fixture_context, ciphertext.data(), &ciphertext_len,
                          ciphertext.size(), plaintext.data(), plaintext.size(),
                          aad.data(), aad.size()) == 1,
        "failed to seal fixture ciphertext");
  ciphertext.resize(ciphertext_len);
  EVP_HPKE_CTX_cleanup(&fixture_context);
  std::vector<uint8_t> output(payload_size + EVP_HPKE_MAX_OVERHEAD);

  uint64_t checksum = 0;
  const auto start = std::chrono::steady_clock::now();
  for (size_t iteration = 0; iteration < iterations; iteration++) {
    EVP_HPKE_CTX context;
    EVP_HPKE_CTX_zero(&context);
    size_t output_len = 0;
    if (operation == Operation::kFirstSeal) {
      size_t current_encapsulation_len = 0;
      Check(EVP_HPKE_CTX_setup_sender_with_seed_for_testing(
                &context, encapsulation.data(), &current_encapsulation_len,
                encapsulation.size(), EVP_hpke_x25519_hkdf_sha256(),
                EVP_hpke_hkdf_sha256(), EVP_hpke_aes_128_gcm(),
                recipient_public.data(), recipient_public.size(), info.data(),
                info.size(), ephemeral_scalar.data(),
                ephemeral_scalar.size()) == 1,
            "failed to initialize sender");
      Check(EVP_HPKE_CTX_seal(&context, output.data(), &output_len,
                              output.size(), plaintext.data(), plaintext.size(),
                              aad.data(), aad.size()) == 1,
            "failed to seal ciphertext");
    } else {
      Check(EVP_HPKE_CTX_setup_recipient(
                &context, &recipient_key, EVP_hpke_hkdf_sha256(),
                EVP_hpke_aes_128_gcm(), encapsulation.data(),
                encapsulation.size(), info.data(), info.size()) == 1,
            "failed to initialize recipient");
      if (operation == Operation::kFirstOpen) {
        Check(EVP_HPKE_CTX_open(&context, output.data(), &output_len,
                                output.size(), ciphertext.data(),
                                ciphertext.size(), aad.data(), aad.size()) == 1,
              "failed to open ciphertext");
        Check(output_len == plaintext.size(), "unexpected plaintext length");
      } else {
        output_len = 1;
        output[0] = 1;
      }
    }
    checksum += output[iteration % output_len];
    EVP_HPKE_CTX_cleanup(&context);
  }
  const auto end = std::chrono::steady_clock::now();
  *nanoseconds = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
  EVP_HPKE_KEY_cleanup(&recipient_key);
  return checksum;
}

void PrintHex(const char *label, const uint8_t *bytes, size_t size) {
  std::printf("%s,", label);
  for (size_t index = 0; index < size; index++) {
    std::printf("%02x", bytes[index]);
  }
  std::printf("\n");
}

void Validate(size_t payload_size, size_t aad_size) {
  const std::vector<uint8_t> recipient_scalar(32, 0x41);
  const std::vector<uint8_t> ephemeral_scalar(32, 0x53);
  const std::vector<uint8_t> info = DeterministicBytes(77, 0x20);
  const std::vector<uint8_t> plaintext = DeterministicBytes(payload_size, 0x30);
  const std::vector<uint8_t> aad = DeterministicBytes(aad_size, 0x40);
  EVP_HPKE_KEY recipient_key;
  EVP_HPKE_KEY_zero(&recipient_key);
  Check(EVP_HPKE_KEY_init(&recipient_key, EVP_hpke_x25519_hkdf_sha256(),
                          recipient_scalar.data(), recipient_scalar.size()) == 1,
        "failed to initialize recipient key");
  std::vector<uint8_t> recipient_public(EVP_HPKE_MAX_PUBLIC_KEY_LENGTH);
  size_t recipient_public_len = 0;
  Check(EVP_HPKE_KEY_public_key(&recipient_key, recipient_public.data(),
                                &recipient_public_len,
                                recipient_public.size()) == 1,
        "failed to export recipient public key");
  recipient_public.resize(recipient_public_len);

  std::vector<uint8_t> encapsulation(EVP_HPKE_MAX_ENC_LENGTH);
  size_t encapsulation_len = 0;
  EVP_HPKE_CTX sender;
  EVP_HPKE_CTX_zero(&sender);
  Check(EVP_HPKE_CTX_setup_sender_with_seed_for_testing(
            &sender, encapsulation.data(), &encapsulation_len,
            encapsulation.size(), EVP_hpke_x25519_hkdf_sha256(),
            EVP_hpke_hkdf_sha256(), EVP_hpke_aes_128_gcm(),
            recipient_public.data(), recipient_public.size(), info.data(),
            info.size(), ephemeral_scalar.data(), ephemeral_scalar.size()) == 1,
        "failed to initialize sender");
  encapsulation.resize(encapsulation_len);
  std::vector<uint8_t> ciphertext(payload_size + EVP_HPKE_MAX_OVERHEAD);
  size_t ciphertext_len = 0;
  Check(EVP_HPKE_CTX_seal(&sender, ciphertext.data(), &ciphertext_len,
                          ciphertext.size(), plaintext.data(), plaintext.size(),
                          aad.data(), aad.size()) == 1,
        "failed to seal ciphertext");
  ciphertext.resize(ciphertext_len);
  EVP_HPKE_CTX_cleanup(&sender);

  EVP_HPKE_CTX recipient;
  EVP_HPKE_CTX_zero(&recipient);
  Check(EVP_HPKE_CTX_setup_recipient(
            &recipient, &recipient_key, EVP_hpke_hkdf_sha256(),
            EVP_hpke_aes_128_gcm(), encapsulation.data(), encapsulation.size(),
            info.data(), info.size()) == 1,
        "failed to initialize recipient");
  std::vector<uint8_t> recovered(payload_size + EVP_HPKE_MAX_OVERHEAD);
  size_t recovered_len = 0;
  Check(EVP_HPKE_CTX_open(&recipient, recovered.data(), &recovered_len,
                          recovered.size(), ciphertext.data(), ciphertext.size(),
                          aad.data(), aad.size()) == 1,
        "failed to open ciphertext");
  Check(recovered_len == plaintext.size(), "unexpected plaintext length");
  EVP_HPKE_CTX_cleanup(&recipient);
  EVP_HPKE_KEY_cleanup(&recipient_key);

  PrintHex("ENCAPSULATION", encapsulation.data(), encapsulation.size());
  PrintHex("CIPHERTEXT", ciphertext.data(), ciphertext.size());
  PrintHex("PLAINTEXT", recovered.data(), recovered_len);
}

}  // namespace

int main(int argc, char **argv) {
  try {
    if (argc == 4 && std::string_view(argv[1]) == "validate") {
      Validate(std::stoull(argv[2]), std::stoull(argv[3]));
      return EXIT_SUCCESS;
    }
    if (argc != 6) {
      throw std::runtime_error(
          "usage: hpke-benchmark OPERATION PAYLOAD AAD ITERATIONS WARMUP");
    }
    const std::string_view operation_name(argv[1]);
    const Operation operation =
        operation_name == "first-seal"
            ? Operation::kFirstSeal
        : operation_name == "first-open"
            ? Operation::kFirstOpen
        : operation_name == "recipient-setup"
            ? Operation::kRecipientSetup
        : operation_name == "x25519-shared"
            ? Operation::kX25519Shared
            : throw std::runtime_error("invalid operation");
    const size_t payload_size = std::stoull(argv[2]);
    const size_t aad_size = std::stoull(argv[3]);
    const size_t iterations = std::stoull(argv[4]);
    const size_t warmup = std::stoull(argv[5]);
    int64_t discarded = 0;
    Run(operation, payload_size, aad_size, warmup, &discarded);
    int64_t nanoseconds = 0;
    const uint64_t checksum =
        Run(operation, payload_size, aad_size, iterations, &nanoseconds);
    std::printf("RESULT,%lld,%llu\n", static_cast<long long>(nanoseconds),
                static_cast<unsigned long long>(checksum));
    return EXIT_SUCCESS;
  } catch (const std::exception &error) {
    std::fprintf(stderr, "%s\n", error.what());
    return EXIT_FAILURE;
  }
}
