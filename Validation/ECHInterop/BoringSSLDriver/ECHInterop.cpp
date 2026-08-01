#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/hpke.h>
#include <openssl/mem.h>
#include <openssl/ssl.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

constexpr char kOriginName[] = "origin.example";
constexpr char kPublicName[] = "public.example";

std::string EncodeHex(const uint8_t *bytes, size_t count) {
  static constexpr char kAlphabet[] = "0123456789abcdef";
  std::string result(count * 2, '\0');
  for (size_t index = 0; index < count; index++) {
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

void Check(bool condition, const char *message) {
  if (!condition) {
    throw std::runtime_error(message);
  }
}

struct ECHFixture {
  EVP_HPKE_KEY key;
  std::vector<uint8_t> private_key;
  std::vector<uint8_t> config;
  std::vector<uint8_t> config_list;

  ECHFixture() { EVP_HPKE_KEY_zero(&key); }
  ECHFixture(const ECHFixture &) = delete;
  ECHFixture &operator=(const ECHFixture &) = delete;
  ECHFixture(ECHFixture &&other) noexcept
      : private_key(std::move(other.private_key)),
        config(std::move(other.config)),
        config_list(std::move(other.config_list)) {
    EVP_HPKE_KEY_zero(&key);
    EVP_HPKE_KEY_move(&key, &other.key);
  }
  ~ECHFixture() { EVP_HPKE_KEY_cleanup(&key); }
};

ECHFixture MakeFixture() {
  ECHFixture fixture;
  std::vector<uint8_t> ikm(32);
  for (size_t index = 0; index < ikm.size(); index++) {
    ikm[index] = static_cast<uint8_t>(index + 1);
  }
  Check(EVP_HPKE_KEY_derive(&fixture.key, EVP_hpke_x25519_hkdf_sha256(),
                            ikm.data(), ikm.size()) == 1,
        "failed to derive ECH key");
  fixture.private_key.resize(EVP_HPKE_MAX_PRIVATE_KEY_LENGTH);
  size_t private_key_len = 0;
  Check(EVP_HPKE_KEY_private_key(&fixture.key, fixture.private_key.data(),
                                 &private_key_len,
                                 fixture.private_key.size()) == 1,
        "failed to export ECH private key");
  fixture.private_key.resize(private_key_len);

  uint8_t *config = nullptr;
  size_t config_len = 0;
  Check(SSL_marshal_ech_config(&config, &config_len, 17, &fixture.key,
                               kPublicName, 64) == 1,
        "failed to marshal ECHConfig");
  fixture.config.assign(config, config + config_len);
  OPENSSL_free(config);
  Check(config_len <= UINT16_MAX, "ECHConfig exceeds ECHConfigList limit");
  fixture.config_list.reserve(config_len + 2);
  fixture.config_list.push_back(static_cast<uint8_t>(config_len >> 8));
  fixture.config_list.push_back(static_cast<uint8_t>(config_len));
  fixture.config_list.insert(fixture.config_list.end(), fixture.config.begin(),
                             fixture.config.end());
  return fixture;
}

std::vector<uint8_t> MakeBoringSSLClientHello(
    const std::vector<uint8_t> &config_list) {
  SSL_CTX *ctx = SSL_CTX_new(TLS_method());
  Check(ctx != nullptr, "failed to create client context");
  Check(SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) == 1 &&
            SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) == 1,
        "failed to constrain client to TLS 1.3");
  SSL *ssl = SSL_new(ctx);
  Check(ssl != nullptr, "failed to create client connection");
  Check(SSL_set_tlsext_host_name(ssl, kOriginName) == 1,
        "failed to set origin server name");
  Check(SSL_set1_ech_config_list(ssl, config_list.data(),
                                 config_list.size()) == 1,
        "failed to configure client ECHConfigList");
  SSL_set_connect_state(ssl);
  BIO *output = BIO_new(BIO_s_mem());
  Check(output != nullptr, "failed to create client output BIO");
  SSL_set_bio(ssl, nullptr, output);
  Check(SSL_connect(ssl) <= 0, "client unexpectedly completed handshake");
  ERR_clear_error();
  const uint8_t *records = nullptr;
  size_t records_len = 0;
  Check(BIO_mem_contents(output, &records, &records_len) == 1,
        "failed to read client output");
  Check(records_len >= 9 && records[0] == SSL3_RT_HANDSHAKE,
        "client output does not begin with a handshake record");
  const size_t record_len =
      (static_cast<size_t>(records[3]) << 8) | records[4];
  Check(record_len + SSL3_RT_HEADER_LENGTH <= records_len,
        "truncated client handshake record");
  std::vector<uint8_t> result(records + SSL3_RT_HEADER_LENGTH,
                              records + SSL3_RT_HEADER_LENGTH + record_len);
  SSL_free(ssl);
  SSL_CTX_free(ctx);
  return result;
}

struct CallbackState {
  bool called = false;
  bool ech_accepted = false;
  bool origin_name = false;
};

ssl_select_cert_result_t SelectCertificate(
    const SSL_CLIENT_HELLO *client_hello) {
  SSL_CTX *ctx = SSL_get_SSL_CTX(client_hello->ssl);
  auto *state = static_cast<CallbackState *>(SSL_CTX_get_app_data(ctx));
  state->called = true;
  state->ech_accepted = SSL_ech_accepted(client_hello->ssl) == 1;
  const char *server_name = SSL_get_servername(
      client_hello->ssl, TLSEXT_NAMETYPE_host_name);
  state->origin_name =
      server_name != nullptr && std::strcmp(server_name, kOriginName) == 0;
  return ssl_select_cert_error;
}

void VerifySwiftClient(std::string_view private_key_hex,
                       std::string_view config_hex,
                       std::string_view client_hello_hex) {
  const std::vector<uint8_t> private_key = DecodeHex(private_key_hex);
  const std::vector<uint8_t> config = DecodeHex(config_hex);
  const std::vector<uint8_t> client_hello = DecodeHex(client_hello_hex);
  EVP_HPKE_KEY key;
  EVP_HPKE_KEY_zero(&key);
  Check(EVP_HPKE_KEY_init(&key, EVP_hpke_x25519_hkdf_sha256(),
                          private_key.data(), private_key.size()) == 1,
        "failed to import ECH private key");
  SSL_ECH_KEYS *keys = SSL_ECH_KEYS_new();
  Check(keys != nullptr, "failed to create ECH key set");
  Check(SSL_ECH_KEYS_add(keys, 1, config.data(), config.size(), &key) == 1,
        "failed to add ECH server key");
  SSL_CTX *ctx = SSL_CTX_new(TLS_method());
  Check(ctx != nullptr, "failed to create server context");
  Check(SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) == 1 &&
            SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) == 1,
        "failed to constrain server to TLS 1.3");
  Check(SSL_CTX_set1_ech_keys(ctx, keys) == 1,
        "failed to configure server ECH keys");
  CallbackState callback_state;
  Check(SSL_CTX_set_app_data(ctx, &callback_state) == 1,
        "failed to attach callback state");
  SSL_CTX_set_select_certificate_cb(ctx, SelectCertificate);
  SSL *ssl = SSL_new(ctx);
  Check(ssl != nullptr, "failed to create server connection");
  SSL_set_accept_state(ssl);
  BIO *input = BIO_new(BIO_s_mem());
  BIO *output = BIO_new(BIO_s_mem());
  Check(input != nullptr && output != nullptr,
        "failed to create server BIOs");
  std::vector<uint8_t> record;
  Check(client_hello.size() <= UINT16_MAX, "ClientHello exceeds record limit");
  record.reserve(client_hello.size() + SSL3_RT_HEADER_LENGTH);
  record.push_back(SSL3_RT_HANDSHAKE);
  record.push_back(0x03);
  record.push_back(0x01);
  record.push_back(static_cast<uint8_t>(client_hello.size() >> 8));
  record.push_back(static_cast<uint8_t>(client_hello.size()));
  record.insert(record.end(), client_hello.begin(), client_hello.end());
  Check(BIO_write(input, record.data(), record.size()) ==
            static_cast<int>(record.size()),
        "failed to write ClientHello record");
  SSL_set_bio(ssl, input, output);
  Check(SSL_accept(ssl) <= 0, "server unexpectedly completed handshake");
  ERR_clear_error();
  Check(callback_state.called, "certificate callback was not reached");
  Check(callback_state.ech_accepted, "BoringSSL rejected Swift ECH");
  Check(callback_state.origin_name,
        "BoringSSL did not reconstruct the origin server name");
  std::puts("swift-client/boringssl-server:accepted");
  SSL_free(ssl);
  SSL_CTX_free(ctx);
  SSL_ECH_KEYS_free(keys);
  EVP_HPKE_KEY_cleanup(&key);
}

void PrintFixture() {
  ECHFixture fixture = MakeFixture();
  const std::vector<uint8_t> client_hello =
      MakeBoringSSLClientHello(fixture.config_list);
  std::printf("private=%s\n", EncodeHex(fixture.private_key.data(),
                                        fixture.private_key.size()).c_str());
  std::printf("config=%s\n",
              EncodeHex(fixture.config.data(), fixture.config.size()).c_str());
  std::printf("config_list=%s\n",
              EncodeHex(fixture.config_list.data(),
                        fixture.config_list.size()).c_str());
  std::printf("client_hello=%s\n",
              EncodeHex(client_hello.data(), client_hello.size()).c_str());
}

}  // namespace

int main(int argc, char **argv) {
  try {
    if (argc == 2 && std::string_view(argv[1]) == "fixture") {
      PrintFixture();
      return EXIT_SUCCESS;
    }
    if (argc == 5 && std::string_view(argv[1]) == "verify-swift-client") {
      VerifySwiftClient(argv[2], argv[3], argv[4]);
      return EXIT_SUCCESS;
    }
    std::fprintf(stderr,
                 "usage: %s fixture | verify-swift-client PRIVATE CONFIG "
                 "CLIENT_HELLO\n",
                 argv[0]);
    return EXIT_FAILURE;
  } catch (const std::exception &error) {
    std::fprintf(stderr, "%s\n", error.what());
    ERR_print_errors_fp(stderr);
    return EXIT_FAILURE;
  }
}
