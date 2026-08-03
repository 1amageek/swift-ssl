#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: $0 BORINGSSL_SOURCE" >&2
  exit 64
fi

boringssl_source=$1
expected_commit=ae49d2681a56ca7b8609f6039a770fda2a8eb550
actual_commit=$(git -C "$boringssl_source" rev-parse HEAD)
if [ "$actual_commit" != "$expected_commit" ]; then
  echo "BoringSSL commit mismatch: $actual_commit" >&2
  exit 65
fi
if [ -n "$(git -C "$boringssl_source" status --short)" ]; then
  echo "BoringSSL checkout must be clean" >&2
  exit 65
fi

build_root=.build/validation-ech-interop
cmake -S Validation/ECHInterop/BoringSSLDriver -B "$build_root/boringssl" \
  -GNinja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_MAKE_PROGRAM="$(command -v ninja)" \
  -DBORINGSSL_SOURCE="$boringssl_source" \
  -DBORINGSSL_COMMIT="$expected_commit"
cmake --build "$build_root/boringssl" --target boringssl-ech-interop

driver="$build_root/boringssl/boringssl-ech-interop"
fixture=$($driver fixture)
private_key=$(printf '%s\n' "$fixture" | sed -n 's/^private=//p')
config=$(printf '%s\n' "$fixture" | sed -n 's/^config=//p')
config_list=$(printf '%s\n' "$fixture" | sed -n 's/^config_list=//p')
boringssl_client_hello=$(printf '%s\n' "$fixture" | sed -n 's/^client_hello=//p')

SWIFT_SSL_ENABLE_ECH_INTEROP_VALIDATION=1 swift run -c release \
  swift-ssl-ech-interop-validation \
  verify-boringssl-client "$private_key" "$config_list" \
  "$boringssl_client_hello"
swift_client_hello=$(SWIFT_SSL_ENABLE_ECH_INTEROP_VALIDATION=1 swift run \
  -c release swift-ssl-ech-interop-validation make-swift-client \
  "$config_list" | tail -n 1)
$driver verify-swift-client "$private_key" "$config" "$swift_client_hello"
