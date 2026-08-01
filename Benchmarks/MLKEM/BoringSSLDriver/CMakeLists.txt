cmake_minimum_required(VERSION 3.22)
project(swift_ssl_boringssl_mlkem_benchmark LANGUAGES C CXX ASM)

set(EXPECTED_BORINGSSL_COMMIT "ae49d2681a56ca7b8609f6039a770fda2a8eb550")

if(NOT DEFINED BORINGSSL_SOURCE)
    message(FATAL_ERROR "BORINGSSL_SOURCE must point to the pinned BoringSSL checkout")
endif()

if(NOT DEFINED BORINGSSL_COMMIT)
    message(FATAL_ERROR "BORINGSSL_COMMIT must identify the pinned BoringSSL source")
endif()

if(NOT BORINGSSL_COMMIT STREQUAL EXPECTED_BORINGSSL_COMMIT)
    message(FATAL_ERROR
        "BoringSSL commit mismatch: expected ${EXPECTED_BORINGSSL_COMMIT}, "
        "found ${BORINGSSL_COMMIT}"
    )
endif()

set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(CFI OFF CACHE BOOL "Disable control-flow instrumentation" FORCE)
set(MSAN OFF CACHE BOOL "Disable MemorySanitizer" FORCE)
set(OPENSSL_NO_ASM OFF CACHE BOOL "Require BoringSSL assembly" FORCE)
add_subdirectory("${BORINGSSL_SOURCE}" boringssl EXCLUDE_FROM_ALL)

add_executable(boringssl-mlkem-benchmark MLKEMBenchmark.cpp)
target_compile_features(boringssl-mlkem-benchmark PRIVATE cxx_std_17)
target_link_libraries(boringssl-mlkem-benchmark PRIVATE crypto)
