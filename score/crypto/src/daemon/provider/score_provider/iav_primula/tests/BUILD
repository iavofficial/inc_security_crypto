load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")

cc_library(
    name = "iav_primula_test_support",
    srcs = ["iav_primula_test_support.cpp"],
    hdrs = ["iav_primula_test_support.hpp"],
    visibility = ["//score/crypto/src/daemon/provider/score_provider/iav_primula/tests:__subpackages__"],
    deps = [
        "//score/iav_primula:iav_primula_ffi_headers",
        "//score/iav_primula:iav_primula_staticlib",
    ],
)

cc_test(
    name = "iav_primula_key_management_test",
    srcs = ["iav_primula_key_management_test.cpp"],
    deps = [
        "//score/crypto/src/daemon/provider/score_provider/iav_primula:provider_iav_primula_library",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "iav_primula_signature_test",
    srcs = ["iav_primula_signature_test.cpp"],
    deps = [
        ":iav_primula_test_support",
        "//score/crypto/src/daemon/common",
        "//score/crypto/src/daemon/provider/handler:sign_handler_operations",
        "//score/crypto/src/daemon/provider/score_provider/iav_primula:provider_iav_primula_library",
        "//score/crypto/src/daemon/provider/score_provider/operations/sign:score_sign_handler",
        "//score/iav_primula:iav_primula_ffi_headers",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "iav_primula_verification_test",
    srcs = ["iav_primula_verification_test.cpp"],
    deps = [
        ":iav_primula_test_support",
        "//score/crypto/src/daemon/common",
        "//score/crypto/src/daemon/provider/handler:verify_handler_operations",
        "//score/crypto/src/daemon/provider/score_provider/iav_primula:provider_iav_primula_library",
        "//score/crypto/src/daemon/provider/score_provider/operations/verify:score_verify_handler",
        "//score/iav_primula:iav_primula_ffi_headers",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "iav_primula_kem_test",
    srcs = ["iav_primula_kem_test.cpp"],
    deps = [
        ":iav_primula_test_support",
        "//score/crypto/src/daemon/provider/handler:kem_handler_operations",
        "//score/crypto/src/daemon/provider/score_provider/iav_primula:provider_iav_primula_library",
        "//score/crypto/src/daemon/provider/score_provider/operations/kem:score_kem_handler",
        "//score/iav_primula:iav_primula_ffi_headers",
        "@googletest//:gtest_main",
    ],
)
