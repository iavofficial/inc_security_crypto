load("@rules_cc//cc:defs.bzl", "cc_test")

cc_test(
    name = "iav_primula_key_management_test",
    srcs = ["iav_primula_key_management_test.cpp"],
    deps = [
        "//score/crypto/src/daemon/provider/score_provider:provider_iav_primula_library",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "iav_primula_signature_test",
    srcs = ["iav_primula_signature_test.cpp"],
    deps = [
        "//score/crypto/src/daemon/provider/score_provider:provider_iav_primula_library",
        "//score/crypto/src/daemon/provider/score_provider/operations/sign:score_sign_handler",
        "@googletest//:gtest_main",
    ],
)
