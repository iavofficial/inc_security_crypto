load("@rules_cc//cc:defs.bzl", "cc_test")

cc_test(
    name = "pqc_provider_application_integration_test",
    srcs = ["pqc_provider_application_integration_test.cpp"],
    deps = [
        "//score/crypto/src/daemon/provider/handler:handler_headers",
        "//score/crypto/src/daemon/provider/handler:sign_handler_operations",
        "//score/crypto/src/daemon/provider/handler:verify_handler_operations",
        "//score/crypto/src/daemon/provider/score_provider/operations/factory:score_handler_factory",
        "//score/crypto/src/daemon/provider/score_provider/pqc_provider:provider_pqc_provider_library",
        "@googletest//:gtest_main",
    ],
)
