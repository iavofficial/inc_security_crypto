load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")
cc_library(
    name = "score_verify_handler",
    srcs = ["src/score_verify_handler.cpp", "src/verify_executor.cpp"],
    hdrs = ["score_verify_handler.hpp", "verify_executor.hpp"],
    visibility = ["//:__subpackages__"],
    deps = [
        "//score/crypto/src/daemon/common",
        "//score/crypto/src/daemon/provider/handler:handler_headers",
        "//score/crypto/src/daemon/provider/handler:handler_utils_impl",
        "//score/crypto/src/daemon/provider/handler:verify_handler_operations",
    ],
)

cc_test(
    name = "verify_executor_test",
    srcs = ["test/verify_executor_test.cpp"],
    deps = [
        ":score_verify_handler",
        "//score/crypto/src/daemon/provider/handler:verify_handler_operations",
        "@googletest//:gtest_main",
    ],
)
