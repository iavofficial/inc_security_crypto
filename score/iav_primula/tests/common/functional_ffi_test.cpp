/********************************************************************************
 * Copyright (c) 2026 Contributors to the Eclipse Foundation
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/

/// @file functional_ffi_test.cpp
/// @brief Functional round-trip tests for the public IAV-Primula C ABI.

#include "score/iav_primula/include/iav_primula_ffi.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <vector>

namespace
{

struct TestRngContext
{
    std::atomic<std::uint64_t> request_counter{0U};
    std::atomic<bool> fail_requests{false};
};

constexpr std::uint64_t kSplitMixGamma = 0x9E3779B97F4A7C15ULL;
constexpr std::uint64_t kSplitMixMultiplier1 = 0xBF58476D1CE4E5B9ULL;
constexpr std::uint64_t kSplitMixMultiplier2 = 0x94D049BB133111EBULL;
constexpr unsigned int kSplitMixShift1 = 30U;
constexpr unsigned int kSplitMixShift2 = 27U;
constexpr unsigned int kSplitMixShift3 = 31U;
constexpr unsigned int kOutputByteShift = 56U;
constexpr std::size_t kMlKem512PublicKeySize = 800U;
constexpr std::size_t kMlKem512CiphertextSize = 768U;
constexpr std::size_t kSharedSecretSize = 32U;
constexpr std::array<std::uint8_t, 5U> kUnalignedMessage = {0x49U, 0x41U, 0x56U, 0x2DU, 0x50U};

/// This deterministic provider is test-only; production targets never depend on it.
int FillTestRandomBytes(std::uint8_t* output, std::size_t output_len, void* user_data)
{
    auto* const context = static_cast<TestRngContext*>(user_data);
    if (context == nullptr || (output == nullptr && output_len != 0U))
    {
        return 1;
    }
    if (context->fail_requests.load(std::memory_order_relaxed))
    {
        return 1;
    }

    const std::uint64_t request = context->request_counter.fetch_add(1U, std::memory_order_relaxed);
    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic): fill the C callback's caller-provided byte span.
    for (std::size_t index = 0U; index < output_len; ++index)
    {
        std::uint64_t value = request + kSplitMixGamma * (index + 1U);
        value = (value ^ (value >> kSplitMixShift1)) * kSplitMixMultiplier1;
        value = (value ^ (value >> kSplitMixShift2)) * kSplitMixMultiplier2;
        value ^= value >> kSplitMixShift3;
        output[index] = static_cast<std::uint8_t>(value >> kOutputByteShift);
    }
    // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    return 0;
}

TestRngContext& GetTestRngContext()
{
    static TestRngContext context;
    return context;
}

iav_status RegisterTestRandomBytesProvider()
{
    static const iav_status status = iav_random_bytes_provider_register(FillTestRandomBytes, &GetTestRngContext());
    return status;
}

class ScopedTestRngFailure
{
  public:
    ScopedTestRngFailure()
    {
        GetTestRngContext().fail_requests.store(true, std::memory_order_relaxed);
    }

    ~ScopedTestRngFailure()
    {
        GetTestRngContext().fail_requests.store(false, std::memory_order_relaxed);
    }

    ScopedTestRngFailure(const ScopedTestRngFailure&) = delete;
    ScopedTestRngFailure& operator=(const ScopedTestRngFailure&) = delete;
    ScopedTestRngFailure(ScopedTestRngFailure&&) = delete;
    ScopedTestRngFailure& operator=(ScopedTestRngFailure&&) = delete;
};

struct KeyDeleter
{
    void operator()(iav_primula_key_handle* key) const
    {
        iav_key_destroy(key);
    }
};

using KeyHandle = std::unique_ptr<iav_primula_key_handle, KeyDeleter>;

class GuardedBuffer
{
  public:
    explicit GuardedBuffer(std::size_t capacity)
        : capacity_(capacity), storage_(kPrefixSize + capacity + kSuffixSize, kCanary)
    {
        std::fill(storage_.begin() + static_cast<std::ptrdiff_t>(kPrefixSize),
                  storage_.begin() + static_cast<std::ptrdiff_t>(kPrefixSize + capacity_),
                  kInitialPayload);
    }

    std::uint8_t* data()
    {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic): expose the guarded byte span.
        return storage_.data() + kPrefixSize;
    }

    const std::uint8_t* data() const
    {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic): expose the guarded byte span.
        return storage_.data() + kPrefixSize;
    }

    std::uint8_t* DataAt(std::size_t offset)
    {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic): address a byte within the guarded span.
        return data() + offset;
    }

    std::size_t capacity() const
    {
        return capacity_;
    }

    bool CanariesIntact() const
    {
        for (std::size_t index = 0U; index < kPrefixSize; ++index)
        {
            if (storage_[index] != kCanary)
            {
                return false;
            }
        }
        for (std::size_t index = kPrefixSize + capacity_; index < storage_.size(); ++index)
        {
            if (storage_[index] != kCanary)
            {
                return false;
            }
        }
        return true;
    }

    bool PayloadUnchanged() const
    {
        return std::all_of(storage_.begin() + static_cast<std::ptrdiff_t>(kPrefixSize),
                           storage_.begin() + static_cast<std::ptrdiff_t>(kPrefixSize + capacity_),
                           [](std::uint8_t value) {
                               return value == kInitialPayload;
                           });
    }

    bool Unchanged() const
    {
        return CanariesIntact() && PayloadUnchanged();
    }

    bool IsUnaligned() const
    {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): inspect the actual byte address alignment.
        return (reinterpret_cast<std::uintptr_t>(data()) % alignof(std::uint32_t)) != 0U;
    }

  private:
    static constexpr std::size_t kPrefixSize = 17U;
    static constexpr std::size_t kSuffixSize = 16U;
    static constexpr std::uint8_t kCanary = 0xD3U;
    static constexpr std::uint8_t kInitialPayload = 0xA5U;

    std::size_t capacity_;
    std::vector<std::uint8_t> storage_;
};

KeyHandle GenerateSignatureKey(iav_algorithm algorithm)
{
    iav_primula_key_handle* raw_key = nullptr;
    EXPECT_EQ(iav_keypair_generate(algorithm, &raw_key), IavStatusOk);
    return KeyHandle(raw_key);
}

KeyHandle GenerateKemKey(iav_algorithm algorithm)
{
    iav_primula_key_handle* raw_key = nullptr;
    EXPECT_EQ(iav_kem_keypair_generate(algorithm, &raw_key), IavStatusOk);
    return KeyHandle(raw_key);
}

struct SignatureCase
{
    const char* test_name;
    iav_algorithm algorithm;
    std::size_t public_key_size;
    std::size_t signature_size;
};

class MlDsaFunctionalTest : public ::testing::TestWithParam<SignatureCase>
{
  protected:
    void SetUp() override
    {
        ASSERT_EQ(RegisterTestRandomBytesProvider(), IavStatusOk);
    }
};

TEST_P(MlDsaFunctionalTest, GeneratesSignsAndVerifiesAndRejectsTampering)
{
    const SignatureCase& test_case = GetParam();
    static constexpr std::array<std::uint8_t, 15U> kMessage = {{
        0x49U,
        0x41U,
        0x56U,
        0x2DU,
        0x50U,
        0x72U,
        0x69U,
        0x6DU,
        0x75U,
        0x6CU,
        0x61U,
        0x2DU,
        0x50U,
        0x51U,
        0x43U,
    }};

    iav_primula_key_handle* raw_key = nullptr;
    const iav_status keygen_status = iav_keypair_generate(test_case.algorithm, &raw_key);
    const KeyHandle key(raw_key);
    ASSERT_EQ(keygen_status, IavStatusOk);
    ASSERT_NE(key, nullptr);

    std::vector<std::uint8_t> public_key(test_case.public_key_size);
    std::size_t public_key_len = public_key.size();
    ASSERT_EQ(iav_public_key_export(key.get(), public_key.data(), &public_key_len), IavStatusOk);
    EXPECT_EQ(public_key_len, test_case.public_key_size);

    std::vector<std::uint8_t> signature(test_case.signature_size);
    std::size_t signature_len = signature.size();
    ASSERT_EQ(iav_sign(key.get(), kMessage.data(), kMessage.size(), signature.data(), &signature_len), IavStatusOk);
    ASSERT_EQ(signature_len, test_case.signature_size);
    EXPECT_EQ(iav_verify(key.get(), kMessage.data(), kMessage.size(), signature.data(), signature_len), IavStatusOk);

    std::vector<std::uint8_t> modified_message(kMessage.begin(), kMessage.end());
    modified_message[0] ^= 0x01U;
    EXPECT_EQ(iav_verify(key.get(), modified_message.data(), modified_message.size(), signature.data(), signature_len),
              IavStatusVerificationFailed);

    signature[signature.size() / 2U] ^= 0x01U;
    EXPECT_EQ(iav_verify(key.get(), kMessage.data(), kMessage.size(), signature.data(), signature_len),
              IavStatusVerificationFailed);
}

TEST_P(MlDsaFunctionalTest, ReportsRequiredSizesWithoutWritingToUndersizedBuffers)
{
    const SignatureCase& test_case = GetParam();
    const KeyHandle key = GenerateSignatureKey(test_case.algorithm);
    ASSERT_NE(key, nullptr);

    GuardedBuffer public_key(test_case.public_key_size - 1U);
    std::size_t public_key_len = public_key.capacity();
    EXPECT_EQ(iav_public_key_export(key.get(), public_key.data(), &public_key_len), IavStatusBufferTooSmall);
    EXPECT_EQ(public_key_len, test_case.public_key_size);
    EXPECT_TRUE(public_key.Unchanged());

    static constexpr std::array<std::uint8_t, 3U> kMessage = {0x01U, 0x02U, 0x03U};
    GuardedBuffer signature(test_case.signature_size - 1U);
    std::size_t signature_len = signature.capacity();
    EXPECT_EQ(iav_sign(key.get(), kMessage.data(), kMessage.size(), signature.data(), &signature_len),
              IavStatusBufferTooSmall);
    EXPECT_EQ(signature_len, test_case.signature_size);
    EXPECT_TRUE(signature.Unchanged());
}

TEST_P(MlDsaFunctionalTest, RejectsInvalidArgumentsAndPreservesOutputBuffers)
{
    const SignatureCase& test_case = GetParam();
    const KeyHandle key = GenerateSignatureKey(test_case.algorithm);
    ASSERT_NE(key, nullptr);

    static constexpr std::array<std::uint8_t, 3U> kMessage = {0x11U, 0x22U, 0x33U};
    GuardedBuffer public_key(test_case.public_key_size);
    std::size_t public_key_len = public_key.capacity();
    EXPECT_EQ(iav_public_key_export(key.get(), public_key.data(), nullptr), IavStatusInvalidArgument);
    EXPECT_EQ(iav_public_key_export(key.get(), nullptr, &public_key_len), IavStatusInvalidArgument);
    EXPECT_EQ(public_key_len, public_key.capacity());
    EXPECT_TRUE(public_key.Unchanged());

    GuardedBuffer signature(test_case.signature_size);
    std::size_t signature_len = signature.capacity();
    EXPECT_EQ(iav_sign(key.get(), kMessage.data(), kMessage.size(), signature.data(), nullptr),
              IavStatusInvalidArgument);
    EXPECT_EQ(iav_sign(key.get(), nullptr, 1U, signature.data(), &signature_len), IavStatusInvalidArgument);
    EXPECT_EQ(signature_len, signature.capacity());
    EXPECT_TRUE(signature.Unchanged());
    if (std::numeric_limits<std::size_t>::max() > std::numeric_limits<std::uint32_t>::max())
    {
        const std::size_t oversized_message_len =
            static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max()) + 1U;
        EXPECT_EQ(iav_sign(key.get(), kMessage.data(), oversized_message_len, signature.data(), &signature_len),
                  IavStatusInvalidArgument);
        EXPECT_EQ(signature_len, signature.capacity());
        EXPECT_TRUE(signature.Unchanged());
        EXPECT_EQ(
            iav_verify(key.get(), kMessage.data(), oversized_message_len, signature.data(), test_case.signature_size),
            IavStatusInvalidArgument);
    }
    EXPECT_EQ(iav_sign(key.get(), kMessage.data(), kMessage.size(), nullptr, &signature_len), IavStatusInvalidArgument);
    EXPECT_EQ(signature_len, signature.capacity());
    EXPECT_TRUE(signature.Unchanged());

    EXPECT_EQ(iav_verify(key.get(), nullptr, 1U, signature.data(), test_case.signature_size), IavStatusInvalidArgument);
    EXPECT_EQ(iav_verify(key.get(), kMessage.data(), kMessage.size(), nullptr, test_case.signature_size),
              IavStatusInvalidArgument);
    EXPECT_EQ(iav_verify(key.get(), kMessage.data(), kMessage.size(), signature.data(), test_case.signature_size - 1U),
              IavStatusInvalidArgument);
}

TEST_P(MlDsaFunctionalTest, SupportsUnalignedBuffersAndEmptyMessagesWithoutDamagingCanaries)
{
    const SignatureCase& test_case = GetParam();
    const KeyHandle key = GenerateSignatureKey(test_case.algorithm);
    ASSERT_NE(key, nullptr);

    GuardedBuffer public_key(test_case.public_key_size);
    ASSERT_TRUE(public_key.IsUnaligned());
    std::size_t public_key_len = public_key.capacity();
    ASSERT_EQ(iav_public_key_export(key.get(), public_key.data(), &public_key_len), IavStatusOk);
    EXPECT_EQ(public_key_len, test_case.public_key_size);
    EXPECT_TRUE(public_key.CanariesIntact());

    GuardedBuffer message(kUnalignedMessage.size());
    ASSERT_TRUE(message.IsUnaligned());
    std::copy(kUnalignedMessage.begin(), kUnalignedMessage.end(), message.data());

    GuardedBuffer signature(test_case.signature_size);
    ASSERT_TRUE(signature.IsUnaligned());
    std::size_t signature_len = signature.capacity();
    ASSERT_EQ(iav_sign(key.get(), message.data(), message.capacity(), signature.data(), &signature_len), IavStatusOk);
    ASSERT_EQ(signature_len, test_case.signature_size);
    EXPECT_EQ(iav_verify(key.get(), message.data(), message.capacity(), signature.data(), signature_len), IavStatusOk);
    EXPECT_TRUE(message.CanariesIntact());
    EXPECT_TRUE(signature.CanariesIntact());

    signature_len = signature.capacity();
    ASSERT_EQ(iav_sign(key.get(), nullptr, 0U, signature.data(), &signature_len), IavStatusOk);
    EXPECT_EQ(iav_verify(key.get(), nullptr, 0U, signature.data(), signature_len), IavStatusOk);
    EXPECT_TRUE(signature.CanariesIntact());
}

INSTANTIATE_TEST_SUITE_P(AllSupportedParameterSets,
                         MlDsaFunctionalTest,
                         ::testing::Values(SignatureCase{"ML_DSA_44", IavAlgorithmMlDsa44, 1312U, 2420U},
                                           SignatureCase{"ML_DSA_65", IavAlgorithmMlDsa65, 1952U, 3309U},
                                           SignatureCase{"ML_DSA_87", IavAlgorithmMlDsa87, 2592U, 4627U}),
                         [](const ::testing::TestParamInfo<SignatureCase>& info) {
                             return info.param.test_name;
                         });

struct KemCase
{
    const char* test_name;
    iav_algorithm algorithm;
    std::size_t public_key_size;
    std::size_t ciphertext_size;
};

class MlKemFunctionalTest : public ::testing::TestWithParam<KemCase>
{
  protected:
    void SetUp() override
    {
        ASSERT_EQ(RegisterTestRandomBytesProvider(), IavStatusOk);
    }
};

TEST_P(MlKemFunctionalTest, EncapsulatesDecapsulatesAndRejectsTamperedCiphertext)
{
    const KemCase& test_case = GetParam();
    iav_primula_key_handle* raw_key = nullptr;
    const iav_status keygen_status = iav_kem_keypair_generate(test_case.algorithm, &raw_key);
    const KeyHandle key(raw_key);
    ASSERT_EQ(keygen_status, IavStatusOk);
    ASSERT_NE(key, nullptr);

    std::vector<std::uint8_t> public_key(test_case.public_key_size);
    std::size_t public_key_len = public_key.size();
    ASSERT_EQ(iav_kem_public_key_export(key.get(), public_key.data(), &public_key_len), IavStatusOk);
    ASSERT_EQ(public_key_len, test_case.public_key_size);

    std::vector<std::uint8_t> ciphertext(test_case.ciphertext_size);
    std::vector<std::uint8_t> encapsulated_secret(kSharedSecretSize);
    std::size_t ciphertext_len = ciphertext.size();
    std::size_t encapsulated_secret_len = encapsulated_secret.size();
    ASSERT_EQ(iav_kem_encapsulate(test_case.algorithm,
                                  public_key.data(),
                                  public_key_len,
                                  ciphertext.data(),
                                  &ciphertext_len,
                                  encapsulated_secret.data(),
                                  &encapsulated_secret_len),
              IavStatusOk);
    ASSERT_EQ(ciphertext_len, test_case.ciphertext_size);
    ASSERT_EQ(encapsulated_secret_len, kSharedSecretSize);

    std::vector<std::uint8_t> decapsulated_secret(kSharedSecretSize);
    std::size_t decapsulated_secret_len = decapsulated_secret.size();
    ASSERT_EQ(iav_kem_decapsulate(
                  key.get(), ciphertext.data(), ciphertext_len, decapsulated_secret.data(), &decapsulated_secret_len),
              IavStatusOk);
    ASSERT_EQ(decapsulated_secret_len, kSharedSecretSize);
    EXPECT_EQ(decapsulated_secret, encapsulated_secret);

    ciphertext[ciphertext.size() / 2U] ^= 0x01U;
    std::vector<std::uint8_t> rejection_secret(kSharedSecretSize);
    std::size_t rejection_secret_len = rejection_secret.size();
    EXPECT_EQ(iav_kem_decapsulate(
                  key.get(), ciphertext.data(), ciphertext_len, rejection_secret.data(), &rejection_secret_len),
              IavStatusOk);
    EXPECT_EQ(rejection_secret_len, kSharedSecretSize);
    EXPECT_NE(rejection_secret, encapsulated_secret);
}

TEST_P(MlKemFunctionalTest, ReportsRequiredSizesWithoutWritingToUndersizedBuffers)
{
    const KemCase& test_case = GetParam();
    const KeyHandle key = GenerateKemKey(test_case.algorithm);
    ASSERT_NE(key, nullptr);

    GuardedBuffer public_key(test_case.public_key_size - 1U);
    std::size_t public_key_len = public_key.capacity();
    EXPECT_EQ(iav_kem_public_key_export(key.get(), public_key.data(), &public_key_len), IavStatusBufferTooSmall);
    EXPECT_EQ(public_key_len, test_case.public_key_size);
    EXPECT_TRUE(public_key.Unchanged());

    std::vector<std::uint8_t> full_public_key(test_case.public_key_size);
    public_key_len = full_public_key.size();
    ASSERT_EQ(iav_kem_public_key_export(key.get(), full_public_key.data(), &public_key_len), IavStatusOk);

    GuardedBuffer short_ciphertext(test_case.ciphertext_size - 1U);
    GuardedBuffer full_secret(kSharedSecretSize);
    std::size_t ciphertext_len = short_ciphertext.capacity();
    std::size_t shared_secret_len = full_secret.capacity();
    EXPECT_EQ(iav_kem_encapsulate(test_case.algorithm,
                                  full_public_key.data(),
                                  full_public_key.size(),
                                  short_ciphertext.data(),
                                  &ciphertext_len,
                                  full_secret.data(),
                                  &shared_secret_len),
              IavStatusBufferTooSmall);
    EXPECT_EQ(ciphertext_len, test_case.ciphertext_size);
    EXPECT_EQ(shared_secret_len, kSharedSecretSize);
    EXPECT_TRUE(short_ciphertext.Unchanged());
    EXPECT_TRUE(full_secret.Unchanged());

    GuardedBuffer full_ciphertext(test_case.ciphertext_size);
    GuardedBuffer short_secret(kSharedSecretSize - 1U);
    ciphertext_len = full_ciphertext.capacity();
    shared_secret_len = short_secret.capacity();
    EXPECT_EQ(iav_kem_encapsulate(test_case.algorithm,
                                  full_public_key.data(),
                                  full_public_key.size(),
                                  full_ciphertext.data(),
                                  &ciphertext_len,
                                  short_secret.data(),
                                  &shared_secret_len),
              IavStatusBufferTooSmall);
    EXPECT_EQ(ciphertext_len, test_case.ciphertext_size);
    EXPECT_EQ(shared_secret_len, kSharedSecretSize);
    EXPECT_TRUE(full_ciphertext.Unchanged());
    EXPECT_TRUE(short_secret.Unchanged());

    std::vector<std::uint8_t> ciphertext(test_case.ciphertext_size);
    std::vector<std::uint8_t> encapsulated_secret(kSharedSecretSize);
    ciphertext_len = ciphertext.size();
    shared_secret_len = encapsulated_secret.size();
    ASSERT_EQ(iav_kem_encapsulate(test_case.algorithm,
                                  full_public_key.data(),
                                  full_public_key.size(),
                                  ciphertext.data(),
                                  &ciphertext_len,
                                  encapsulated_secret.data(),
                                  &shared_secret_len),
              IavStatusOk);

    GuardedBuffer short_decapsulated_secret(kSharedSecretSize - 1U);
    shared_secret_len = short_decapsulated_secret.capacity();
    EXPECT_EQ(
        iav_kem_decapsulate(
            key.get(), ciphertext.data(), ciphertext.size(), short_decapsulated_secret.data(), &shared_secret_len),
        IavStatusBufferTooSmall);
    EXPECT_EQ(shared_secret_len, kSharedSecretSize);
    EXPECT_TRUE(short_decapsulated_secret.Unchanged());
}

TEST_P(MlKemFunctionalTest, RejectsInvalidArgumentsAndPreservesOutputBuffers)
{
    const KemCase& test_case = GetParam();
    const KeyHandle key = GenerateKemKey(test_case.algorithm);
    ASSERT_NE(key, nullptr);

    std::vector<std::uint8_t> public_key(test_case.public_key_size);
    std::size_t public_key_len = public_key.size();
    ASSERT_EQ(iav_kem_public_key_export(key.get(), public_key.data(), &public_key_len), IavStatusOk);

    GuardedBuffer exported_public_key(test_case.public_key_size);
    std::size_t exported_public_key_len = exported_public_key.capacity();
    EXPECT_EQ(iav_kem_public_key_export(key.get(), exported_public_key.data(), nullptr), IavStatusInvalidArgument);
    EXPECT_EQ(iav_kem_public_key_export(key.get(), nullptr, &exported_public_key_len), IavStatusInvalidArgument);
    EXPECT_EQ(exported_public_key_len, exported_public_key.capacity());
    EXPECT_TRUE(exported_public_key.Unchanged());

    GuardedBuffer ciphertext(test_case.ciphertext_size);
    GuardedBuffer shared_secret(kSharedSecretSize);
    std::size_t ciphertext_len = ciphertext.capacity();
    std::size_t shared_secret_len = shared_secret.capacity();
    EXPECT_EQ(iav_kem_encapsulate(test_case.algorithm,
                                  nullptr,
                                  public_key.size(),
                                  ciphertext.data(),
                                  &ciphertext_len,
                                  shared_secret.data(),
                                  &shared_secret_len),
              IavStatusInvalidArgument);
    EXPECT_EQ(iav_kem_encapsulate(test_case.algorithm,
                                  public_key.data(),
                                  public_key.size() - 1U,
                                  ciphertext.data(),
                                  &ciphertext_len,
                                  shared_secret.data(),
                                  &shared_secret_len),
              IavStatusInvalidArgument);
    EXPECT_EQ(iav_kem_encapsulate(test_case.algorithm,
                                  public_key.data(),
                                  public_key.size(),
                                  ciphertext.data(),
                                  nullptr,
                                  shared_secret.data(),
                                  &shared_secret_len),
              IavStatusInvalidArgument);
    EXPECT_EQ(iav_kem_encapsulate(test_case.algorithm,
                                  public_key.data(),
                                  public_key.size(),
                                  ciphertext.data(),
                                  &ciphertext_len,
                                  shared_secret.data(),
                                  nullptr),
              IavStatusInvalidArgument);
    EXPECT_EQ(iav_kem_encapsulate(test_case.algorithm,
                                  public_key.data(),
                                  public_key.size(),
                                  nullptr,
                                  &ciphertext_len,
                                  shared_secret.data(),
                                  &shared_secret_len),
              IavStatusInvalidArgument);
    EXPECT_EQ(iav_kem_encapsulate(test_case.algorithm,
                                  public_key.data(),
                                  public_key.size(),
                                  ciphertext.data(),
                                  &ciphertext_len,
                                  nullptr,
                                  &shared_secret_len),
              IavStatusInvalidArgument);
    EXPECT_EQ(ciphertext_len, ciphertext.capacity());
    EXPECT_EQ(shared_secret_len, shared_secret.capacity());
    EXPECT_TRUE(ciphertext.Unchanged());
    EXPECT_TRUE(shared_secret.Unchanged());

    EXPECT_EQ(iav_kem_encapsulate(IavAlgorithmMlDsa44,
                                  public_key.data(),
                                  public_key.size(),
                                  ciphertext.data(),
                                  &ciphertext_len,
                                  shared_secret.data(),
                                  &shared_secret_len),
              IavStatusInvalidArgument);
    EXPECT_EQ(iav_kem_encapsulate(IavAlgorithmHqc128,
                                  public_key.data(),
                                  public_key.size(),
                                  ciphertext.data(),
                                  &ciphertext_len,
                                  shared_secret.data(),
                                  &shared_secret_len),
              IavStatusUnsupportedAlgorithm);

    EXPECT_EQ(iav_kem_decapsulate(key.get(), nullptr, 0U, shared_secret.data(), &shared_secret_len),
              IavStatusInvalidArgument);
    EXPECT_EQ(iav_kem_decapsulate(
                  key.get(), ciphertext.data(), ciphertext.capacity() - 1U, shared_secret.data(), &shared_secret_len),
              IavStatusInvalidArgument);
    EXPECT_EQ(iav_kem_decapsulate(key.get(), ciphertext.data(), ciphertext.capacity(), shared_secret.data(), nullptr),
              IavStatusInvalidArgument);
    EXPECT_EQ(iav_kem_decapsulate(key.get(), ciphertext.data(), ciphertext.capacity(), nullptr, &shared_secret_len),
              IavStatusInvalidArgument);
    EXPECT_EQ(shared_secret_len, shared_secret.capacity());
    EXPECT_TRUE(shared_secret.Unchanged());
}

TEST_P(MlKemFunctionalTest, SupportsUnalignedBuffersAndPreservesCanaries)
{
    const KemCase& test_case = GetParam();
    const KeyHandle key = GenerateKemKey(test_case.algorithm);
    ASSERT_NE(key, nullptr);

    GuardedBuffer public_key(test_case.public_key_size);
    GuardedBuffer ciphertext(test_case.ciphertext_size);
    GuardedBuffer encapsulated_secret(kSharedSecretSize);
    GuardedBuffer decapsulated_secret(kSharedSecretSize);
    ASSERT_TRUE(public_key.IsUnaligned());
    ASSERT_TRUE(ciphertext.IsUnaligned());
    ASSERT_TRUE(encapsulated_secret.IsUnaligned());
    ASSERT_TRUE(decapsulated_secret.IsUnaligned());

    std::size_t public_key_len = public_key.capacity();
    ASSERT_EQ(iav_kem_public_key_export(key.get(), public_key.data(), &public_key_len), IavStatusOk);
    EXPECT_EQ(public_key_len, test_case.public_key_size);

    std::size_t ciphertext_len = ciphertext.capacity();
    std::size_t encapsulated_secret_len = encapsulated_secret.capacity();
    ASSERT_EQ(iav_kem_encapsulate(test_case.algorithm,
                                  public_key.data(),
                                  public_key_len,
                                  ciphertext.data(),
                                  &ciphertext_len,
                                  encapsulated_secret.data(),
                                  &encapsulated_secret_len),
              IavStatusOk);
    EXPECT_EQ(ciphertext_len, test_case.ciphertext_size);
    EXPECT_EQ(encapsulated_secret_len, kSharedSecretSize);

    std::size_t decapsulated_secret_len = decapsulated_secret.capacity();
    ASSERT_EQ(iav_kem_decapsulate(
                  key.get(), ciphertext.data(), ciphertext_len, decapsulated_secret.data(), &decapsulated_secret_len),
              IavStatusOk);
    EXPECT_EQ(decapsulated_secret_len, kSharedSecretSize);
    EXPECT_EQ(std::memcmp(encapsulated_secret.data(), decapsulated_secret.data(), encapsulated_secret_len), 0);
    EXPECT_TRUE(public_key.CanariesIntact());
    EXPECT_TRUE(ciphertext.CanariesIntact());
    EXPECT_TRUE(encapsulated_secret.CanariesIntact());
    EXPECT_TRUE(decapsulated_secret.CanariesIntact());
}

INSTANTIATE_TEST_SUITE_P(AllSupportedParameterSets,
                         MlKemFunctionalTest,
                         ::testing::Values(KemCase{"ML_KEM_512", IavAlgorithmMlKem512, 800U, 768U},
                                           KemCase{"ML_KEM_768", IavAlgorithmMlKem768, 1184U, 1088U},
                                           KemCase{"ML_KEM_1024", IavAlgorithmMlKem1024, 1568U, 1568U}),
                         [](const ::testing::TestParamInfo<KemCase>& info) {
                             return info.param.test_name;
                         });

class FfiEdgeCaseTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        ASSERT_EQ(RegisterTestRandomBytesProvider(), IavStatusOk);
    }
};

TEST_F(FfiEdgeCaseTest, RejectsNullUnsupportedAndCrossFamilyKeyGenerationArguments)
{
    iav_primula_key_handle* output_key = nullptr;
    EXPECT_EQ(iav_keypair_generate(IavAlgorithmMlDsa44, nullptr), IavStatusInvalidArgument);
    EXPECT_EQ(iav_kem_keypair_generate(IavAlgorithmMlKem512, nullptr), IavStatusInvalidArgument);

    const KeyHandle signature_key = GenerateSignatureKey(IavAlgorithmMlDsa44);
    const KeyHandle kem_key = GenerateKemKey(IavAlgorithmMlKem512);
    ASSERT_NE(signature_key, nullptr);
    ASSERT_NE(kem_key, nullptr);

    output_key = signature_key.get();
    EXPECT_EQ(iav_keypair_generate(IavAlgorithmFnDsa512, &output_key), IavStatusUnsupportedAlgorithm);
    EXPECT_EQ(output_key, nullptr);
    output_key = signature_key.get();
    EXPECT_EQ(iav_keypair_generate(IavAlgorithmMlKem512, &output_key), IavStatusInvalidArgument);
    EXPECT_EQ(output_key, nullptr);
    output_key = kem_key.get();
    EXPECT_EQ(iav_kem_keypair_generate(IavAlgorithmHqc128, &output_key), IavStatusUnsupportedAlgorithm);
    EXPECT_EQ(output_key, nullptr);
    output_key = kem_key.get();
    EXPECT_EQ(iav_kem_keypair_generate(IavAlgorithmMlDsa44, &output_key), IavStatusInvalidArgument);
    EXPECT_EQ(output_key, nullptr);
}

TEST_F(FfiEdgeCaseTest, RejectsNullAndWrongFamilyKeyHandlesAndAllowsNullDestruction)
{
    const KeyHandle signature_key = GenerateSignatureKey(IavAlgorithmMlDsa44);
    const KeyHandle kem_key = GenerateKemKey(IavAlgorithmMlKem512);
    ASSERT_NE(signature_key, nullptr);
    ASSERT_NE(kem_key, nullptr);

    std::array<std::uint8_t, 1U> byte_buffer{};
    std::size_t output_len = byte_buffer.size();
    EXPECT_EQ(iav_public_key_export(nullptr, byte_buffer.data(), &output_len), IavStatusInvalidArgument);
    EXPECT_EQ(iav_public_key_export(kem_key.get(), byte_buffer.data(), &output_len), IavStatusInvalidArgument);
    EXPECT_EQ(iav_kem_public_key_export(nullptr, byte_buffer.data(), &output_len), IavStatusInvalidArgument);
    EXPECT_EQ(iav_kem_public_key_export(signature_key.get(), byte_buffer.data(), &output_len),
              IavStatusInvalidArgument);
    EXPECT_EQ(iav_sign(nullptr, byte_buffer.data(), byte_buffer.size(), byte_buffer.data(), &output_len),
              IavStatusInvalidArgument);
    EXPECT_EQ(iav_sign(kem_key.get(), byte_buffer.data(), byte_buffer.size(), byte_buffer.data(), &output_len),
              IavStatusInvalidArgument);
    EXPECT_EQ(iav_verify(nullptr, byte_buffer.data(), byte_buffer.size(), byte_buffer.data(), byte_buffer.size()),
              IavStatusInvalidArgument);
    EXPECT_EQ(iav_verify(kem_key.get(), byte_buffer.data(), byte_buffer.size(), byte_buffer.data(), byte_buffer.size()),
              IavStatusInvalidArgument);
    EXPECT_EQ(iav_kem_decapsulate(nullptr, byte_buffer.data(), byte_buffer.size(), byte_buffer.data(), &output_len),
              IavStatusInvalidArgument);
    EXPECT_EQ(iav_kem_decapsulate(
                  signature_key.get(), byte_buffer.data(), byte_buffer.size(), byte_buffer.data(), &output_len),
              IavStatusInvalidArgument);

    iav_key_destroy(nullptr);
}

TEST_F(FfiEdgeCaseTest, RejectsOverlappingKemOutputsAndLengthPointersWithoutWriting)
{
    const KeyHandle key = GenerateKemKey(IavAlgorithmMlKem512);
    ASSERT_NE(key, nullptr);

    std::array<std::uint8_t, kMlKem512PublicKeySize> public_key{};
    std::size_t public_key_len = public_key.size();
    ASSERT_EQ(iav_kem_public_key_export(key.get(), public_key.data(), &public_key_len), IavStatusOk);

    GuardedBuffer overlapping_outputs(kMlKem512CiphertextSize + kSharedSecretSize + 1U);
    std::size_t ciphertext_len = kMlKem512CiphertextSize;
    std::size_t shared_secret_len = kSharedSecretSize;
    EXPECT_EQ(iav_kem_encapsulate(IavAlgorithmMlKem512,
                                  public_key.data(),
                                  public_key_len,
                                  overlapping_outputs.data(),
                                  &ciphertext_len,
                                  overlapping_outputs.DataAt(1U),
                                  &shared_secret_len),
              IavStatusInvalidArgument);
    EXPECT_EQ(ciphertext_len, kMlKem512CiphertextSize);
    EXPECT_EQ(shared_secret_len, kSharedSecretSize);
    EXPECT_TRUE(overlapping_outputs.Unchanged());

    GuardedBuffer ciphertext(kMlKem512CiphertextSize);
    GuardedBuffer shared_secret(kSharedSecretSize);
    std::size_t aliased_length = ciphertext.capacity();
    EXPECT_EQ(iav_kem_encapsulate(IavAlgorithmMlKem512,
                                  public_key.data(),
                                  public_key_len,
                                  ciphertext.data(),
                                  &aliased_length,
                                  shared_secret.data(),
                                  &aliased_length),
              IavStatusInvalidArgument);
    EXPECT_EQ(aliased_length, ciphertext.capacity());
    EXPECT_TRUE(ciphertext.Unchanged());
    EXPECT_TRUE(shared_secret.Unchanged());
}

TEST_F(FfiEdgeCaseTest, ReportsRandomProviderFailuresAndLeavesCallerBuffersUnchanged)
{
    const KeyHandle key = GenerateKemKey(IavAlgorithmMlKem512);
    ASSERT_NE(key, nullptr);
    std::array<std::uint8_t, kMlKem512PublicKeySize> public_key{};
    std::size_t public_key_len = public_key.size();
    ASSERT_EQ(iav_kem_public_key_export(key.get(), public_key.data(), &public_key_len), IavStatusOk);

    iav_primula_key_handle* failed_key = nullptr;
    iav_status keygen_status = IavStatusOk;
    GuardedBuffer ciphertext(kMlKem512CiphertextSize);
    GuardedBuffer shared_secret(kSharedSecretSize);
    std::size_t ciphertext_len = ciphertext.capacity();
    std::size_t shared_secret_len = shared_secret.capacity();
    iav_status encapsulation_status = IavStatusOk;
    {
        const ScopedTestRngFailure failing_rng;
        keygen_status = iav_keypair_generate(IavAlgorithmMlDsa44, &failed_key);
        encapsulation_status = iav_kem_encapsulate(IavAlgorithmMlKem512,
                                                   public_key.data(),
                                                   public_key_len,
                                                   ciphertext.data(),
                                                   &ciphertext_len,
                                                   shared_secret.data(),
                                                   &shared_secret_len);
    }

    EXPECT_EQ(keygen_status, IavStatusCryptoFailure);
    EXPECT_EQ(failed_key, nullptr);
    EXPECT_EQ(encapsulation_status, IavStatusCryptoFailure);
    EXPECT_EQ(ciphertext_len, ciphertext.capacity());
    EXPECT_EQ(shared_secret_len, shared_secret.capacity());
    EXPECT_TRUE(ciphertext.Unchanged());
    EXPECT_TRUE(shared_secret.Unchanged());
}

TEST_F(FfiEdgeCaseTest, RejectsNullAndDuplicateRandomProviderRegistration)
{
    EXPECT_EQ(iav_random_bytes_provider_register(nullptr, nullptr), IavStatusInvalidArgument);
    EXPECT_EQ(iav_random_bytes_provider_register(FillTestRandomBytes, &GetTestRngContext()), IavStatusInvalidArgument);
}

}  // namespace
