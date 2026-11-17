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

#include "pqc_provider_ffi.h"

#include <oqs/common.h>
#include <oqs/kem.h>
#include <oqs/sig.h>

#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>

namespace
{

enum class KeyFamily : std::uint8_t
{
    kSignature,
    kKem,
};

const char* SignatureMethod(const pqc_provider_algorithm algorithm) noexcept
{
    switch (algorithm)
    {
        case PqcProviderAlgorithmMlDsa44:
            return "ML-DSA-44";
        case PqcProviderAlgorithmMlDsa65:
            return "ML-DSA-65";
        case PqcProviderAlgorithmMlDsa87:
            return "ML-DSA-87";
        default:
            return nullptr;
    }
}

const char* KemMethod(const pqc_provider_algorithm algorithm) noexcept
{
    switch (algorithm)
    {
        case PqcProviderAlgorithmMlKem512:
            return "ML-KEM-512";
        case PqcProviderAlgorithmMlKem768:
            return "ML-KEM-768";
        case PqcProviderAlgorithmMlKem1024:
            return "ML-KEM-1024";
        default:
            return nullptr;
    }
}

template <typename Operation>
pqc_provider_status GuardAbiCall(Operation operation) noexcept
{
    try
    {
        return operation();
    }
    catch (...)
    {
        return PqcProviderStatusCryptoFailure;
    }
}

bool IsValidInput(const std::uint8_t* const input, const std::size_t input_length) noexcept
{
    return input != nullptr || input_length == 0U;
}

pqc_provider_status ValidateKey(const pqc_provider_key_handle* key, KeyFamily family) noexcept;

}  // namespace

class pqc_provider_key_handle
{
  public:
    pqc_provider_key_handle(const pqc_provider_algorithm algorithm, const KeyFamily family) noexcept
        : algorithm_{algorithm}, family_{family}
    {
    }

    ~pqc_provider_key_handle()
    {
        if (!secret_key_.empty())
        {
            OQS_MEM_cleanse(secret_key_.data(), secret_key_.size());
        }
    }

    pqc_provider_key_handle(const pqc_provider_key_handle&) = delete;
    pqc_provider_key_handle& operator=(const pqc_provider_key_handle&) = delete;
    pqc_provider_key_handle(pqc_provider_key_handle&&) = delete;
    pqc_provider_key_handle& operator=(pqc_provider_key_handle&&) = delete;

    [[nodiscard]] pqc_provider_algorithm Algorithm() const noexcept
    {
        return algorithm_;
    }

    [[nodiscard]] KeyFamily Family() const noexcept
    {
        return family_;
    }

    [[nodiscard]] std::vector<std::uint8_t>& MutablePublicKey() noexcept
    {
        return public_key_;
    }

    [[nodiscard]] const std::vector<std::uint8_t>& PublicKey() const noexcept
    {
        return public_key_;
    }

    [[nodiscard]] std::vector<std::uint8_t>& MutableSecretKey() noexcept
    {
        return secret_key_;
    }

    [[nodiscard]] const std::vector<std::uint8_t>& SecretKey() const noexcept
    {
        return secret_key_;
    }

  private:
    pqc_provider_algorithm algorithm_{};
    KeyFamily family_{KeyFamily::kSignature};
    std::vector<std::uint8_t> public_key_;
    std::vector<std::uint8_t> secret_key_;
};

namespace
{

pqc_provider_status ValidateKey(const pqc_provider_key_handle* const key, const KeyFamily family) noexcept
{
    if (key == nullptr || key->Family() != family)
    {
        return PqcProviderStatusInvalidArgument;
    }
    return PqcProviderStatusOk;
}

}  // namespace

extern "C" {

pqc_provider_status pqc_provider_keypair_generate(const pqc_provider_algorithm algorithm, pqc_provider_key_handle** const key)
{
    return GuardAbiCall([&]() {
        if (key == nullptr)
        {
            return PqcProviderStatusInvalidArgument;
        }
        *key = nullptr;

        const char* const method = SignatureMethod(algorithm);
        if (method == nullptr)
        {
            return PqcProviderStatusUnsupportedAlgorithm;
        }

        std::unique_ptr<OQS_SIG, decltype(&OQS_SIG_free)> signature{OQS_SIG_new(method), &OQS_SIG_free};
        if (signature == nullptr)
        {
            return PqcProviderStatusCryptoFailure;
        }

        auto generated = std::make_unique<pqc_provider_key_handle>(algorithm, KeyFamily::kSignature);
        generated->MutablePublicKey().resize(signature->length_public_key);
        generated->MutableSecretKey().resize(signature->length_secret_key);
        if (OQS_SIG_keypair(signature.get(),
                            generated->MutablePublicKey().data(),
                            generated->MutableSecretKey().data()) != OQS_SUCCESS)
        {
            return PqcProviderStatusCryptoFailure;
        }

        *key = generated.release();
        return PqcProviderStatusOk;
    });
}

pqc_provider_status pqc_provider_public_key_export(const pqc_provider_key_handle* const key,
                                 std::uint8_t* const output,
                                 std::size_t* const output_len)
{
    if (key == nullptr || key->Family() != KeyFamily::kSignature || output == nullptr || output_len == nullptr)
    {
        return PqcProviderStatusInvalidArgument;
    }
    if (*output_len < key->PublicKey().size())
    {
        return PqcProviderStatusBufferTooSmall;
    }

    std::memcpy(output, key->PublicKey().data(), key->PublicKey().size());
    *output_len = key->PublicKey().size();
    return PqcProviderStatusOk;
}

pqc_provider_status pqc_provider_sign(const pqc_provider_key_handle* const key,
                    const std::uint8_t* const message,
                    const std::size_t message_len,
                    std::uint8_t* const signature_output,
                    std::size_t* const signature_len)
{
    return GuardAbiCall([&]() {
        if (ValidateKey(key, KeyFamily::kSignature) != PqcProviderStatusOk || !IsValidInput(message, message_len) ||
            signature_output == nullptr || signature_len == nullptr)
        {
            return PqcProviderStatusInvalidArgument;
        }

        std::unique_ptr<OQS_SIG, decltype(&OQS_SIG_free)> signature{OQS_SIG_new(SignatureMethod(key->Algorithm())),
                                                                    &OQS_SIG_free};
        if (signature == nullptr)
        {
            return PqcProviderStatusCryptoFailure;
        }
        const std::size_t capacity = *signature_len;
        if (capacity < signature->length_signature)
        {
            return PqcProviderStatusBufferTooSmall;
        }

        std::size_t actual_length = 0U;
        if (OQS_SIG_sign(
                signature.get(), signature_output, &actual_length, message, message_len, key->SecretKey().data()) !=
            OQS_SUCCESS)
        {
            return PqcProviderStatusCryptoFailure;
        }
        if (actual_length > capacity)
        {
            return PqcProviderStatusCryptoFailure;
        }
        *signature_len = actual_length;
        return PqcProviderStatusOk;
    });
}

pqc_provider_status pqc_provider_verify(const pqc_provider_key_handle* const key,
                      const std::uint8_t* const message,
                      const std::size_t message_len,
                      const std::uint8_t* const signature_input,
                      const std::size_t signature_len)
{
    return GuardAbiCall([&]() {
        if (ValidateKey(key, KeyFamily::kSignature) != PqcProviderStatusOk || !IsValidInput(message, message_len) ||
            signature_input == nullptr)
        {
            return PqcProviderStatusInvalidArgument;
        }

        const std::unique_ptr<OQS_SIG, decltype(&OQS_SIG_free)> signature{
            OQS_SIG_new(SignatureMethod(key->Algorithm())), &OQS_SIG_free};
        if (signature == nullptr)
        {
            return PqcProviderStatusCryptoFailure;
        }

        const OQS_STATUS result = OQS_SIG_verify(
            signature.get(), message, message_len, signature_input, signature_len, key->PublicKey().data());
        return result == OQS_SUCCESS ? PqcProviderStatusOk : PqcProviderStatusVerificationFailed;
    });
}

pqc_provider_status pqc_provider_verify_public_key(const pqc_provider_algorithm algorithm,
                                 const std::uint8_t* const public_key,
                                 const std::size_t public_key_len,
                                 const std::uint8_t* const message,
                                 const std::size_t message_len,
                                 const std::uint8_t* const signature_input,
                                 const std::size_t signature_len)
{
    return GuardAbiCall([&]() {
        const char* const method = SignatureMethod(algorithm);
        if (method == nullptr)
        {
            return PqcProviderStatusUnsupportedAlgorithm;
        }
        if (public_key == nullptr || !IsValidInput(message, message_len) || signature_input == nullptr)
        {
            return PqcProviderStatusInvalidArgument;
        }

        std::unique_ptr<OQS_SIG, decltype(&OQS_SIG_free)> signature{OQS_SIG_new(method), &OQS_SIG_free};
        if (signature == nullptr)
        {
            return PqcProviderStatusCryptoFailure;
        }
        if (public_key_len != signature->length_public_key)
        {
            return PqcProviderStatusInvalidArgument;
        }

        const OQS_STATUS result =
            OQS_SIG_verify(signature.get(), message, message_len, signature_input, signature_len, public_key);
        return result == OQS_SUCCESS ? PqcProviderStatusOk : PqcProviderStatusVerificationFailed;
    });
}

pqc_provider_status pqc_provider_kem_keypair_generate(const pqc_provider_algorithm algorithm, pqc_provider_key_handle** const key)
{
    return GuardAbiCall([&]() {
        if (key == nullptr)
        {
            return PqcProviderStatusInvalidArgument;
        }
        *key = nullptr;

        const char* const method = KemMethod(algorithm);
        if (method == nullptr)
        {
            return PqcProviderStatusUnsupportedAlgorithm;
        }

        std::unique_ptr<OQS_KEM, decltype(&OQS_KEM_free)> kem{OQS_KEM_new(method), &OQS_KEM_free};
        if (kem == nullptr)
        {
            return PqcProviderStatusCryptoFailure;
        }

        auto generated = std::make_unique<pqc_provider_key_handle>(algorithm, KeyFamily::kKem);
        generated->MutablePublicKey().resize(kem->length_public_key);
        generated->MutableSecretKey().resize(kem->length_secret_key);
        if (OQS_KEM_keypair(kem.get(), generated->MutablePublicKey().data(), generated->MutableSecretKey().data()) !=
            OQS_SUCCESS)
        {
            return PqcProviderStatusCryptoFailure;
        }

        *key = generated.release();
        return PqcProviderStatusOk;
    });
}

pqc_provider_status pqc_provider_kem_public_key_export(const pqc_provider_key_handle* const key,
                                     std::uint8_t* const output,
                                     std::size_t* const output_len)
{
    if (key == nullptr || key->Family() != KeyFamily::kKem || output == nullptr || output_len == nullptr)
    {
        return PqcProviderStatusInvalidArgument;
    }
    if (*output_len < key->PublicKey().size())
    {
        return PqcProviderStatusBufferTooSmall;
    }

    std::memcpy(output, key->PublicKey().data(), key->PublicKey().size());
    *output_len = key->PublicKey().size();
    return PqcProviderStatusOk;
}

pqc_provider_status pqc_provider_kem_encapsulate(const pqc_provider_algorithm algorithm,
                               const std::uint8_t* const public_key,
                               const std::size_t public_key_len,
                               std::uint8_t* const ciphertext,
                               std::size_t* const ciphertext_len,
                               std::uint8_t* const shared_secret,
                               std::size_t* const shared_secret_len)
{
    return GuardAbiCall([&]() {
        const char* const method = KemMethod(algorithm);
        if (method == nullptr)
        {
            return PqcProviderStatusUnsupportedAlgorithm;
        }
        if (public_key == nullptr || ciphertext == nullptr || ciphertext_len == nullptr || shared_secret == nullptr ||
            shared_secret_len == nullptr)
        {
            return PqcProviderStatusInvalidArgument;
        }

        std::unique_ptr<OQS_KEM, decltype(&OQS_KEM_free)> kem{OQS_KEM_new(method), &OQS_KEM_free};
        if (kem == nullptr)
        {
            return PqcProviderStatusCryptoFailure;
        }
        if (public_key_len != kem->length_public_key)
        {
            return PqcProviderStatusInvalidArgument;
        }
        const std::size_t ciphertext_capacity = *ciphertext_len;
        const std::size_t shared_secret_capacity = *shared_secret_len;
        if (ciphertext_capacity < kem->length_ciphertext || shared_secret_capacity < kem->length_shared_secret)
        {
            return PqcProviderStatusBufferTooSmall;
        }

        if (OQS_KEM_encaps(kem.get(), ciphertext, shared_secret, public_key) != OQS_SUCCESS)
        {
            return PqcProviderStatusCryptoFailure;
        }
        *ciphertext_len = kem->length_ciphertext;
        *shared_secret_len = kem->length_shared_secret;
        return PqcProviderStatusOk;
    });
}

pqc_provider_status pqc_provider_kem_decapsulate(const pqc_provider_key_handle* const key,
                               const std::uint8_t* const ciphertext,
                               const std::size_t ciphertext_len,
                               std::uint8_t* const shared_secret,
                               std::size_t* const shared_secret_len)
{
    return GuardAbiCall([&]() {
        if (ValidateKey(key, KeyFamily::kKem) != PqcProviderStatusOk || ciphertext == nullptr || shared_secret == nullptr ||
            shared_secret_len == nullptr)
        {
            return PqcProviderStatusInvalidArgument;
        }

        const char* const method = KemMethod(key->Algorithm());
        if (method == nullptr)
        {
            return PqcProviderStatusCryptoFailure;
        }
        std::unique_ptr<OQS_KEM, decltype(&OQS_KEM_free)> kem{OQS_KEM_new(method), &OQS_KEM_free};
        if (kem == nullptr)
        {
            return PqcProviderStatusCryptoFailure;
        }
        if (ciphertext_len != kem->length_ciphertext)
        {
            return PqcProviderStatusInvalidArgument;
        }
        const std::size_t capacity = *shared_secret_len;
        if (capacity < kem->length_shared_secret)
        {
            return PqcProviderStatusBufferTooSmall;
        }

        if (OQS_KEM_decaps(kem.get(), shared_secret, ciphertext, key->SecretKey().data()) != OQS_SUCCESS)
        {
            return PqcProviderStatusCryptoFailure;
        }
        *shared_secret_len = kem->length_shared_secret;
        return PqcProviderStatusOk;
    });
}

void pqc_provider_key_destroy(pqc_provider_key_handle* const key)
{
    const std::unique_ptr<pqc_provider_key_handle> owned_key{key};
}

}  // extern "C"
