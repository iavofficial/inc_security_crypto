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

#include "iav_primula_ffi.h"

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

const char* SignatureMethod(const iav_algorithm algorithm) noexcept
{
    switch (algorithm)
    {
        case IavAlgorithmMlDsa44:
            return "ML-DSA-44";
        case IavAlgorithmMlDsa65:
            return "ML-DSA-65";
        case IavAlgorithmMlDsa87:
            return "ML-DSA-87";
        default:
            return nullptr;
    }
}

const char* KemMethod(const iav_algorithm algorithm) noexcept
{
    switch (algorithm)
    {
        case IavAlgorithmMlKem512:
            return "ML-KEM-512";
        case IavAlgorithmMlKem768:
            return "ML-KEM-768";
        case IavAlgorithmMlKem1024:
            return "ML-KEM-1024";
        default:
            return nullptr;
    }
}

template <typename Operation>
iav_status GuardAbiCall(Operation operation) noexcept
{
    try
    {
        return operation();
    }
    catch (...)
    {
        return IavStatusCryptoFailure;
    }
}

bool IsValidInput(const std::uint8_t* const input, const std::size_t input_length) noexcept
{
    return input != nullptr || input_length == 0U;
}

iav_status ValidateKey(const iav_primula_key_handle* key, KeyFamily family) noexcept;

}  // namespace

class iav_primula_key_handle
{
  public:
    iav_primula_key_handle(const iav_algorithm algorithm, const KeyFamily family) noexcept
        : algorithm_{algorithm}, family_{family}
    {
    }

    ~iav_primula_key_handle()
    {
        if (!secret_key_.empty())
        {
            OQS_MEM_cleanse(secret_key_.data(), secret_key_.size());
        }
    }

    iav_primula_key_handle(const iav_primula_key_handle&) = delete;
    iav_primula_key_handle& operator=(const iav_primula_key_handle&) = delete;
    iav_primula_key_handle(iav_primula_key_handle&&) = delete;
    iav_primula_key_handle& operator=(iav_primula_key_handle&&) = delete;

    [[nodiscard]] iav_algorithm Algorithm() const noexcept
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
    iav_algorithm algorithm_{};
    KeyFamily family_{KeyFamily::kSignature};
    std::vector<std::uint8_t> public_key_;
    std::vector<std::uint8_t> secret_key_;
};

namespace
{

iav_status ValidateKey(const iav_primula_key_handle* const key, const KeyFamily family) noexcept
{
    if (key == nullptr || key->Family() != family)
    {
        return IavStatusInvalidArgument;
    }
    return IavStatusOk;
}

}  // namespace

extern "C" {

iav_status iav_keypair_generate(const iav_algorithm algorithm, iav_primula_key_handle** const key)
{
    return GuardAbiCall([&]() {
        if (key == nullptr)
        {
            return IavStatusInvalidArgument;
        }
        *key = nullptr;

        const char* const method = SignatureMethod(algorithm);
        if (method == nullptr)
        {
            return IavStatusUnsupportedAlgorithm;
        }

        std::unique_ptr<OQS_SIG, decltype(&OQS_SIG_free)> signature{OQS_SIG_new(method), &OQS_SIG_free};
        if (signature == nullptr)
        {
            return IavStatusCryptoFailure;
        }

        auto generated = std::make_unique<iav_primula_key_handle>(algorithm, KeyFamily::kSignature);
        generated->MutablePublicKey().resize(signature->length_public_key);
        generated->MutableSecretKey().resize(signature->length_secret_key);
        if (OQS_SIG_keypair(signature.get(),
                            generated->MutablePublicKey().data(),
                            generated->MutableSecretKey().data()) != OQS_SUCCESS)
        {
            return IavStatusCryptoFailure;
        }

        *key = generated.release();
        return IavStatusOk;
    });
}

iav_status iav_public_key_export(const iav_primula_key_handle* const key,
                                 std::uint8_t* const output,
                                 std::size_t* const output_len)
{
    if (key == nullptr || key->Family() != KeyFamily::kSignature || output == nullptr || output_len == nullptr)
    {
        return IavStatusInvalidArgument;
    }
    if (*output_len < key->PublicKey().size())
    {
        return IavStatusBufferTooSmall;
    }

    std::memcpy(output, key->PublicKey().data(), key->PublicKey().size());
    *output_len = key->PublicKey().size();
    return IavStatusOk;
}

iav_status iav_sign(const iav_primula_key_handle* const key,
                    const std::uint8_t* const message,
                    const std::size_t message_len,
                    std::uint8_t* const signature_output,
                    std::size_t* const signature_len)
{
    return GuardAbiCall([&]() {
        if (ValidateKey(key, KeyFamily::kSignature) != IavStatusOk || !IsValidInput(message, message_len) ||
            signature_output == nullptr || signature_len == nullptr)
        {
            return IavStatusInvalidArgument;
        }

        std::unique_ptr<OQS_SIG, decltype(&OQS_SIG_free)> signature{OQS_SIG_new(SignatureMethod(key->Algorithm())),
                                                                    &OQS_SIG_free};
        if (signature == nullptr)
        {
            return IavStatusCryptoFailure;
        }
        const std::size_t capacity = *signature_len;
        if (capacity < signature->length_signature)
        {
            return IavStatusBufferTooSmall;
        }

        std::size_t actual_length = 0U;
        if (OQS_SIG_sign(
                signature.get(), signature_output, &actual_length, message, message_len, key->SecretKey().data()) !=
            OQS_SUCCESS)
        {
            return IavStatusCryptoFailure;
        }
        if (actual_length > capacity)
        {
            return IavStatusCryptoFailure;
        }
        *signature_len = actual_length;
        return IavStatusOk;
    });
}

iav_status iav_verify(const iav_primula_key_handle* const key,
                      const std::uint8_t* const message,
                      const std::size_t message_len,
                      const std::uint8_t* const signature_input,
                      const std::size_t signature_len)
{
    return GuardAbiCall([&]() {
        if (ValidateKey(key, KeyFamily::kSignature) != IavStatusOk || !IsValidInput(message, message_len) ||
            signature_input == nullptr)
        {
            return IavStatusInvalidArgument;
        }

        const std::unique_ptr<OQS_SIG, decltype(&OQS_SIG_free)> signature{
            OQS_SIG_new(SignatureMethod(key->Algorithm())), &OQS_SIG_free};
        if (signature == nullptr)
        {
            return IavStatusCryptoFailure;
        }

        const OQS_STATUS result = OQS_SIG_verify(
            signature.get(), message, message_len, signature_input, signature_len, key->PublicKey().data());
        return result == OQS_SUCCESS ? IavStatusOk : IavStatusVerificationFailed;
    });
}

iav_status iav_verify_public_key(const iav_algorithm algorithm,
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
            return IavStatusUnsupportedAlgorithm;
        }
        if (public_key == nullptr || !IsValidInput(message, message_len) || signature_input == nullptr)
        {
            return IavStatusInvalidArgument;
        }

        std::unique_ptr<OQS_SIG, decltype(&OQS_SIG_free)> signature{OQS_SIG_new(method), &OQS_SIG_free};
        if (signature == nullptr)
        {
            return IavStatusCryptoFailure;
        }
        if (public_key_len != signature->length_public_key)
        {
            return IavStatusInvalidArgument;
        }

        const OQS_STATUS result =
            OQS_SIG_verify(signature.get(), message, message_len, signature_input, signature_len, public_key);
        return result == OQS_SUCCESS ? IavStatusOk : IavStatusVerificationFailed;
    });
}

iav_status iav_kem_keypair_generate(const iav_algorithm algorithm, iav_primula_key_handle** const key)
{
    return GuardAbiCall([&]() {
        if (key == nullptr)
        {
            return IavStatusInvalidArgument;
        }
        *key = nullptr;

        const char* const method = KemMethod(algorithm);
        if (method == nullptr)
        {
            return IavStatusUnsupportedAlgorithm;
        }

        std::unique_ptr<OQS_KEM, decltype(&OQS_KEM_free)> kem{OQS_KEM_new(method), &OQS_KEM_free};
        if (kem == nullptr)
        {
            return IavStatusCryptoFailure;
        }

        auto generated = std::make_unique<iav_primula_key_handle>(algorithm, KeyFamily::kKem);
        generated->MutablePublicKey().resize(kem->length_public_key);
        generated->MutableSecretKey().resize(kem->length_secret_key);
        if (OQS_KEM_keypair(kem.get(), generated->MutablePublicKey().data(), generated->MutableSecretKey().data()) !=
            OQS_SUCCESS)
        {
            return IavStatusCryptoFailure;
        }

        *key = generated.release();
        return IavStatusOk;
    });
}

iav_status iav_kem_public_key_export(const iav_primula_key_handle* const key,
                                     std::uint8_t* const output,
                                     std::size_t* const output_len)
{
    if (key == nullptr || key->Family() != KeyFamily::kKem || output == nullptr || output_len == nullptr)
    {
        return IavStatusInvalidArgument;
    }
    if (*output_len < key->PublicKey().size())
    {
        return IavStatusBufferTooSmall;
    }

    std::memcpy(output, key->PublicKey().data(), key->PublicKey().size());
    *output_len = key->PublicKey().size();
    return IavStatusOk;
}

iav_status iav_kem_encapsulate(const iav_algorithm algorithm,
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
            return IavStatusUnsupportedAlgorithm;
        }
        if (public_key == nullptr || ciphertext == nullptr || ciphertext_len == nullptr || shared_secret == nullptr ||
            shared_secret_len == nullptr)
        {
            return IavStatusInvalidArgument;
        }

        std::unique_ptr<OQS_KEM, decltype(&OQS_KEM_free)> kem{OQS_KEM_new(method), &OQS_KEM_free};
        if (kem == nullptr)
        {
            return IavStatusCryptoFailure;
        }
        if (public_key_len != kem->length_public_key)
        {
            return IavStatusInvalidArgument;
        }
        const std::size_t ciphertext_capacity = *ciphertext_len;
        const std::size_t shared_secret_capacity = *shared_secret_len;
        if (ciphertext_capacity < kem->length_ciphertext || shared_secret_capacity < kem->length_shared_secret)
        {
            return IavStatusBufferTooSmall;
        }

        if (OQS_KEM_encaps(kem.get(), ciphertext, shared_secret, public_key) != OQS_SUCCESS)
        {
            return IavStatusCryptoFailure;
        }
        *ciphertext_len = kem->length_ciphertext;
        *shared_secret_len = kem->length_shared_secret;
        return IavStatusOk;
    });
}

iav_status iav_kem_decapsulate(const iav_primula_key_handle* const key,
                               const std::uint8_t* const ciphertext,
                               const std::size_t ciphertext_len,
                               std::uint8_t* const shared_secret,
                               std::size_t* const shared_secret_len)
{
    return GuardAbiCall([&]() {
        if (ValidateKey(key, KeyFamily::kKem) != IavStatusOk || ciphertext == nullptr || shared_secret == nullptr ||
            shared_secret_len == nullptr)
        {
            return IavStatusInvalidArgument;
        }

        const char* const method = KemMethod(key->Algorithm());
        if (method == nullptr)
        {
            return IavStatusCryptoFailure;
        }
        std::unique_ptr<OQS_KEM, decltype(&OQS_KEM_free)> kem{OQS_KEM_new(method), &OQS_KEM_free};
        if (kem == nullptr)
        {
            return IavStatusCryptoFailure;
        }
        if (ciphertext_len != kem->length_ciphertext)
        {
            return IavStatusInvalidArgument;
        }
        const std::size_t capacity = *shared_secret_len;
        if (capacity < kem->length_shared_secret)
        {
            return IavStatusBufferTooSmall;
        }

        if (OQS_KEM_decaps(kem.get(), shared_secret, ciphertext, key->SecretKey().data()) != OQS_SUCCESS)
        {
            return IavStatusCryptoFailure;
        }
        *shared_secret_len = kem->length_shared_secret;
        return IavStatusOk;
    });
}

void iav_key_destroy(iav_primula_key_handle* const key)
{
    const std::unique_ptr<iav_primula_key_handle> owned_key{key};
}

}  // extern "C"
