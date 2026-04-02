# 📖 Contribution Proposal: Comprehensive Crypto, Security & Identity Stack for Eclipse S-Core

## 1. Motivation
* **Unified Security Foundation:** For the S-Core 1.0 release, a robust, standardized security layer is mandatory. This requires a seamless integration of Cryptography, Key/Certificate Management, and User Management.
* **Standardized Interfaces:** Applications require clear APIs for authentication, authorization, hashing, and encryption, backed by industry standards like PKCS#11 for key management.
* **Crypto-Agility & The Quantum Threat:** Software Defined Vehicles (SDVs) must remain secure over their entire lifecycle. The architecture must support current classical cryptography while being fully prepared to integrate upcoming Post-Quantum Cryptography (PQC) standards without altering application logic.

## 2. Proposed Contribution
We propose contributing the complete foundational **Crypto, Security & Identity Stack** to fulfill the S-Core 1.0 feature requests. Our contribution establishes a highly modular, crypto-agile architecture that serves as the central security authority.

We will provide the standardized APIs and service logic for Crypto, Key Management, and User Management. As a major addition to ensure immediate crypto-agility, we will also integrate a fully functional Post-Quantum provider based on [**PQClean Automotive**](https://github.com/iavofficial/PQCleanAutomotive), our open-source, embedded-ready PQC library.

This approach is backed by our practical experience at IAV, where we successfully build and integrate modular, PQC-ready crypto architectures (like "IAV Primula") for complex automotive systems.

## 3. High-Level Architecture
Our architecture securely separates application requests from the underlying cryptographic and system-level implementations.

1. **Eclipse S-Core Application Layer:** Applications request security services via generic APIs.
2. **S-Core Security Services (Our Core Contribution):**
    * **Crypto API:** Provides generic interfaces to compute Cryptographic Hashes (init, ingest, finalize, output), generate and authenticate digital signatures, and handle symmetric en-/decryption.
    * **Key & Certificate Management:** Tightly coupled with the Crypto API. It handles secure key derivation, secure storage (covering all extensive key management capabilities known from AUTOSAR), as well as storing and verifying certificates, and extracting keys directly from certificates.
    * **User Management:** Local in-device user and resource access control, handling privilege management for applications and APIs (designed with POSIX compliance and QNX 8.0 readiness in mind).
3. **Crypto Provider Interface (Abstraction Layer):** A standardized adapter routing API calls to the appropriate backend.
4. **Pluggable Cryptographic Providers:**
    * **Classical Provider:** Hardware or software modules for standard algorithms (AES, RSA, ECC).
    * **IAV PQC Provider:** Seamlessly integrates PQClean Automotive, handling Bazel build rules, FFI (Rust/C/C++), and context management for NIST PQC candidates.

## 4. Supported Algorithms & PQC Expertise
Alongside the architectural framework for classical cryptography, we bring deep expertise in NIST-standardized PQC algorithms to future-proof the stack:

* **ML-KEM (CRYSTALS-Kyber):** Highly performant, quantum-safe foundation for key exchange in resource-constrained environments.
* **HQC (Hamming Quasi-Cyclic):** Code-based KEM alternative with distinct security assumptions.
* **ML-DSA (CRYSTALS-Dilithium):** Lattice-based signatures optimized for Secure Boot, firmware updates, and authentication.
* **FN-DSA (Falcon):** Lattice-based signatures utilized for highly compact signature requirements.
* **SLH-DSA (SPHINCS+):** Hash-based, stateless signatures for maximum security use cases.

## 5. Proven Performance & Stack Expertise
PQC algorithms require significant computing resources. We have already conducted extensive runtime and memory measurements of these algorithms on embedded automotive hardware (Infineon Aurix TC3), proving their real-world feasibility for vehicle microcontrollers.

Furthermore, at IAV, we have already designed and developed our own internal AUTOSAR stack, successfully integrating these PQC algorithms natively. This hands-on experience proves our deep understanding of not just individual algorithms, but of creating, integrating, and managing an entire, production-ready Security Stack from the ground up.

## 6. Proof of Concept
This proposal already includes a small integrated module (`pqc_iav_contribution:pqc_crypto`) which demonstrates the basic integration and usage of the PQClean Automotive library (All mentioned algorithms and their variants) within the S-Core toolchain. Please note that this is currently intended as a minimal usage example for the scope of this proposal and does not yet represent the final, fully-featured S-Core PQC Adapter.

---
## 🚀 Getting Started

### 1️⃣ Clone the Repository

```sh
git clone https://https://github.com/iavofficial/inc_security_crypto.git
cd inc_security_crypto
```

### 2️⃣ Build the Examples of module

> DISCLAIMER: Depending what module implements, it's possible that different
> configuration flags needs to be set on command line.

To build all targets of the module the following command can be used:

```sh
bazel build //src/...
```

This command will instruct Bazel to build all targets that are under Bazel
package `src/`. The ideal solution is to provide single target that builds
artifacts, for example:

```sh
bazel build //src/pqc_iav_contribution:pqc_crypto
```

### 3️⃣ Run Tests

```sh
bazel test //tests/...
```

---

## 🛠 Tools & Linters

The template integrates **tools and linters** from **centralized repositories** to ensure consistency across projects.

- **C++:** `clang-tidy`, `cppcheck`, `Google Test`
- **Rust:** `clippy`, `rustfmt`, `Rust Unit Tests`
- **CI/CD:** GitHub Actions for automated builds and tests

---
