
# C++ & Rust Bazel Template Repository

This repository serves as a **template** for setting up **C++ and Rust projects** using **Bazel**.
It provides a **standardized project structure**, ensuring best practices for:

- **Build configuration** with Bazel.
- **Testing** (unit and integration tests).
- **Documentation** setup.
- **CI/CD workflows**.
- **Development environment** configuration.

---

## 📂 Project Structure

| File/Folder                         | Description                                       |
| ----------------------------------- | ------------------------------------------------- |
| `README.md`                         | Short description & build instructions            |
| `src/`                              | Source files for the module                       |
| `tests/`                            | Unit tests (UT) and integration tests (IT)        |
| `examples/`                         | Example files used for guidance                   |
| `docs/`                             | Documentation (Doxygen for C++ / mdBook for Rust) |
| `.github/workflows/`                | CI/CD pipelines                                   |
| `.vscode/`                          | Recommended VS Code settings                      |
| `.bazelrc`, `MODULE.bazel`, `BUILD` | Bazel configuration & settings                    |
| `project_config.bzl`                | Project-specific metadata for Bazel macros        |
| `LICENSE.md`                        | Licensing information                             |
| `CONTRIBUTION.md`                   | Contribution guidelines                           |

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
# 📖 Contribution Proposal: Post-Quantum Cryptography (PQC) for Eclipse S-Core

## 1. Motivation
* **The Quantum Threat:** Quantum computers could become available in the next 5 to 10 years, putting current asymmetric cryptography and digital infrastructures at risk.
* **Lack of Hardware Support:** Upcoming microcontroller generations lack hardware support for the new NIST post-quantum cryptography (PQC) standards. Therefore, software-based PQC calculation is strictly required.
* **Crypto-Agility for SDVs:** Software Defined Vehicles require flexible, updatable cryptographic algorithms over their entire service life.

## 2. Proposed Contribution
We propose contributing a reliable, modular PQC integration for Eclipse S-Core based on [**PQClean Automotive**](https://github.com/iavofficial/PQCleanAutomotive), our open-source, embedded-ready PQC library. This library represents the world's first implementation of NIST PQC candidates specifically optimized for embedded systems. It is designed to be open-source, transparent, secure, and free of backdoors.

Our approach is heavily backed by our practical experience. Internally, we successfully integrate PQClean Automotive into AUTOSAR architectures using our product "IAV Primula", which acts as a Crypto Driver Software (Cry SW PQC) connecting seamlessly to the Crypto Service Manager.

We plan to transfer this proven, two-part architecture to Eclipse S-Core:

* **PQClean Automotive (Core):** A highly modular, platform-independent library containing the mathematical PQC algorithms. It is currently available in MISRA-C, with individual algorithms already being ported to Rust. It provides a scalable, lifelong updatable solution ensuring true crypto agility.
* **S-Core PQC Adapter (Wrapper):** A platform-dependent integration layer designed specifically for this project. This adapter connects the PQClean Automotive core seamlessly into the S-Core ecosystem's native crypto interfaces. It handles the Bazel build rules, Foreign Function Interfaces (FFI) between C and Rust, and necessary context management.

By clearly separating the cryptographic logic from the platform-specific implementation, S-Core will gain a flexible foundation that can easily be extended with future NIST standardized algorithms (e.g., NIST selection round 4) without altering the core infrastructure.
## 3. High-Level Architecture
Our architecture strictly separates the cryptographic logic from the platform-specific implementation.

1. **Eclipse S-Core Application Layer**
2. **S-Core Crypto Interface** (Standardized API)
3. **S-Core PQC Adapter** (*Our Contribution* - Handles Bazel build rules, FFI between Rust/C++, and context management).
4. **PQClean Automotive Library** (Provides the mathematical PQC primitives in C/Rust).

## 4. Supported Algorithms & Practical Experience
We have been working with the NIST-standardized PQC algorithms and their precursors for several years. Our expertise includes:

* **ML-KEM (CRYSTALS-Kyber) – Lattice-based KEM:** Utilized as a highly performant, quantum-safe foundation for key exchange in embedded systems. We have practical experience with various security levels (e.g., NIST Level 1/3/5) regarding their impact on key/ciphertext sizes and runtimes, specifically evaluating their suitability for sporadic key exchanges in resource-constrained environments like ECUs.
* **HQC (Hamming Quasi-Cyclic) – Code-based KEM:** Experienced in implementation and optimization on microcontrollers (e.g., Cortex-M, AURIX) based on current research. We understand its distinct security assumptions compared to lattice-based methods (error correction vs. lattice problems) and evaluate its use cases as an alternative or complement to ML-KEM.
* **ML-DSA (CRYSTALS-Dilithium) – Lattice-based Signature:** Applied for Secure Boot, firmware updates, and authentication. We have practical experience with NIST levels (e.g., 2/3/5) and the trade-offs between signature size, key size, and verification time, allowing us to assess its viability for real-time systems and ECU boot chains.
* **FN-DSA (Falcon) – Lattice-based Signature:** Focused on compact signatures. We have analyzed its algorithmic properties and implementation requirements. Our practical insights show its limited suitability for certain automotive real-time systems due to higher complexity, though we understand exactly when it makes sense to use (e.g., in backends or on more powerful platforms).
* **SLH-DSA (SPHINCS+) – Hash-based, Stateless Signature:** Experienced in embedded implementation and optimization, including necessary adaptations like replacing dynamic arrays with static structures. We evaluate its highly conservative security model against its significant computational and memory demands, targeting use cases with maximum security requirements but lower signature frequencies.


## 5. Proven Performance
PQC algorithms require significant computing resources. We have already conducted extensive runtime and memory measurements of these algorithms on embedded automotive hardware (Infineon Aurix TC3), proving their real-world feasibility for vehicle microcontrollers.

## 6. Proof of Concept
This proposal already includes a small integrated module (`pqc_iav_contribution:pqc_crypto`) which demonstrates the basic integration and usage of the PQClean Automotive library (All mentioned algorithms and their variants) within the S-Core toolchain. Please note that this is currently intended as a minimal usage example for the scope of this proposal and does not yet represent the final, fully-featured S-Core PQC Adapter.

---

