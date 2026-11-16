# *******************************************************************************
# Copyright (c) 2026 Contributors to the Eclipse Foundation
#
# See the NOTICE file(s) distributed with this work for additional
# information regarding copyright ownership.
#
# This program and the accompanying materials are made available under the
# terms of the Apache License Version 2.0 which is available at
# https://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0
# *******************************************************************************

"""Validate and flatten the vendored NIST ACVP ML-KEM projection files."""

import json
import sys
from pathlib import Path


PARAMETER_SETS = ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024")
PUBLIC_KEY_BYTES = {
    "ML-KEM-512": 800,
    "ML-KEM-768": 1184,
    "ML-KEM-1024": 1568,
}


def read_projection(path: str, algorithm: str, mode: str) -> dict:
    with Path(path).open(encoding="utf-8") as projection_file:
        projection = json.load(projection_file)
    if projection.get("algorithm") != algorithm or projection.get("mode") != mode:
        raise ValueError(
            f"{path}: expected {algorithm}/{mode}, got "
            f"{projection.get('algorithm')}/{projection.get('mode')}"
        )
    if not isinstance(projection.get("testGroups"), list):
        raise ValueError(f"{path}: missing testGroups array")
    return projection


def check_hex(value: object, field: str, context: str) -> str:
    if not isinstance(value, str) or len(value) % 2:
        raise ValueError(f"{context}: {field} must be an even-length hex string")
    try:
        bytes.fromhex(value)
    except ValueError as error:
        raise ValueError(f"{context}: invalid {field}: {error}") from error
    return value.lower()


def cases(projection: dict, parameter_set: str, function: str | None, test_type: str):
    matches = [
        group
        for group in projection["testGroups"]
        if group.get("parameterSet") == parameter_set
        and group.get("function") == function
        and group.get("testType") == test_type
    ]
    if len(matches) != 1:
        raise ValueError(
            f"expected exactly one {parameter_set}/{function}/{test_type} group; "
            f"found {len(matches)}"
        )
    group = matches[0]
    if not isinstance(group.get("tests"), list):
        raise ValueError(f"test group {group.get('tgId')} is missing tests")
    return group["tests"]


def emit(operation: str, parameter_set: str, test_case: dict, fields: list[str]) -> str:
    context = (
        f"{operation}/{parameter_set}/tcId={test_case.get('tcId')}"
    )
    if test_case.get("deferred") is not False:
        raise ValueError(f"{context}: expected a non-deferred ACVP case")
    tc_id = test_case.get("tcId")
    if not isinstance(tc_id, int) or tc_id <= 0:
        raise ValueError(f"{context}: invalid tcId")
    values = [check_hex(test_case.get(field), field, context) for field in fields]
    if operation.endswith("_key_check"):
        passed = test_case.get("testPassed")
        if not isinstance(passed, bool):
            raise ValueError(f"{context}: testPassed must be a boolean")
        values.append("1" if passed else "0")
    return "\t".join((operation, parameter_set, str(tc_id), *values))


def main() -> int:
    if len(sys.argv) != 3:
        print(
            "usage: convert_acvp_mlkem_vectors.py KEYGEN_JSON ENCAPDECAP_JSON",
            file=sys.stderr,
        )
        return 2

    keygen = read_projection(sys.argv[1], "ML-KEM", "keyGen")
    encap_decap = read_projection(sys.argv[2], "ML-KEM", "encapDecap")
    output: list[str] = []
    oversized_encapsulation_keys = 0

    for parameter_set in PARAMETER_SETS:
        keygen_cases = cases(keygen, parameter_set, None, "AFT")
        if len(keygen_cases) != 25:
            raise ValueError(f"{parameter_set}: expected 25 key-generation cases")
        for test_case in keygen_cases:
            seed = check_hex(test_case.get("d"), "d", f"{parameter_set}/keyGen")
            z = check_hex(test_case.get("z"), "z", f"{parameter_set}/keyGen")
            if len(seed) != 64 or len(z) != 64:
                raise ValueError(f"{parameter_set}/keyGen: d and z must each be 32 bytes")
            joined_case = dict(test_case, seed=seed + z)
            output.append(emit("keygen", parameter_set, joined_case, ["seed", "ek", "dk"]))

        encapsulation_cases = cases(
            encap_decap, parameter_set, "encapsulation", "AFT"
        )
        if len(encapsulation_cases) != 25:
            raise ValueError(f"{parameter_set}: expected 25 encapsulation cases")
        for test_case in encapsulation_cases:
            output.append(
                emit("encaps", parameter_set, test_case, ["m", "ek", "k", "c"])
            )

        decapsulation_cases = cases(
            encap_decap, parameter_set, "decapsulation", "VAL"
        )
        if len(decapsulation_cases) != 10:
            raise ValueError(f"{parameter_set}: expected 10 decapsulation cases")
        for test_case in decapsulation_cases:
            output.append(
                emit("decaps", parameter_set, test_case, ["dk", "c", "k"])
            )

        encapsulation_key_cases = cases(
            encap_decap, parameter_set, "encapsulationKeyCheck", "VAL"
        )
        if len(encapsulation_key_cases) != 10:
            raise ValueError(
                f"{parameter_set}: expected 10 encapsulation-key-check cases"
            )
        for test_case in encapsulation_key_cases:
            public_key = check_hex(
                test_case.get("ek"),
                "ek",
                f"encapsulationKeyCheck/{parameter_set}/tcId={test_case.get('tcId')}",
            )
            row = emit(
                "encaps_key_check",
                parameter_set,
                test_case,
                ["ek"],
            )
            if len(public_key) == PUBLIC_KEY_BYTES[parameter_set] * 2:
                output.append(row)
            else:
                if test_case["testPassed"]:
                    raise ValueError(
                        f"{parameter_set}/encapsulationKeyCheck: valid key has "
                        "the wrong length"
                    )
                if len(public_key) < PUBLIC_KEY_BYTES[parameter_set] * 2:
                    raise ValueError(
                        f"{parameter_set}/encapsulationKeyCheck: invalid key is "
                        "shorter than the liboqs API key size"
                    )
                # OQS_KEM_encaps_derand takes a fixed-size key pointer, not a
                # length. Oversized-key rejection belongs to its caller's
                # length-validation boundary, so this input cannot be tested
                # meaningfully through that liboqs operation.
                oversized_encapsulation_keys += 1

        decapsulation_key_cases = cases(
            encap_decap, parameter_set, "decapsulationKeyCheck", "VAL"
        )
        if len(decapsulation_key_cases) != 10:
            raise ValueError(
                f"{parameter_set}: expected 10 decapsulation-key-check cases"
            )
        for test_case in decapsulation_key_cases:
            output.append(
                emit(
                    "decaps_key_check",
                    parameter_set,
                    test_case,
                    ["ek", "dk"],
                )
            )

    if oversized_encapsulation_keys != 15:
        raise ValueError(
            "expected 15 oversized encapsulation keys outside the liboqs "
            f"fixed-size API boundary, found {oversized_encapsulation_keys}"
        )
    if len(output) != 225:
        raise ValueError(f"expected 225 runnable ACVP cases, produced {len(output)}")
    sys.stdout.write("\n".join(output) + "\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"ACVP ML-KEM vector conversion failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
