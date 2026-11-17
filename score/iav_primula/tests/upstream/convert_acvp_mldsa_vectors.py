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

"""Validate and flatten the vendored NIST ACVP ML-DSA projections."""

import hashlib
import json
import sys
from pathlib import Path


PARAMETER_SETS = {
    "ML-DSA-44": {"public_key": 1312, "secret_key": 2560, "signature": 2420},
    "ML-DSA-65": {"public_key": 1952, "secret_key": 4032, "signature": 3309},
    "ML-DSA-87": {"public_key": 2592, "secret_key": 4896, "signature": 4627},
}

PREHASH_IDS = {
    "SHA2-224": 1,
    "SHA2-256": 2,
    "SHA2-384": 3,
    "SHA2-512": 4,
    "SHA2-512/224": 5,
    "SHA2-512/256": 6,
    "SHA3-224": 7,
    "SHA3-256": 8,
    "SHA3-384": 9,
    "SHA3-512": 10,
    "SHAKE-128": 11,
    "SHAKE-256": 12,
}

EXPECTED_TOTALS = {
    "keygen": 75,
    "siggen_internal": 180,
    "siggen_external": 90,
    "siggen_prehash": 90,
    "sigver_internal": 90,
    "sigver_external": 45,
    "sigver_prehash": 45,
}
EXPECTED_CASE_COUNT = sum(EXPECTED_TOTALS.values())


def read_projection(path: str, mode: str) -> dict:
    with Path(path).open(encoding="utf-8") as projection_file:
        projection = json.load(projection_file)
    actual = (
        projection.get("algorithm"),
        projection.get("mode"),
        projection.get("revision"),
    )
    expected = ("ML-DSA", mode, "FIPS204")
    if actual != expected:
        raise ValueError(
            f"{path}: expected ML-DSA/{mode}/FIPS204, got "
            f"{actual[0]}/{actual[1]}/{actual[2]}"
        )
    if not isinstance(projection.get("testGroups"), list):
        raise ValueError(f"{path}: missing testGroups array")
    return projection


def hex_bytes(value: object, field: str, context: str, expected: int | None = None) -> str:
    if not isinstance(value, str) or len(value) % 2:
        raise ValueError(f"{context}: {field} must be an even-length hex string")
    try:
        encoded = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError(f"{context}: invalid {field}: {error}") from error
    if expected is not None and len(encoded) != expected:
        raise ValueError(
            f"{context}: {field} has {len(encoded)} bytes, expected {expected}"
        )
    return value.lower()


def require_case(group: dict, test_case: dict, context: str) -> int:
    if group.get("testType") != "AFT":
        raise ValueError(f"{context}: unexpected test type {group.get('testType')}")
    if test_case.get("deferred") is not False:
        raise ValueError(f"{context}: expected a non-deferred ACVP case")
    tc_id = test_case.get("tcId")
    if not isinstance(tc_id, int) or tc_id <= 0:
        raise ValueError(f"{context}: invalid tcId")
    return tc_id


def field(test_case: dict, name: str, context: str, expected: int | None = None) -> str:
    return hex_bytes(test_case.get(name), name, context, expected)


def digest_message(message_hex: str, algorithm: str, context: str) -> str:
    try:
        message = bytes.fromhex(message_hex)
    except ValueError as error:
        raise ValueError(f"{context}: invalid message hex: {error}") from error
    if algorithm == "SHA2-224":
        digest = hashlib.sha224(message).digest()
    elif algorithm == "SHA2-256":
        digest = hashlib.sha256(message).digest()
    elif algorithm == "SHA2-384":
        digest = hashlib.sha384(message).digest()
    elif algorithm == "SHA2-512":
        digest = hashlib.sha512(message).digest()
    elif algorithm == "SHA2-512/224":
        digest = hashlib.new("sha512_224", message).digest()
    elif algorithm == "SHA2-512/256":
        digest = hashlib.new("sha512_256", message).digest()
    elif algorithm == "SHA3-224":
        digest = hashlib.sha3_224(message).digest()
    elif algorithm == "SHA3-256":
        digest = hashlib.sha3_256(message).digest()
    elif algorithm == "SHA3-384":
        digest = hashlib.sha3_384(message).digest()
    elif algorithm == "SHA3-512":
        digest = hashlib.sha3_512(message).digest()
    elif algorithm == "SHAKE-128":
        digest = hashlib.shake_128(message).digest(32)
    elif algorithm == "SHAKE-256":
        digest = hashlib.shake_256(message).digest(64)
    else:
        raise ValueError(f"{context}: unsupported pre-hash algorithm {algorithm!r}")
    return digest.hex()


def emit(operation: str, parameter_set: str, group_id: int, tc_id: int, *values: str) -> str:
    return "\t".join((operation, parameter_set, str(group_id), str(tc_id), *values))


def convert_keygen(projection: dict) -> list[str]:
    output = []
    seen = set()
    for group in projection["testGroups"]:
        parameter_set = group.get("parameterSet")
        if parameter_set not in PARAMETER_SETS or parameter_set in seen:
            raise ValueError(f"keyGen: unexpected or duplicate parameter set {parameter_set!r}")
        seen.add(parameter_set)
        lengths = PARAMETER_SETS[parameter_set]
        if len(group.get("tests", [])) != 25:
            raise ValueError(f"keyGen/{parameter_set}: expected 25 cases")
        for test_case in group["tests"]:
            context = f"keyGen/{parameter_set}/tgId={group.get('tgId')}/tcId={test_case.get('tcId')}"
            tc_id = require_case(group, test_case, context)
            if test_case.get("tgId") is not None:
                raise ValueError(f"{context}: ACVP test unexpectedly has a tgId")
            output.append(
                emit(
                    "keygen",
                    parameter_set,
                    int(group["tgId"]),
                    tc_id,
                    field(test_case, "seed", context, 32),
                    field(test_case, "pk", context, lengths["public_key"]),
                    field(test_case, "sk", context, lengths["secret_key"]),
                )
            )
    if seen != set(PARAMETER_SETS):
        raise ValueError(f"keyGen: missing parameter sets {sorted(set(PARAMETER_SETS) - seen)}")
    return output


def convert_siggen(projection: dict) -> list[str]:
    output = []
    groups_per_set = {parameter_set: 0 for parameter_set in PARAMETER_SETS}
    for group in projection["testGroups"]:
        parameter_set = group.get("parameterSet")
        if parameter_set not in PARAMETER_SETS:
            raise ValueError(f"sigGen: unexpected parameter set {parameter_set!r}")
        groups_per_set[parameter_set] += 1
        lengths = PARAMETER_SETS[parameter_set]
        interface = group.get("signatureInterface")
        pre_hash = group.get("preHash")
        external_mu = group.get("externalMu")
        deterministic = group.get("deterministic")
        if interface not in ("internal", "external") or not isinstance(external_mu, bool):
            raise ValueError(f"sigGen/tgId={group.get('tgId')}: invalid interface metadata")
        if not isinstance(deterministic, bool):
            raise ValueError(f"sigGen/tgId={group.get('tgId')}: deterministic must be boolean")
        if interface == "internal":
            if pre_hash != "none":
                raise ValueError(f"sigGen/tgId={group.get('tgId')}: unsupported internal preHash")
            operation = "siggen_internal"
        elif pre_hash == "pure" and not external_mu:
            operation = "siggen_external"
        elif pre_hash == "preHash" and not external_mu:
            operation = "siggen_prehash"
        else:
            raise ValueError(
                f"sigGen/tgId={group.get('tgId')}: unsupported "
                f"{interface}/{pre_hash}/externalMu={external_mu}"
            )
        if len(group.get("tests", [])) != 15:
            raise ValueError(f"sigGen/tgId={group.get('tgId')}: expected 15 cases")

        for test_case in group["tests"]:
            context = f"sigGen/{parameter_set}/tgId={group.get('tgId')}/tcId={test_case.get('tcId')}"
            tc_id = require_case(group, test_case, context)
            secret_key = field(test_case, "sk", context, lengths["secret_key"])
            signature = field(test_case, "signature", context, lengths["signature"])
            if deterministic:
                if "rnd" in test_case:
                    raise ValueError(f"{context}: deterministic vector unexpectedly has rnd")
                rnd = "00" * 32
            else:
                rnd = field(test_case, "rnd", context, 32)

            if operation == "siggen_internal":
                message_field = "mu" if external_mu else "message"
                message = field(test_case, message_field, context)
                values = (message, rnd, secret_key, signature, "1" if external_mu else "0")
            elif operation == "siggen_external":
                message = field(test_case, "message", context)
                context_hex = field(test_case, "context", context)
                if len(context_hex) > 255 * 2:
                    raise ValueError(f"{context}: context exceeds 255 bytes")
                values = (message, context_hex, rnd, secret_key, signature)
            else:
                message = field(test_case, "message", context)
                hash_algorithm = test_case.get("hashAlg")
                if hash_algorithm not in PREHASH_IDS:
                    raise ValueError(f"{context}: unsupported pre-hash algorithm {hash_algorithm!r}")
                prehash = digest_message(message, hash_algorithm, context)
                context_hex = field(test_case, "context", context)
                if len(context_hex) > 255 * 2:
                    raise ValueError(f"{context}: context exceeds 255 bytes")
                values = (
                    prehash,
                    context_hex,
                    rnd,
                    secret_key,
                    signature,
                    str(PREHASH_IDS[hash_algorithm]),
                )
            output.append(emit(operation, parameter_set, int(group["tgId"]), tc_id, *values))

    if groups_per_set != {parameter_set: 8 for parameter_set in PARAMETER_SETS}:
        raise ValueError(f"sigGen: expected eight groups per parameter set, got {groups_per_set}")
    return output


def convert_sigver(projection: dict) -> list[str]:
    output = []
    groups_per_set = {parameter_set: 0 for parameter_set in PARAMETER_SETS}
    for group in projection["testGroups"]:
        parameter_set = group.get("parameterSet")
        if parameter_set not in PARAMETER_SETS:
            raise ValueError(f"sigVer: unexpected parameter set {parameter_set!r}")
        groups_per_set[parameter_set] += 1
        lengths = PARAMETER_SETS[parameter_set]
        interface = group.get("signatureInterface")
        pre_hash = group.get("preHash")
        external_mu = group.get("externalMu")
        if interface not in ("internal", "external") or not isinstance(external_mu, bool):
            raise ValueError(f"sigVer/tgId={group.get('tgId')}: invalid interface metadata")
        if interface == "internal":
            if pre_hash != "none":
                raise ValueError(f"sigVer/tgId={group.get('tgId')}: unsupported internal preHash")
            operation = "sigver_internal"
        elif pre_hash == "pure" and not external_mu:
            operation = "sigver_external"
        elif pre_hash == "preHash" and not external_mu:
            operation = "sigver_prehash"
        else:
            raise ValueError(
                f"sigVer/tgId={group.get('tgId')}: unsupported "
                f"{interface}/{pre_hash}/externalMu={external_mu}"
            )
        if len(group.get("tests", [])) != 15:
            raise ValueError(f"sigVer/tgId={group.get('tgId')}: expected 15 cases")

        for test_case in group["tests"]:
            context = f"sigVer/{parameter_set}/tgId={group.get('tgId')}/tcId={test_case.get('tcId')}"
            tc_id = require_case(group, test_case, context)
            public_key = field(test_case, "pk", context, lengths["public_key"])
            signature = field(test_case, "signature", context, lengths["signature"])
            passed = test_case.get("testPassed")
            if not isinstance(passed, bool):
                raise ValueError(f"{context}: testPassed must be boolean")

            if operation == "sigver_internal":
                message_field = "mu" if external_mu else "message"
                message = field(test_case, message_field, context)
                values = (public_key, message, signature, "1" if passed else "0", "1" if external_mu else "0")
            elif operation == "sigver_external":
                message = field(test_case, "message", context)
                context_hex = field(test_case, "context", context)
                if len(context_hex) > 255 * 2:
                    raise ValueError(f"{context}: context exceeds 255 bytes")
                values = (public_key, message, signature, context_hex, "1" if passed else "0")
            else:
                message = field(test_case, "message", context)
                hash_algorithm = test_case.get("hashAlg")
                if hash_algorithm not in PREHASH_IDS:
                    raise ValueError(f"{context}: unsupported pre-hash algorithm {hash_algorithm!r}")
                prehash = digest_message(message, hash_algorithm, context)
                context_hex = field(test_case, "context", context)
                if len(context_hex) > 255 * 2:
                    raise ValueError(f"{context}: context exceeds 255 bytes")
                values = (
                    public_key,
                    prehash,
                    signature,
                    context_hex,
                    "1" if passed else "0",
                    str(PREHASH_IDS[hash_algorithm]),
                )
            output.append(emit(operation, parameter_set, int(group["tgId"]), tc_id, *values))

    if groups_per_set != {parameter_set: 4 for parameter_set in PARAMETER_SETS}:
        raise ValueError(f"sigVer: expected four groups per parameter set, got {groups_per_set}")
    return output


def main() -> int:
    if len(sys.argv) != 4:
        print(
            "usage: convert_acvp_mldsa_vectors.py KEYGEN_JSON SIGGEN_JSON SIGVER_JSON",
            file=sys.stderr,
        )
        return 2

    projections = (
        read_projection(sys.argv[1], "keyGen"),
        read_projection(sys.argv[2], "sigGen"),
        read_projection(sys.argv[3], "sigVer"),
    )
    converted = (
        convert_keygen(projections[0])
        + convert_siggen(projections[1])
        + convert_sigver(projections[2])
    )
    counts = {name: 0 for name in EXPECTED_TOTALS}
    for row in converted:
        operation = row.split("\t", 1)[0]
        counts[operation] += 1
    if counts != EXPECTED_TOTALS or len(converted) != EXPECTED_CASE_COUNT:
        raise ValueError(
            f"expected {EXPECTED_CASE_COUNT} runnable ACVP cases with "
            f"counts {EXPECTED_TOTALS}, got {len(converted)} with {counts}"
        )
    sys.stdout.write("\n".join(converted) + "\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"ACVP ML-DSA vector conversion failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
