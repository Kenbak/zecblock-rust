#!/usr/bin/env python3
"""Fingerprint health categories, ignoring changing clocks, heights and metrics."""
import hashlib
import json
import sys


def fingerprint(service_status, health_rc, output):
    if service_status != "active":
        categories = ["service_inactive"]
    elif health_rc == 0:
        categories = ["healthy"]
    elif health_rc in (124, 137):
        categories = ["health_command_timeout"]
    else:
        categories = ["health_command_failed"]
        # Tracing can precede JSON and Rust's main can print an Error afterwards.
        for offset, char in enumerate(output):
            if char != "{":
                continue
            try:
                assessment, _ = json.JSONDecoder().raw_decode(output[offset:])
            except ValueError:
                continue
            if not isinstance(assessment, dict) or assessment.get("healthy") is not False:
                continue
            codes = assessment.get("reason_codes")
            if isinstance(codes, list) and codes and all(isinstance(code, str) for code in codes):
                categories = sorted(set(codes))
            break
    identity = json.dumps([service_status, categories], separators=(",", ":"))
    return hashlib.sha256(identity.encode()).hexdigest()


if __name__ == "__main__":
    print(fingerprint(sys.argv[1], int(sys.argv[2]), sys.stdin.read()))
