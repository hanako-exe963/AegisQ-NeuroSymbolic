
#!/usr/bin/env python3

import argparse
import json
from pathlib import Path


VERSION = "0.2.0"


def build_assessment(
    family,
    quantum_assessment,
    status,
    priority,
    reason,
    recommendation,
    limitations,
):
    return {
        "crypto_family": family,
        "quantum_assessment": quantum_assessment,
        "security_status": status,
        "priority": priority,
        "reason": reason,
        "recommendation": recommendation,
        "limitations": limitations,
        "confirmed_vulnerability": False,
    }


def evaluate_finding(finding):
    algorithm = finding.get("algorithm", "").upper()
    operation = finding.get("operation", "")
    context = finding.get("context", "")

    # RSA: classical public-key cryptography
    if algorithm == "RSA":

        if context == "digital_signature":
            return build_assessment(
                "classical_public_key",
                "quantum_vulnerable_algorithm",
                "PQC_SIGNATURE_MIGRATION_REVIEW",
                "HIGH",
                (
                    "RSA is used in a digital-signature context. "
                    "A sufficiently capable fault-tolerant quantum "
                    "computer could threaten RSA using Shor's algorithm."
                ),
                (
                    "Review the signature protocol and assess ML-DSA "
                    "as a post-quantum signature candidate. Check "
                    "certificate, interoperability, and verification "
                    "requirements before migration."
                ),
                (
                    "Static API analysis does not establish key size, "
                    "production exposure, protocol reachability, or "
                    "whether the signature operation is security-critical."
                ),
            )

        if context in ("encryption", "decryption"):
            return build_assessment(
                "classical_public_key",
                "quantum_vulnerable_algorithm",
                "PQC_ENCRYPTION_ARCHITECTURE_REVIEW",
                "HIGH",
                (
                    "RSA is used in an encryption-related context. "
                    "RSA's security relies on integer factorization, "
                    "which a sufficiently capable quantum computer "
                    "could threaten using Shor's algorithm."
                ),
                (
                    "Review the complete encryption architecture. "
                    "For new key-establishment designs, evaluate "
                    "ML-KEM and hybrid key establishment, followed "
                    "by symmetric authenticated encryption. Do not "
                    "treat ML-KEM as a direct drop-in replacement "
                    "for arbitrary RSA data encryption."
                ),
                (
                    "The detected operation does not establish the "
                    "encrypted data, key-management design, padding "
                    "security, or production usage."
                ),
            )

        if context == "key_generation":
            return build_assessment(
                "classical_public_key",
                "quantum_vulnerable_algorithm",
                "PQC_USAGE_REVIEW",
                "MEDIUM",
                (
                    "RSA key generation was detected. RSA is a "
                    "classical public-key algorithm vulnerable in "
                    "principle to Shor's algorithm on a sufficiently "
                    "capable fault-tolerant quantum computer."
                ),
                (
                    "Trace where the generated key is used. Determine "
                    "whether it supports signatures, encryption, or "
                    "key establishment, then select a suitable "
                    "post-quantum migration strategy."
                ),
                (
                    "Key generation alone does not establish the "
                    "key's purpose, use, exposure, or production status."
                ),
            )

        if context == "key_exchange":
            return build_assessment(
                "classical_public_key",
                "quantum_vulnerable_algorithm",
                "PQC_KEY_ESTABLISHMENT_REVIEW",
                "HIGH",
                (
                    "RSA was detected in a key-exchange context. "
                    "Classical public-key key establishment can be "
                    "threatened by sufficiently capable quantum computers."
                ),
                (
                    "Inspect the protocol and evaluate ML-KEM-based "
                    "or hybrid key establishment where supported."
                ),
                (
                    "The source-level classification does not prove "
                    "that a network key exchange actually occurs."
                ),
            )

        return build_assessment(
            "classical_public_key",
            "quantum_vulnerable_algorithm",
            "PQC_CONTEXT_REVIEW",
            "MEDIUM",
            "RSA API usage was detected, but its cryptographic role is unclear.",
            (
                "Trace the key and related operations to determine "
                "whether RSA is used for signatures, encryption, "
                "or key establishment."
            ),
            "The detected API alone does not establish the complete workflow.",
        )

    # ECC: classical elliptic-curve cryptography
    if algorithm == "ECC":

        if context == "digital_signature":
            return build_assessment(
                "classical_public_key",
                "quantum_vulnerable_algorithm",
                "PQC_SIGNATURE_MIGRATION_REVIEW",
                "HIGH",
                (
                    "ECC is used in a digital-signature context. "
                    "Shor's algorithm could threaten classical "
                    "elliptic-curve signatures on a sufficiently "
                    "capable fault-tolerant quantum computer."
                ),
                (
                    "Review the signature protocol and evaluate "
                    "ML-DSA as a post-quantum signature candidate. "
                    "Consider certificate size, compatibility, "
                    "and verification requirements."
                ),
                (
                    "API detection does not prove production use, "
                    "security-critical reachability, or complete "
                    "signature workflow."
                ),
            )

        if context == "key_exchange":
            return build_assessment(
                "classical_public_key",
                "quantum_vulnerable_algorithm",
                "PQC_KEY_ESTABLISHMENT_REVIEW",
                "HIGH",
                (
                    "ECC is used in a key-exchange context. Classical "
                    "elliptic-curve key agreement can be threatened "
                    "by Shor's algorithm on a sufficiently capable "
                    "fault-tolerant quantum computer."
                ),
                (
                    "Evaluate ML-KEM-based key establishment and "
                    "hybrid classical/post-quantum approaches. "
                    "Inspect protocol support and interoperability."
                ),
                (
                    "Detecting an ECDH scheme does not prove that "
                    "a key exchange is executed or exposed over a network."
                ),
            )

        if context == "key_generation":
            return build_assessment(
                "classical_public_key",
                "quantum_vulnerable_algorithm",
                "PQC_USAGE_REVIEW",
                "MEDIUM",
                (
                    "ECC key generation was detected. Classical "
                    "elliptic-curve cryptography can be threatened "
                    "by Shor's algorithm on a sufficiently capable "
                    "fault-tolerant quantum computer."
                ),
                (
                    "Trace the generated key to determine whether "
                    "it supports ECDSA signatures, ECDH key exchange, "
                    "or another operation. Select the migration "
                    "strategy according to its actual purpose."
                ),
                (
                    "Key generation alone does not identify the "
                    "cryptographic purpose or prove production use."
                ),
            )

        return build_assessment(
            "classical_public_key",
            "quantum_vulnerable_algorithm",
            "PQC_CONTEXT_REVIEW",
            "MEDIUM",
            "ECC API usage was detected, but its role is unclear.",
            (
                "Trace the key and related operations to identify "
                "signature or key-establishment usage."
            ),
            "Static analysis does not establish the complete workflow.",
        )

    # AES: symmetric cryptography
    if algorithm in ("AES", "AES-GCM"):
        return build_assessment(
            "symmetric_cryptography",
            "quantum_security_margin_review",
            "CONFIGURATION_REVIEW",
            "MEDIUM",
            (
                "AES is symmetric cryptography. Grover's algorithm "
                "can affect its theoretical security margin, but "
                "AES is not threatened in the same way as RSA or ECC."
            ),
            (
                "Inspect key length, nonce uniqueness, authentication "
                "tag configuration, and implementation. Evaluate "
                "AES-256 when a larger quantum security margin is required."
            ),
            (
                "API detection does not reveal the actual key length, "
                "nonce lifecycle, or complete encryption workflow."
            ),
        )

    # Cryptographic hash functions
    if algorithm.startswith("SHA-"):
        return build_assessment(
            "cryptographic_hash",
            "quantum_security_margin_review",
            "HASH_CONFIGURATION_REVIEW",
            "LOW",
            (
                "Quantum search can reduce the theoretical security "
                "margin of cryptographic hash functions."
            ),
            (
                "Evaluate the hash function according to its purpose, "
                "output length, and applicable security requirements. "
                "Do not use general-purpose SHA hashing as a password "
                "storage replacement for a password-hashing scheme."
            ),
            (
                "The detected call does not identify whether the "
                "hash is used for integrity, signatures, or another purpose."
            ),
        )

    # TLS
    if algorithm == "TLS":
        return build_assessment(
            "network_security",
            "protocol_inspection_required",
            "TLS_CONFIGURATION_REVIEW",
            "MEDIUM",
            (
                "TLS security depends on negotiated protocol versions, "
                "key exchange groups, signatures, certificates, and policy."
            ),
            (
                "Inspect actual TLS configuration and negotiated "
                "parameters. Evaluate supported hybrid post-quantum "
                "key establishment and fallback policy."
            ),
            (
                "Creating a TLS context does not reveal the negotiated "
                "cipher suite, key exchange group, or peer configuration."
            ),
        )

    return build_assessment(
        "unknown",
        "not_assessed",
        "MANUAL_REVIEW",
        "UNKNOWN",
        "No matching symbolic security rule was found.",
        "Review this finding manually.",
        "The current rule set does not cover this operation.",
    )


def process_report(input_path, output_path):
    report = json.loads(input_path.read_text(encoding="utf-8"))

    if not isinstance(report, dict) or not isinstance(
        report.get("findings"), list
    ):
        raise ValueError("Invalid analyzer report: expected a findings list.")

    priority_counts = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "UNKNOWN": 0,
    }

    for finding in report["findings"]:
        assessment = evaluate_finding(finding)
        finding["symbolic_assessment"] = assessment
        priority_counts[assessment["priority"]] += 1

    report["component"] = "AegisQ Neuro-Symbolic Assessment"
    report["rules_engine"] = {
        "version": VERSION,
        "findings_evaluated": len(report["findings"]),
        "priority_counts": priority_counts,
        "note": (
            "Assessments indicate review priorities, not confirmed "
            "vulnerabilities or proof of exploitability."
        ),
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report, indent=4),
        encoding="utf-8",
    )

    print("\nAegisQ Symbolic Reasoning Engine")
    print(f"Version: {VERSION}")
    print(f"Findings evaluated: {len(report['findings'])}")
    print(f"Output: {output_path}")

    print("\nPriority summary:")
    for priority, count in priority_counts.items():
        print(f"  {priority}: {count}")

    print("\nDetailed assessments:")
    for finding in report["findings"]:
        assessment = finding["symbolic_assessment"]
        print(
            f"[{assessment['priority']}] "
            f"{finding.get('algorithm', 'UNKNOWN')} | "
            f"{finding.get('operation', 'unknown')} | "
            f"{assessment['security_status']}"
        )


def main():
    parser = argparse.ArgumentParser(
        description="AegisQ Context-Aware Symbolic Security Rules Engine"
    )

    parser.add_argument(
        "input",
        help="Input JSON report from the Python analyzer",
    )

    parser.add_argument(
        "--output",
        default="results/symbolic_report.json",
        help="Output assessment report",
    )

    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)

    if not input_path.is_file():
        parser.error(f"Input report does not exist: {input_path}")

    try:
        process_report(input_path, output_path)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
