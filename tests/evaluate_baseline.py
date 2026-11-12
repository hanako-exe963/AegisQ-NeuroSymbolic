
import json
from pathlib import Path

REPORT = Path("results/python_scan.json")

# Manually verified expected findings for our current test fixtures.
EXPECTED = {
    "aes_example.py": 1,
    "ecc_example.py": 1,
    "ecc_operations.py": 6,
    "negative_examples.py": 0,
    "normal_example.py": 0,
    "rsa_example.py": 1,
    "rsa_operations.py": 5,
}


def main():
    if not REPORT.exists():
        raise FileNotFoundError(
            f"Scan report not found: {REPORT}"
        )

    with REPORT.open() as f:
        report = json.load(f)

    findings = report.get("findings", [])

    actual = {filename: 0 for filename in EXPECTED}

    for finding in findings:
        filename = Path(finding["file"]).name

        if filename in actual:
            actual[filename] += 1

    # File-level classification:
    # Positive = cryptographic API usage is expected.
    # Negative = no cryptographic API usage is expected.
    tp = fp = fn = tn = 0

    print("\nAegisQ — Baseline Evaluation")
    print("=" * 65)
    print(f"{'File':<27} {'Expected':<12} {'Detected':<12} Result")
    print("-" * 65)

    for filename, expected_count in EXPECTED.items():
        detected_count = actual[filename]

        expected_positive = expected_count > 0
        predicted_positive = detected_count > 0

        if expected_positive and predicted_positive:
            tp += 1
        elif not expected_positive and predicted_positive:
            fp += 1
        elif expected_positive and not predicted_positive:
            fn += 1
        else:
            tn += 1

        result = "PASS" if expected_positive == predicted_positive else "FAIL"

        count_status = (
            "count OK"
            if expected_count == detected_count
            else "count mismatch"
        )

        print(
            f"{filename:<27} "
            f"{expected_count:<12} "
            f"{detected_count:<12} "
            f"{result} ({count_status})"
        )

    total = tp + fp + fn + tn

    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0
    accuracy = (tp + tn) / total if total else 0

    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0
    )

    print("\n" + "=" * 65)
    print("FILE-LEVEL CONFUSION MATRIX")
    print("-" * 35)
    print(f"True Positives:  {tp}")
    print(f"False Positives: {fp}")
    print(f"False Negatives: {fn}")
    print(f"True Negatives:  {tn}")

    print("\nFILE-LEVEL METRICS")
    print("-" * 35)
    print(f"Accuracy:  {accuracy:.2%}")
    print(f"Precision: {precision:.2%}")
    print(f"Recall:    {recall:.2%}")
    print(f"F1-score:  {f1:.2%}")

    exact_count_matches = sum(
        actual[name] == expected
        for name, expected in EXPECTED.items()
    )

    print("\nFINDING COUNT AGREEMENT")
    print("-" * 35)
    print(f"Exact file count matches: {exact_count_matches}/{len(EXPECTED)}")
    print(f"Total detected findings: {len(findings)}")

    print("\nIMPORTANT:")
    print("Metrics are file-level and based on this small curated dataset.")
    print("They do not establish real-world vulnerability detection accuracy.")


if __name__ == "__main__":
    main()
