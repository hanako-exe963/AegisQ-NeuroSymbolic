
#!/usr/bin/env python3

import argparse
import ast
import json
from pathlib import Path


CRYPTO_APIS = {
    "rsa.generate_private_key": ("RSA", "key_generation", "key_generation"),
    "ec.generate_private_key": ("ECC", "key_generation", "key_generation"),
    "RSA.generate": ("RSA", "key_generation", "key_generation"),
    "ECC.generate": ("ECC", "key_generation", "key_generation"),

    "AESGCM": ("AES-GCM", "authenticated_encryption", "authenticated_encryption"),
    "AES.new": ("AES", "encryption", "symmetric_encryption"),
    "algorithms.AES": ("AES", "encryption", "symmetric_encryption"),

    "hashlib.sha256": ("SHA-256", "hashing", "hashing"),
    "hashlib.sha384": ("SHA-384", "hashing", "hashing"),
    "hashlib.sha512": ("SHA-512", "hashing", "hashing"),

    "SSLContext": ("TLS", "TLS_context_creation", "TLS"),
    "create_default_context": ("TLS", "TLS_context_creation", "TLS"),

    "ec.ECDSA": ("ECC", "signature_scheme", "digital_signature"),
    "ec.ECDH": ("ECC", "key_exchange_scheme", "key_exchange"),

    "padding.PSS": ("RSA", "signature_padding", "digital_signature"),
    "padding.OAEP": ("RSA", "encryption_padding", "encryption"),
}


SUPPORTED_HASHES = {
    "SHA1",
    "SHA224",
    "SHA256",
    "SHA384",
    "SHA512",
    "SHA3_256",
    "SHA3_384",
    "SHA3_512",
}


class CryptoAnalyzer(ast.NodeVisitor):

    def __init__(self, source_lines):
        self.source_lines = source_lines
        self.source = "\n".join(source_lines)

        self.imports = {}
        self.findings = []
        self.variable_algorithms = {}

    # --------------------------------------------------
    # Finding management
    # --------------------------------------------------

    def add_finding(
        self,
        algorithm,
        operation,
        context,
        node,
        api_name,
        parameters=None
    ):
        line = getattr(node, "lineno", 0)

        evidence = ast.get_source_segment(self.source, node)

        if not evidence and 0 < line <= len(self.source_lines):
            evidence = self.source_lines[line - 1].strip()

        self.findings.append({
            "algorithm": algorithm,
            "operation": operation,
            "context": context,
            "line": line,
            "api": api_name,
            "evidence": evidence or "",
            "parameters": parameters or {},
            "classification": "API_USAGE_DETECTED"
        })

    # --------------------------------------------------
    # Import resolution
    # --------------------------------------------------

    def visit_Import(self, node):
        for alias in node.names:
            local_name = alias.asname or alias.name.split(".")[0]
            self.imports[local_name] = alias.name

        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module:
            for alias in node.names:

                if alias.name == "*":
                    continue

                local_name = alias.asname or alias.name

                self.imports[local_name] = (
                    f"{node.module}.{alias.name}"
                )

        self.generic_visit(node)

    # --------------------------------------------------
    # Name resolution
    # --------------------------------------------------

    def resolve_name(self, node):

        if isinstance(node, ast.Name):
            return self.imports.get(node.id, node.id)

        if isinstance(node, ast.Attribute):
            parent = self.resolve_name(node.value)
            return f"{parent}.{node.attr}"

        if isinstance(node, ast.Call):
            return self.resolve_name(node.func)

        return ""

    def get_call_name(self, node):

        if isinstance(node, ast.Call):
            return self.resolve_name(node.func)

        return self.resolve_name(node)

    # --------------------------------------------------
    # Algorithm inference
    # --------------------------------------------------

    def infer_algorithm(self, node):

        if isinstance(node, ast.Call):

            name = self.resolve_name(node.func)

            for suffix, (algorithm, _, _) in CRYPTO_APIS.items():

                if name == suffix or name.endswith("." + suffix):

                    if algorithm in ("RSA", "ECC"):
                        return algorithm

            if isinstance(node.func, ast.Attribute):
                return self.infer_algorithm(node.func.value)

        if isinstance(node, ast.Name):
            return self.variable_algorithms.get(node.id)

        return None

    # --------------------------------------------------
    # Hash extraction
    # --------------------------------------------------

    def extract_hash_algorithm(self, node):

        if not isinstance(node, ast.Call):
            return None

        name = self.get_call_name(node)
        hash_name = name.split(".")[-1]

        if hash_name in SUPPORTED_HASHES:
            return hash_name

        return None

    def extract_nested_hash(self, node):
        """
        Search nested expressions for a supported hash constructor.

        Example:
            padding.MGF1(hashes.SHA256())
        """

        if node is None:
            return None

        for child in ast.walk(node):

            if isinstance(child, ast.Call):

                name = self.get_call_name(child)
                hash_name = name.split(".")[-1]

                if hash_name in SUPPORTED_HASHES:
                    return hash_name

        return None

    # --------------------------------------------------
    # Parameter extraction
    # --------------------------------------------------

    def extract_parameters(self, node, algorithm):

        parameters = {}

        if not isinstance(node, ast.Call):
            return parameters

        api_name = self.resolve_name(node.func)

        # RSA key generation
        if algorithm == "RSA" and (
            api_name.endswith("generate_private_key")
            or api_name.endswith("RSA.generate")
        ):

            for keyword in node.keywords:

                if keyword.arg == "key_size":

                    try:
                        value = ast.literal_eval(keyword.value)

                        if isinstance(value, int) and not isinstance(value, bool):
                            parameters["key_size_bits"] = value

                    except (ValueError, TypeError):
                        parameters["key_size_bits"] = "dynamic"

        # ECC key generation
        if algorithm == "ECC" and api_name.endswith("generate_private_key"):

            curve_node = None

            # Positional argument:
            # ec.generate_private_key(ec.SECP256R1())

            if node.args:
                curve_node = node.args[0]

            # Keyword argument:
            # ec.generate_private_key(curve=ec.SECP384R1())

            for keyword in node.keywords:

                if keyword.arg == "curve":
                    curve_node = keyword.value
                    break

            if isinstance(curve_node, ast.Call):

                curve_name = self.get_call_name(curve_node)
                parameters["curve"] = curve_name.split(".")[-1]

            elif curve_node is not None:
                parameters["curve"] = "dynamic"

        # RSA-PSS and RSA-OAEP
        if algorithm == "RSA":

            if (
                api_name.endswith("padding.PSS")
                or api_name.endswith(".PSS")
            ):
                parameters["scheme"] = "PSS"

            elif (
                api_name.endswith("padding.OAEP")
                or api_name.endswith(".OAEP")
            ):
                parameters["scheme"] = "OAEP"

            if "scheme" in parameters:

                for keyword in node.keywords:

                    # MGF extraction
                    if (
                        keyword.arg == "mgf"
                        and isinstance(keyword.value, ast.Call)
                    ):

                        mgf_name = self.get_call_name(keyword.value)

                        parameters["mgf"] = mgf_name.split(".")[-1]

                        mgf_hash = self.extract_nested_hash(
                            keyword.value
                        )

                        if mgf_hash:
                            parameters["mgf_hash_algorithm"] = mgf_hash

                    # OAEP hash extraction
                    if keyword.arg == "algorithm":

                        hash_name = self.extract_hash_algorithm(
                            keyword.value
                        )

                        if hash_name:
                            parameters["hash_algorithm"] = hash_name

                        elif keyword.value is not None:
                            parameters["hash_algorithm"] = "dynamic"

        # ECC ECDSA
        if algorithm == "ECC" and api_name.endswith("ec.ECDSA"):

            parameters["scheme"] = "ECDSA"

            for argument in node.args:

                hash_name = self.extract_hash_algorithm(argument)

                if hash_name:
                    parameters["hash_algorithm"] = hash_name

        return parameters

    # --------------------------------------------------
    # Variable tracking
    # --------------------------------------------------

    def visit_Assign(self, node):

        self.visit(node.value)

        algorithm = self.infer_algorithm(node.value)

        if algorithm:

            for target in node.targets:

                if isinstance(target, ast.Name):
                    self.variable_algorithms[target.id] = algorithm

        for target in node.targets:
            self.visit(target)

    def visit_AnnAssign(self, node):

        if node.value:

            self.visit(node.value)

            algorithm = self.infer_algorithm(node.value)

            if algorithm and isinstance(node.target, ast.Name):
                self.variable_algorithms[node.target.id] = algorithm

        self.visit(node.target)

    # --------------------------------------------------
    # Cryptographic API and operation detection
    # --------------------------------------------------

    def visit_Call(self, node):

        api_name = self.resolve_name(node.func)

        for suffix, (algorithm, operation, context) in CRYPTO_APIS.items():

            if api_name == suffix or api_name.endswith("." + suffix):

                parameters = self.extract_parameters(
                    node,
                    algorithm
                )

                self.add_finding(
                    algorithm,
                    operation,
                    context,
                    node,
                    api_name,
                    parameters
                )

                break

        # Detect operations on tracked variables
        if isinstance(node.func, ast.Attribute):

            method = node.func.attr
            receiver = node.func.value

            if isinstance(receiver, ast.Name):

                algorithm = self.variable_algorithms.get(receiver.id)

                if algorithm:

                    operation_map = {
                        "sign": (
                            "signature_operation",
                            "digital_signature"
                        ),
                        "verify": (
                            "signature_verification",
                            "digital_signature"
                        ),
                        "encrypt": (
                            "encryption_operation",
                            "encryption"
                        ),
                        "decrypt": (
                            "decryption_operation",
                            "decryption"
                        ),
                        "exchange": (
                            "key_exchange_operation",
                            "key_exchange"
                        ),
                    }

                    if method in operation_map:

                        operation, context = operation_map[method]

                        self.add_finding(
                            algorithm,
                            operation,
                            context,
                            node,
                            f"{algorithm}.{method}"
                        )

        self.generic_visit(node)


# --------------------------------------------------
# File analysis
# --------------------------------------------------

def analyze_file(file_path, root):

    try:

        source = file_path.read_text(encoding="utf-8")

        tree = ast.parse(
            source,
            filename=str(file_path)
        )

    except (OSError, UnicodeError, SyntaxError) as error:
        return [], str(error)

    analyzer = CryptoAnalyzer(source.splitlines())
    analyzer.visit(tree)

    results = []

    for finding in analyzer.findings:

        finding["file"] = str(file_path.relative_to(root))
        results.append(finding)

    return results, None


# --------------------------------------------------
# Directory scanning
# --------------------------------------------------

def scan_directory(target):

    findings = []
    errors = []
    files_scanned = 0

    for file_path in sorted(target.rglob("*.py")):

        if ".venv" in file_path.parts or "__pycache__" in file_path.parts:
            continue

        files_scanned += 1

        file_findings, error = analyze_file(
            file_path,
            target
        )

        findings.extend(file_findings)

        if error:

            errors.append({
                "file": str(file_path.relative_to(target)),
                "error": error
            })

    return findings, errors, files_scanned


# --------------------------------------------------
# CLI
# --------------------------------------------------

def main():

    parser = argparse.ArgumentParser(
        description="AegisQ Python Cryptographic Source Analyzer"
    )

    parser.add_argument(
        "target",
        help="Directory containing Python source files"
    )

    parser.add_argument(
        "--output",
        default="results/python_scan.json",
        help="JSON output file"
    )

    args = parser.parse_args()

    target = Path(args.target).resolve()

    if not target.is_dir():
        parser.error(f"Target directory does not exist: {target}")

    findings, errors, files_scanned = scan_directory(target)

    report = {
        "tool": "AegisQ-NeuroSymbolic",
        "component": "Python Cryptographic Analyzer",
        "target": str(target),
        "findings_count": len(findings),
        "findings": findings,
        "scan_errors": errors
    }

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)

    output.write_text(
        json.dumps(report, indent=4),
        encoding="utf-8"
    )

    print("\nAegisQ Python Analyzer")
    print(f"Files scanned: {files_scanned}")
    print(f"Findings: {len(findings)}")
    print(f"Scan errors: {len(errors)}")
    print(f"Report saved to: {output}")


if __name__ == "__main__":
    main()
