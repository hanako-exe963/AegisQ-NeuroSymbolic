import sys
import unittest
import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "analyzer" / "python"))

from scanner import CryptoAnalyzer


class TestCryptoAnalyzer(unittest.TestCase):

    def analyze(self, source):
        analyzer = CryptoAnalyzer(source.splitlines())
        analyzer.visit(ast.parse(source))
        return analyzer.findings

    def test_rsa_key_generation(self):
        source = """
from cryptography.hazmat.primitives.asymmetric import rsa
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
"""
        findings = self.analyze(source)

        self.assertTrue(any(
            f["algorithm"] == "RSA"
            and f["operation"] == "key_generation"
            for f in findings
        ))

    def test_ecc_signature_scheme(self):
        source = """
from cryptography.hazmat.primitives.asymmetric import ec
algorithm = ec.ECDSA(None)
"""
        findings = self.analyze(source)

        self.assertTrue(any(
            f["algorithm"] == "ECC"
            and f["context"] == "digital_signature"
            for f in findings
        ))

    def test_ecc_key_exchange_scheme(self):
        source = """
from cryptography.hazmat.primitives.asymmetric import ec
algorithm = ec.ECDH()
"""
        findings = self.analyze(source)

        self.assertTrue(any(
            f["algorithm"] == "ECC"
            and f["context"] == "key_exchange"
            for f in findings
        ))

    def test_rsa_encryption_operation(self):
        source = """
from cryptography.hazmat.primitives.asymmetric import rsa, padding
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()
ciphertext = public_key.encrypt(b"data", padding.OAEP(
    mgf=None, algorithm=None, label=None
))
"""
        findings = self.analyze(source)

        self.assertTrue(any(
            f["algorithm"] == "RSA"
            and f["operation"] == "encryption_operation"
            for f in findings
        ))

    def test_comments_and_strings_are_not_findings(self):
        source = """
# RSA.generate_private_key()
message = "ec.generate_private_key()"
"""
        findings = self.analyze(source)
        self.assertEqual(findings, [])

    def test_normal_python_code_is_not_crypto(self):
        source = """
def calculate_total(price, quantity):
    return price * quantity
"""
        findings = self.analyze(source)
        self.assertEqual(findings, [])

    def test_rsa_import_alias(self):
        source = """
from cryptography.hazmat.primitives.asymmetric import rsa as rsa_module
private_key = rsa_module.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
"""
        findings = self.analyze(source)

        self.assertTrue(any(
            f["algorithm"] == "RSA"
            and f["operation"] == "key_generation"
            for f in findings
        ))

    def test_ecc_import_alias_key_exchange(self):
        source = """
from cryptography.hazmat.primitives.asymmetric import ec as elliptic_curve
exchange = elliptic_curve.ECDH()
"""
        findings = self.analyze(source)

        self.assertTrue(any(
            f["algorithm"] == "ECC"
            and f["context"] == "key_exchange"
            for f in findings
        ))

    def test_misleading_crypto_references(self):
        source = '''
description = "RSA and ECC are examples of public-key cryptography."

def generate_report():
    return "No cryptographic operation is performed here."

# rsa.generate_private_key()
'''
        findings = self.analyze(source)
        self.assertEqual(findings, [])



    def test_rsa_key_size_extraction(self):
        source = """
from cryptography.hazmat.primitives.asymmetric import rsa

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=3072
)
"""
        findings = self.analyze(source)

        rsa_finding = next(
            f for f in findings
            if f["algorithm"] == "RSA"
            and f["operation"] == "key_generation"
        )

        self.assertEqual(
            rsa_finding["parameters"]["key_size_bits"],
            3072
        )

    def test_ecc_curve_extraction(self):
        source = """
from cryptography.hazmat.primitives.asymmetric import ec

private_key = ec.generate_private_key(
    curve=ec.SECP384R1()
)
"""
        findings = self.analyze(source)

        ecc_finding = next(
            f for f in findings
            if f["algorithm"] == "ECC"
            and f["operation"] == "key_generation"
        )

        self.assertEqual(
            ecc_finding["parameters"]["curve"],
            "SECP384R1"
        )



   
    def test_ecc_positional_curve_extraction(self):
        source = """
from cryptography.hazmat.primitives.asymmetric import ec

private_key = ec.generate_private_key(
    ec.SECP256R1()
)
"""
        findings = self.analyze(source)

        ecc_finding = next(
            f for f in findings
            if f["algorithm"] == "ECC"
            and f["operation"] == "key_generation"
        )

        self.assertEqual(
            ecc_finding["parameters"]["curve"],
            "SECP256R1"
        )



    def test_rsa_pss_parameter_extraction(self):
        source = """
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

signature_padding = padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH
)
"""
        findings = self.analyze(source)

        finding = next(
            f for f in findings
            if f["operation"] == "signature_padding"
        )

        self.assertEqual(finding["parameters"]["scheme"], "PSS")
        self.assertEqual(finding["parameters"]["mgf"], "MGF1")

    def test_rsa_oaep_parameter_extraction(self):
        source = """
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

encryption_padding = padding.OAEP(
    mgf=padding.MGF1(hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None
)
"""
        findings = self.analyze(source)

        finding = next(
            f for f in findings
            if f["operation"] == "encryption_padding"
        )

        self.assertEqual(finding["parameters"]["scheme"], "OAEP")
        self.assertEqual(finding["parameters"]["mgf"], "MGF1")
        self.assertEqual(
            finding["parameters"]["hash_algorithm"],
            "SHA256"
        )

    def test_ecc_ecdsa_hash_extraction(self):
        source = """
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

algorithm = ec.ECDSA(hashes.SHA256())
"""
        findings = self.analyze(source)

        finding = next(
            f for f in findings
            if f["operation"] == "signature_scheme"
        )

        self.assertEqual(finding["parameters"]["scheme"], "ECDSA")
        self.assertEqual(
            finding["parameters"]["hash_algorithm"],
            "SHA256"
        )



    def test_rsa_pss_mgf_hash_extraction(self):
        source = """
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

signature_padding = padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH
)
"""
        findings = self.analyze(source)

        finding = next(
            f for f in findings
            if f["operation"] == "signature_padding"
        )

        self.assertEqual(
            finding["parameters"]["mgf_hash_algorithm"],
            "SHA256"
        )

if __name__ == "__main__":
    unittest.main(verbosity=2)
