import datetime
import ipaddress
import socket
import ssl
import tempfile
import threading
import unittest
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from tlsgrader.scanner import _probe_ssl2, _probe_ssl3, scan_target


class LocalTLSServer:
    def __init__(self, directory: str):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
            .sign(key, hashes.SHA256())
        )
        self.cert_path = Path(directory) / "cert.pem"
        self.key_path = Path(directory) / "key.pem"
        self.cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        self.key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
        self.socket = socket.socket()
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen(20)
        self.socket.settimeout(.2)
        self.port = self.socket.getsockname()[1]
        self.stop_event = threading.Event()
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(self.cert_path, self.key_path)
        self.thread = threading.Thread(target=self.run, daemon=True)

    def start(self):
        self.thread.start()

    def run(self):
        while not self.stop_event.is_set():
            try:
                client, _ = self.socket.accept()
                with client:
                    try:
                        with self.context.wrap_socket(client, server_side=True) as tls:
                            tls.settimeout(.2)
                            try:
                                tls.recv(64)
                            except Exception:
                                pass
                    except ssl.SSLError:
                        pass
            except socket.timeout:
                pass
            except OSError:
                break

    def close(self):
        self.stop_event.set()
        self.socket.close()
        self.thread.join(timeout=2)


class OneShotProbeServer:
    def __init__(self, response: bytes):
        self.response = response
        self.socket = socket.socket()
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen(1)
        self.port = self.socket.getsockname()[1]
        self.thread = threading.Thread(target=self.run, daemon=True)

    def start(self):
        self.thread.start()

    def run(self):
        try:
            client, _ = self.socket.accept()
            with client:
                client.settimeout(1)
                client.recv(4096)
                client.sendall(self.response)
        finally:
            self.socket.close()

    def close(self):
        self.thread.join(timeout=2)


class ScannerIntegrationTests(unittest.TestCase):
    def test_raw_ssl3_probe_detects_server_hello(self):
        server = OneShotProbeServer(b"\x16\x03\x00\x00\x06\x02\x00\x00\x02\x03\x00")
        server.start()
        try:
            state, detail = _probe_ssl3("127.0.0.1", server.port, 1)
        finally:
            server.close()
        self.assertEqual(state, "supported")
        self.assertEqual(detail["server_version_hex"], "0300")

    def test_raw_ssl2_probe_detects_server_hello(self):
        server = OneShotProbeServer(b"\x80\x05\x04\x00\x01\x00\x02")
        server.start()
        try:
            state, detail = _probe_ssl2("127.0.0.1", server.port, 1)
        finally:
            server.close()
        self.assertEqual(state, "supported")
        self.assertEqual(detail["server_version_hex"], "0002")

    def test_self_signed_local_server_is_scanned_and_capped(self):
        with tempfile.TemporaryDirectory() as directory:
            local = LocalTLSServer(directory)
            local.start()
            try:
                result = scan_target("localhost", local.port, timeout=1.2, country="Singapore", sector="Education")
            finally:
                local.close()
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["certificate"]["common_name"], "localhost")
        self.assertTrue(result["certificate"]["hostname_valid"])
        self.assertFalse(result["certificate"]["trust_valid"])
        self.assertIn(result["protocols"]["SSL 3.0"], {"unsupported", "error"})
        self.assertIn(result["protocols"]["SSL 2.0"], {"unsupported", "error"})
        self.assertEqual(result["scores"]["grade"], "F")


if __name__ == "__main__":
    unittest.main()
