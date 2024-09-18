# Copyright 2020 Canonical Ltd
# Copyright 2016-2019 Open Source Robotics Foundation, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import datetime
import os
import sys
import pathlib
import datetime
import tempfile
import subprocess

from cryptography import x509
from cryptography.hazmat.backends import default_backend as cryptography_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

import sros2.errors

_DOMAIN_ID_ENV = 'ROS_DOMAIN_ID'
_KEYSTORE_DIR_ENV = 'ROS_SECURITY_KEYSTORE'

#OPENSSL_BINARY_NAME = "openssl"
OPENSSL_BINARY_NAME = "oqs_openssl3" # TODO: change to default openssl if necessary
# using the custom installation with symbolic link at oqs_openssl3 avoid conflicts with the local installation
OQS_PROVIDER_NAME = 'oqsprovider'

class PQPrivateKey:
    def __init__(self, key_path: pathlib.Path):
        self.key_path = key_path

    def public_key(self):
        return PQPublicKey(self.key_path)

    def sign(self, data: bytes):
        try:
            # Write data to a temporary file
            with tempfile.NamedTemporaryFile(delete=False) as temp_data_file:
                temp_data_file.write(data)
                temp_data_file_path = temp_data_file.name

            # Output signature to a temporary file
            with tempfile.NamedTemporaryFile(delete=False) as temp_sig_file:
                temp_sig_file_path = temp_sig_file.name

            subprocess.run([
                OPENSSL_BINARY_NAME, 'pkeyutl',
                '-sign',
                '-rawin',  # Add this line
                '-inkey', str(self.key_path),
                '-provider', OQS_PROVIDER_NAME,
                '-in', temp_data_file_path,
                '-out', temp_sig_file_path,
            ], check=True)

            # Read the signature
            with open(temp_sig_file_path, 'rb') as f:
                signature = f.read()

            return signature
        except subprocess.CalledProcessError as e:
            print(f"Error signing data: {e}")
            raise
        finally:
            # Clean up temporary files
            os.unlink(temp_data_file_path)
            os.unlink(temp_sig_file_path)

class PQPublicKey:
    def __init__(self, key_path: pathlib.Path):
        self.key_path = key_path

    def verify(self, signature: bytes, data: bytes):
        try:
            # Write data and signature to temporary files
            with tempfile.NamedTemporaryFile(delete=False) as temp_data_file:
                temp_data_file.write(data)
                temp_data_file_path = temp_data_file.name

            with tempfile.NamedTemporaryFile(delete=False) as temp_sig_file:
                temp_sig_file.write(signature)
                temp_sig_file_path = temp_sig_file.name

            subprocess.run([
                OPENSSL_BINARY_NAME, 'pkeyutl',
                '-verify',
                '-rawin',  # Add this line
                '-pubin',
                '-inkey', str(self.key_path),
                '-provider', OQS_PROVIDER_NAME,
                '-in', temp_data_file_path,
                '-sigfile', temp_sig_file_path,
            ], check=True)

            return True
        except subprocess.CalledProcessError:
            return False
        finally:
            # Clean up temporary files
            os.unlink(temp_data_file_path)
            os.unlink(temp_sig_file_path)

class PQCertificate:
    def __init__(self, builder, signature):
        self.builder = builder
        self.signature = signature

class PQCertificateBuilder:
    def __init__(self):
        self._issuer_name = None
        self._subject_name = None
        self._public_key = None
        self._serial_number = None
        self._not_valid_before = None
        self._not_valid_after = None
        self._extensions = []

    def issuer_name(self, name):
        self._issuer_name = name
        return self

    def subject_name(self, name):
        self._subject_name = name
        return self

    def public_key(self, key):
        self._public_key = key
        return self

    def serial_number(self, number):
        self._serial_number = number
        return self

    def not_valid_before(self, time):
        self._not_valid_before = time
        return self

    def not_valid_after(self, time):
        self._not_valid_after = time
        return self

    def add_extension(self, extension, critical):
        self._extensions.append((extension, critical))
        return self

    def sign(self, private_key: PQPrivateKey):
        # Serialize the certificate information
        tbs_certificate = self._serialize_tbs_certificate()

        # Sign the TBS (To-Be-Signed) certificate
        signature = private_key.sign(tbs_certificate)

        return PQCertificate(self, signature)

    def _serialize_tbs_certificate(self):
        # In a real implementation, this would properly serialize all the certificate fields
        # For simplicity, we'll just concatenate some fields
        return f"{self._issuer_name}{self._subject_name}{self._serial_number}".encode()
    
def is_provider_available(provider_name):
    try:
        result = subprocess.run(
            [OPENSSL_BINARY_NAME, 'list', '-providers'],
            capture_output=True,
            text=True,
            check=True
        )
        output = provider_name.lower() in result.stdout.lower().split()
        if output:
            print(f'The provider {provider_name} is correctly loaded')
        else:
            print(f'The provider {provider_name} cannot be found')
        return output
    except subprocess.CalledProcessError:
        return False

def create_symlink(*, src: pathlib.Path, dst: pathlib.Path):
    if dst.exists():
        # Don't do more work than we need to
        if dst.samefile(dst.parent.joinpath(src)):
            return
        os.remove(dst)
    os.symlink(src, dst)


def domain_id() -> str:
    return os.getenv(_DOMAIN_ID_ENV, '0')


def get_keystore_path_from_env() -> pathlib.Path:
    root_keystore_path = os.getenv(_KEYSTORE_DIR_ENV)
    if root_keystore_path is None:
        raise sros2.errors.InvalidKeystoreEnvironmentError(_KEYSTORE_DIR_ENV)
    return pathlib.Path(root_keystore_path)


def create_smime_signed_file(cert_path: pathlib.Path, key_path: pathlib.Path, 
                             unsigned_file_path: pathlib.Path, signed_file_path: pathlib.Path, 
                             pq_algorithm: str = 'default'):
    use_pq = pq_algorithm != 'DEFAULT' and is_provider_available(OQS_PROVIDER_NAME)

    if use_pq:
        try:
            with tempfile.NamedTemporaryFile(delete=False) as temp_in:
                temp_in.write(unsigned_file_path.read_bytes())
                temp_in_path = pathlib.Path(temp_in.name)
            
            with tempfile.NamedTemporaryFile(delete=False) as temp_out:
                temp_out_path = pathlib.Path(temp_out.name)

            # check https://github.com/open-quantum-safe/oqs-provider/blob/main/USAGE.md#smime-message-signing----cryptographic-message-syntax-cms
            # for the documentation about S/MIME signing with the oqsprovider

            subprocess.run([
                OPENSSL_BINARY_NAME, 'cms', '-sign',
                '-in', str(unsigned_file_path),
                '-signer', str(cert_path),
                '-inkey', str(key_path),
                '-outform', 'PEM',
                '-nodetach',
                '-out', str(signed_file_path),
                '-md', 'sha512',
                '-provider', OQS_PROVIDER_NAME,
                '-provider', 'default'
            ], check=True)
            
            signed_data = temp_out_path.read_bytes()
            with open(signed_file_path, 'wb') as f:
                f.write(signed_data)
            
            print(f"S/MIME signed file (PQ) created at {signed_file_path}")
        except subprocess.CalledProcessError as e:
            print(f"Error signing file with PQ crypto: {e}")
            sys.exit(1)
        finally:
            # Securely delete temporary files
            if temp_in_path.exists():
                temp_in_path.unlink()
            if temp_out_path.exists():
                temp_out_path.unlink()
    else:
        cert = load_cert(cert_path)

        with open(key_path, 'rb') as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(), None, cryptography_backend())

        with open(unsigned_file_path, 'rb') as f:
            content = f.read()

        with open(signed_file_path, 'wb') as f:
            f.write(_sign_bytes(cert, private_key, content))
        print(f"S/MIME signed file created at {signed_file_path}")

def generate_pq_key(pq_algorithm: str = 'default') -> PQPrivateKey:
    key_path = pathlib.Path(f"pq_key_{pq_algorithm}.pem")
    try:
        subprocess.run([
            OPENSSL_BINARY_NAME, 'genpkey',
            '-algorithm', pq_algorithm,
            '-provider', OQS_PROVIDER_NAME,
            '-out', str(key_path)
        ], check=True)
        print(f"Post-Quantum key generated at {key_path}")
        return PQPrivateKey(key_path)
    except subprocess.CalledProcessError as e:
        print(f"Error generating PQ key: {e}")
        sys.exit(1)

def build_key_and_cert(subject_name, *, ca=False, ca_key=None, issuer_name='', pq_algorithm='default'):
    if not issuer_name:
            issuer_name = subject_name

    use_pq = pq_algorithm != 'default' and is_provider_available(OQS_PROVIDER_NAME)

    if use_pq:
        try:
            # Generate a new post-quantum private key 
            private_key = generate_pq_key(pq_algorithm=pq_algorithm)  # TODO: properly link with algorithm name

            # If no CA key is provided, use the newly generated private key as the CA key
            if not ca_key:
                ca_key = private_key

            # Set up the BasicConstraints extension
            extension = x509.BasicConstraints(ca=True, path_length=1) if ca else x509.BasicConstraints(ca=False, path_length=None)

            utcnow = datetime.datetime.utcnow()
            
            # Create a certificate builder and set its properties
            builder = PQCertificateBuilder()
            builder = builder.issuer_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, issuer_name)]))
            builder = builder.serial_number(x509.random_serial_number())
            builder = builder.not_valid_before(utcnow - datetime.timedelta(days=1))
            builder = builder.not_valid_after(utcnow + datetime.timedelta(days=3650))
            builder = builder.public_key(private_key.public_key())
            builder = builder.subject_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, subject_name)]))
            builder = builder.add_extension(extension, critical=ca)

            # Sign the certificate with the CA key
            #cert = builder.sign(ca_key, 'dilithium3') # TODO: properly link with algorithm name
            cert = builder.sign(ca_key)
        except Exception as e:
            print(f"Error in PQ key and cert generation: {e}")
            return None, None
    else:
        # DDS-Security section 9.3.1 calls for prime256v1, for which SECP256R1 is an alias
        private_key = ec.generate_private_key(ec.SECP256R1, cryptography_backend())
        if not ca_key:
            ca_key = private_key

        if ca:
            extension = x509.BasicConstraints(ca=True, path_length=1)
        else:
            extension = x509.BasicConstraints(ca=False, path_length=None)

        utcnow = datetime.datetime.utcnow()
        builder = x509.CertificateBuilder(
            ).issuer_name(
                issuer_name
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                # Using a day earlier here to prevent Connext (5.3.1) from complaining
                # when extracting it from the permissions file and thinking it's in the future
                # https://github.com/ros2/ci/pull/436#issuecomment-624874296
                utcnow - datetime.timedelta(days=1)
            ).not_valid_after(
                # TODO: This should not be hard-coded
                utcnow + datetime.timedelta(days=3650)
            ).public_key(
                private_key.public_key()
            ).subject_name(
                subject_name
            ).add_extension(
                extension, critical=ca
            )
        cert = builder.sign(ca_key, hashes.SHA256(), cryptography_backend())

    return (cert, private_key)


def write_key(
    key,
    key_path: pathlib.Path,
    *,
    encoding=serialization.Encoding.PEM,
    serialization_format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
):
    with open(key_path, 'wb') as f:
        f.write(key.private_bytes(
            encoding=encoding,
            format=serialization_format,
            encryption_algorithm=encryption_algorithm))


def write_cert(cert, cert_path: pathlib.Path, *, encoding=serialization.Encoding.PEM):
    with open(cert_path, 'wb') as f:
        f.write(cert.public_bytes(encoding=encoding))


def load_cert(cert_path: pathlib.Path):
    with open(cert_path, 'rb') as cert_file:
        return x509.load_pem_x509_certificate(
            cert_file.read(), cryptography_backend())


def _sign_bytes_pkcs7(cert, key, byte_string):
    from cryptography.hazmat.primitives.serialization import pkcs7

    builder = (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(byte_string)
        .add_signer(cert, key, hashes.SHA256())
    )
    options = [pkcs7.PKCS7Options.Text, pkcs7.PKCS7Options.DetachedSignature]
    return builder.sign(serialization.Encoding.SMIME, options)


def _sign_bytes_ssl_binding(cert, key, byte_string):
    from cryptography.hazmat.bindings.openssl.binding import Binding as SSLBinding

    # Using two flags here to get the output required:
    #   - PKCS7_DETACHED: Use cleartext signing
    #   - PKCS7_TEXT: Set the MIME headers for text/plain
    flags = SSLBinding.lib.PKCS7_DETACHED
    flags |= SSLBinding.lib.PKCS7_TEXT

    # Convert the byte string into a buffer for SSL
    bio_in = SSLBinding.lib.BIO_new_mem_buf(byte_string, len(byte_string))
    try:
        pkcs7 = SSLBinding.lib.PKCS7_sign(
            cert._x509, key._evp_pkey, SSLBinding.ffi.NULL, bio_in, flags)
    finally:
        # Free the memory allocated for the buffer
        SSLBinding.lib.BIO_free(bio_in)

    # PKCS7_sign consumes the buffer; allocate a new one again to get it into the final document
    bio_in = SSLBinding.lib.BIO_new_mem_buf(byte_string, len(byte_string))
    try:
        # Allocate a buffer for the output document
        bio_out = SSLBinding.lib.BIO_new(SSLBinding.lib.BIO_s_mem())
        try:
            # Write the final document out to the buffer
            SSLBinding.lib.SMIME_write_PKCS7(bio_out, pkcs7, bio_in, flags)

            # Copy the output document back to python-managed memory
            result_buffer = SSLBinding.ffi.new('char**')
            buffer_length = SSLBinding.lib.BIO_get_mem_data(bio_out, result_buffer)
            output = SSLBinding.ffi.buffer(result_buffer[0], buffer_length)[:]
        finally:
            # Free the memory required for the output buffer
            SSLBinding.lib.BIO_free(bio_out)
    finally:
        # Free the memory allocated for the input buffer
        SSLBinding.lib.BIO_free(bio_in)

    return output


def _sign_bytes(cert, key, byte_string):
    try:
        return _sign_bytes_pkcs7(cert, key, byte_string)
    except ImportError:
        pass

    return _sign_bytes_ssl_binding(cert, key, byte_string)
