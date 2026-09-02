# Copyright 2020 Canonical Ltd
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

import pathlib
import subprocess

import pytest

from sros2 import _utilities
import sros2.errors


def test_get_keystore_path_from_env(monkeypatch):
    monkeypatch.setenv(_utilities._KEYSTORE_DIR_ENV, '/keystore/path')
    assert _utilities.get_keystore_path_from_env() == pathlib.Path('/keystore/path')


def test_get_keystore_path_from_env_error(monkeypatch):
    monkeypatch.delenv(_utilities._KEYSTORE_DIR_ENV, raising=False)

    with pytest.raises(sros2.errors.InvalidKeystoreEnvironmentError) as e:
        _utilities.get_keystore_path_from_env()

    assert e.value.variable_name == _utilities._KEYSTORE_DIR_ENV


def test_openssl_subject_escapes_enclave_path():
    assert _utilities._openssl_subject('/demo/talker') == r'/CN=\/demo\/talker'


def _supports_mldsa44():
    result = subprocess.run(
        ['openssl', 'list', '-signature-algorithms'],
        capture_output=True,
        text=True)
    return result.returncode == 0 and 'ML-DSA-44' in result.stdout


@pytest.mark.skipif(not _supports_mldsa44(), reason='OpenSSL lacks ML-DSA-44')
def test_build_pq_identity_certificate(tmp_path):
    ca_key = tmp_path / 'ca.key.pem'
    ca_cert = tmp_path / 'ca.cert.pem'
    key = tmp_path / 'node.key.pem'
    cert = tmp_path / 'node.cert.pem'

    _utilities.build_pq_identity_ca(
        'sros2CA', 'ML-DSA-44', ca_key, ca_cert)
    _utilities.build_pq_identity_certificate(
        '/demo/talker', 'ML-DSA-44', ca_key, ca_cert, key, cert)

    result = subprocess.run(
        ['openssl', 'verify', '-CAfile', str(ca_cert), str(cert)],
        check=True,
        capture_output=True,
        text=True)
    assert result.stdout.rstrip().endswith(': OK')
