# PQSec-DDS integration

Use this fork with the current
[PQSec-DDS CycloneDDS adapter](https://github.com/qursa-uc3m/pqsec-dds).
Both projects use OpenSSL EVP and the standardized OpenSSL 3.5 algorithm names.

The responsibilities are separate:

| Layer | Experimental protection |
|---|---|
| SROS2 identity artifacts | ML-DSA X.509 CA and participant certificates |
| DDS authentication plugin | ML-KEM or hybrid KEM handshake and ML-DSA identity proof |
| DDS access control | P-256 CMS-signed governance and permissions |
| DDS data protection | CycloneDDS built-in DDS Security cryptographic plugin |

Build the adapter with a native OpenSSL KEM:

```bash
git clone https://github.com/qursa-uc3m/pqsec-dds.git
cd pqsec-dds
adapters/cyclonedds/scripts/build_plugin.sh \
  -c /opt/ros/lyrical \
  -s /usr \
  --kem mlkem768 \
  -t Release
```

Then generate the keystore as shown in the root README, point CycloneDDS at
the adapter's security configuration, and run ROS nodes with their normal
`--enclave` arguments. The complete, containerized talker/listener test lives
in [ros2-pqc-demos](https://github.com/qursa-uc3m/ros2-pqc-demos).

The adapter handshake is experimental and requires the same PQSec-DDS plugin
and KEM selection at both peers. It is not interoperable with a stock DDS
Security authentication plugin.
