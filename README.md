# SROS2 with native ML-DSA identities

This experimental fork adds native OpenSSL 3.5 ML-DSA identity certificate
generation to upstream SROS2. It is intended for PQSec-DDS experiments. The
normal SROS2 behavior remains the default.

The fork deliberately uses two certification authorities when ML-DSA is
selected:

- The identity CA and participant certificates use `ML-DSA-44`,
  `ML-DSA-65`, or `ML-DSA-87` from OpenSSL's default provider.
- The permissions CA stays on P-256 because the OpenSSL CMS path used for DDS
  governance and permissions does not yet support digestless ML-DSA signing.

This makes participant authentication post-quantum in the experimental DDS
plugin. It does not make every SROS2 artifact post-quantum, and it does not
define an official DDS Security profile.

## Use

Install ROS 2 Lyrical and OpenSSL 3.5 or newer, then build this repository as a
ROS overlay:

```bash
source /opt/ros/lyrical/setup.bash
colcon build --packages-select sros2 sros2_cmake
source install/setup.bash

ros2 security create_keystore demo_keystore \
  --identity-algorithm ML-DSA-44
ros2 security create_enclave demo_keystore /talker_listener/talker
ros2 security create_enclave demo_keystore /talker_listener/listener
```

Set `SROS2_OPENSSL` only when the required OpenSSL executable is not on
`PATH`. No liboqs or oqsprovider installation is needed for standardized
ML-DSA algorithms.

See [the integration guide](sros2_pqsecdds.md) for the PQSec-DDS boundary and
the upstream platform guides for general SROS2 usage:

- [Linux](SROS2_Linux.md)
- [macOS](SROS2_MacOS.md)
- [Windows](SROS2_Windows.md)
