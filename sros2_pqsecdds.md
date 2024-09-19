# Testing PQSec-DDS with SROS2 and CycloneDDS

**Note**: Before proceeding with this guide, please ensure you have ROS2 Jazzy Jalisco installed. For installation instructions, refer to the [ROS2 Jazzy Jalisco Installation Guide](build_ros2_jazzy.md) in the root of this repository.

## 1. Set up the environment

```bash
# Create and activate a new Python virtual environment
python3.12 -m venv .sros2-test-venv
source .sros2-test-venv/bin/activate

# Install required Python packages
pip install --no-cache-dir -r requirements.txt
```

## 2. Build dependencies

### Build liboqs

```bash
cd /tmp
git clone --branch main https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
sudo mkdir -p /opt/liboqs
cmake -GNinja -DCMAKE_INSTALL_PREFIX=/opt/liboqs ..
ninja
sudo ninja install
```

### Build oqs-provider

```bash
mkdir oqs-provider-install && cd oqs-provider-install
git clone git://git.openssl.org/openssl.git
cd openssl
./config --prefix=$(pwd)/../.local && make && make install_sw
cd ..
git clone https://github.com/open-quantum-safe/oqs-provider.git
cd oqs-provider
cmake -DOPENSSL_ROOT_DIR=$(pwd)/../.local -DCMAKE_PREFIX_PATH=$(pwd)/../.local -S . -B _build
cmake --build _build
cd ..
export LD_LIBRARY_PATH="$(pwd)/.local/lib64:$LD_LIBRARY_PATH"
```

### Configure OpenSSL for oqs-provider

Edit the OpenSSL configuration file (location found with `$(pwd)/.local/bin/openssl version -d`) to include:

```
[openssl_init]
providers = provider_sect

[provider_sect]
oqsprovider = oqsprovider_section
default = default_sect

[oqsprovider_section]
activate = 1
module = /path/to/oqs-provider-install/oqs-provider/_build/lib/oqsprovider.so
[default_sect]
activate = 1
[legacy_sect]
activate = 1
```

Verify the configuration:

```bash
$(pwd)/.local/bin/openssl list -providers -verbose
```

## 3. Build CycloneDDS

```bash
git clone https://github.com/eclipse-cyclonedds/cyclonedds.git
cd cyclonedds
mkdir build && cd build
sudo mkdir /opt/cyclonedds
cmake -DCMAKE_BUILD_TYPE=Debug -DBUILD_EXAMPLES=ON -DBUILD_TESTING=ON -DCMAKE_INSTALL_PREFIX=/opt/cyclonedds ..
sudo cmake --build . --target install
```

## 4. Build PQSec-DDS plugin

```bash
git clone https://github.com/qursa-uc3m/pqsec-dds.git
cd pqsec-dds/src
mkdir build && cd build
cmake -DENABLE_PQ_CRYPTO=ON \
    -DDEBUG=ON \
    -DCYCLONEDDS_PATH=/opt/cyclonedds \
    -DLIBOQS_PATH=/opt/liboqs \
    -DOPENSSL_PATH=/path/to/oqs-provider-install/.local \
    ..
cmake --build .
```

## 5. Build SROS2 with PQ support

```bash
cd /path/to/ros2_workspace
git clone -b pq https://github.com/fj-blanco/sros2.git src/sros2
colcon build --symlink-install --packages-select sros2
source install/setup.bash
```

## 6. Configure and run the test

```bash
# Set up CycloneDDS configuration
export CYCLONEDDS_URI=/path/to/pqsec-dds/config/cyclonedds/custom_auth_plugin.xml

# Add PQSec-DDS plugin to library path
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/path/to/pqsec-dds/src/build/lib

# Generate security artifacts
mkdir sros2_demo && cd sros2_demo
ros2 security create_keystore demo_keystore --pq-algorithm dilithium3
ros2 security create_enclave demo_keystore /talker_listener/talker --pq-algorithm dilithium3
ros2 security create_enclave demo_keystore /talker_listener/listener --pq-algorithm dilithium3

# Set up security environment
export ROS_SECURITY_KEYSTORE=$(pwd)/demo_keystore
export ROS_SECURITY_ENABLE=true
export ROS_SECURITY_STRATEGY=Enforce

# Run the test nodes
# Terminal 1
ros2 run demo_nodes_cpp talker --ros-args --enclave /talker_listener/talker

# Terminal 2
ros2 run demo_nodes_py listener --ros-args --enclave /talker_listener/listener
```

Check the output of both terminals to ensure that:

1. The PQSec-DDS plugin is being used (look for debug messages).
2. The talker and listener are communicating securely.
3. Post-quantum algorithms are being used for key exchange and signatures.

If everything is set up correctly, you should see the talker publishing messages and the listener receiving them, with all communication secured using post-quantum cryptography via PQSec-DDS and your modified SROS2.