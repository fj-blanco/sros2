# SROS2 with Post-Quantum Cryptography Integration (Work in Progress)

This repository is a fork of the original [SROS2 project](https://github.com/ros2/sros2), extended to support post-quantum cryptography (PQC) algorithms in its security management features. Please note that this is a work in progress and subject to changes and improvements.

## Overview

SROS2 (Secure Robot Operating System 2) provides tools and instructions to use ROS 2 with enhanced security features. This fork extends SROS2 to incorporate post-quantum cryptography options, preparing ROS 2 communications for potential quantum computer threats.

Key features of this fork:

- Support for PQC algorithms in certificate generation and management
- Compatibility with existing SROS2 features and workflows
- Extended CLI commands to support PQ algorithms

This fork uses the [oqs-provider](https://github.com/open-quantum-safe/oqs-provider) (which uses [liboqs](https://github.com/open-quantum-safe/liboqs) as the underlying cryptographic library) to enable post-quantum cryptography options in SROS2's security management features.

## Compatibility with PQSec-DDS

This fork of SROS2 is designed to work alongside PQC-enabled DDS implementations. Specifically, it has been tested with [PQSec-DDS](https://github.com/qursa-uc3m/pqsec-dds), a post-quantum cryptography plugin for the CycloneDDS middleware.

SROS2 and PQSec-DDS have complementary roles in providing post-quantum security for ROS 2:

- This SROS2 fork manages security artifacts (certificates, keys, etc.) and supports post-quantum signatures for these artifacts.
- PQSec-DDS handles the secure communication at the DDS level, implementing both post-quantum Key Encapsulation Mechanisms (KEMs) and signatures for the actual data exchange.

By using both together, you can achieve a more comprehensive post-quantum security setup for ROS 2:

- SROS2 ensures that the security artifacts are quantum-resistant.
- PQSec-DDS provides quantum-resistant communication channels and data integrity.

We provide a [testing guide](sros2_pqsecdds.md) that demonstrates how to use this SROS2 fork in conjunction with PQSec-DDS for a fully post-quantum secure ROS 2 setup.

## Documentation

- [Building ROS2 Jazzy Jalisco](build_ros2_jazzy.md): Instructions for building ROS2 Jazzy Jalisco from binaries or source.
- [Testing SROS2 with PQC and PQSec-DDS](sros2_pqsecdds.md): Guide on setting up and testing this SROS2 fork with PQC-enabled DDS.

## Original SROS2 Documentation

- [Try SROS2 on Linux](SROS2_Linux.md)
- [Try SROS2 on MacOS](SROS2_MacOS.md)
- [Try SROS2 on Windows](SROS2_Windows.md)

## Getting Started

To get started with this PQ-enabled version of SROS2:

1. Follow the [ROS2 Jazzy Jalisco build instructions](build_ros2_jazzy.md).
2. Set up this SROS2 fork and optionally PQSec-DDS as described in the [testing guide](sros2_pqsecdds.md).

Remember, as this is a work in progress, you may encounter issues or limitations. We welcome feedback and contributions to improve this integration.