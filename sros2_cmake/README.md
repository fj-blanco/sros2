# Security Helper
Add authentication, cryptography, and access control security keys using a cmake macro.
The macro will generate the secure root directory if it does not exist, then create authentication and cryptography keys.

In package.xml add:  
`<depend>sros2_cmake</depend>`  
In CMakeLists add:  
`find_package(sros2_cmake REQUIRED)`  
`sros2_generate_artifacts(ENCLAVES <enclave_name> [PQ_ALGORITHM <pq_algorithm>])`  

Macro definition:  
```
# sros2_generate_artifacts(ENCLAVES <enclave_1> <enclave_2>...<enclave_n> [PQ_ALGORITHM <pq_algorithm>])

# ENCLAVES (macro multi-arg) takes the enclaves names for which keys will be generated
#   Executables can use different or the same enclaves.
#   All nodes in the same process use the same enclave.
# PQ_ALGORITHM (optional) specifies the post-quantum algorithm to use. 
#   Options: DEFAULT, dilithium2, dilithium3, dilithium5, falcon512, falcon1024
#   If not specified or set to DEFAULT, traditional cryptography will be used.
# SECURITY (cmake arg) if not defined or OFF, will not generate key/keystores
# ROS_SECURITY_KEYSTORE (env variable) the location of the keystore
# POLICY_FILE (cmake arg) if defined, will generate security artifacts for each enclave defined in the policy file.
```

Example usage with post-quantum cryptography:
```cmake
sros2_generate_artifacts(ENCLAVES my_enclave PQ_ALGORITHM dilithium3)
```
