# Copyright 2016-2020 Open Source Robotics Foundation, Inc.
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

macro(sros2_generate_artifacts)
  # sros2_generate_artifacts(ENCLAVES <enclave_1> <enclave_2>...<enclave_n> [PQ_ALGORITHM <pq_algorithm>])
  #
  # ENCLAVES (macro multi-arg) takes the enclave names for which artifacts will be generated
  # PQ_ALGORITHM (optional) specifies the post-quantum algorithm to use
  #   Options: DEFAULT, dilithium2, dilithium3, dilithium5, falcon512, falcon1024
  #   If not specified or set to DEFAULT, traditional cryptography will be used
  # SECURITY (cmake arg) if not defined or OFF, will not generate keystore/keys/permissions
  # POLICY_FILE (cmake arg) if defined, policies defined in the file will be used to generate
  #   permission files for all the enclaves listed in the policy file
  # ROS_SECURITY_KEYSTORE (env variable) will be the location of the keystore
  if(NOT SECURITY)
    message(STATUS "Not generating security files")
    return()
  endif()
  find_program(PROGRAM ros2)

  if(DEFINED ENV{ROS_SECURITY_KEYSTORE})
    set(SECURITY_KEYSTORE $ENV{ROS_SECURITY_KEYSTORE})
  else()
    set(SECURITY_KEYSTORE ${DEFAULT_KEYSTORE})
  endif()
  cmake_parse_arguments(ros2_generate_security_artifacts "" "PQ_ALGORITHM" "ENCLAVES" ${ARGN})
  set(generate_artifacts_command ${PROGRAM} security generate_artifacts -k ${SECURITY_KEYSTORE})
  list(LENGTH ros2_generate_security_artifacts_ENCLAVES nb_enclaves)
  if(${nb_enclaves} GREATER "0")
    list(APPEND generate_artifacts_command "-e")
    foreach(enclave ${ros2_generate_security_artifacts_ENCLAVES})
        list(APPEND generate_artifacts_command ${enclave})
    endforeach()
  endif()
  if(POLICY_FILE)
    if(EXISTS ${POLICY_FILE})
      set(policy ${POLICY_FILE})
      list(APPEND generate_artifacts_command -p ${policy})
    else()
      message(WARNING "policy file '${POLICY_FILE}' doesn't exist, skipping..")
    endif()
  endif()
  if(DEFINED ros2_generate_security_artifacts_PQ_ALGORITHM)
    list(APPEND generate_artifacts_command --pq-algorithm ${ros2_generate_security_artifacts_PQ_ALGORITHM})
  endif()

  message(STATUS "Executing: ${generate_artifacts_command}")
  execute_process(
    COMMAND ${generate_artifacts_command}
    RESULT_VARIABLE GENERATE_ARTIFACTS_RESULT
    ERROR_VARIABLE GENERATE_ARTIFACTS_ERROR
  )
  if(NOT ${GENERATE_ARTIFACTS_RESULT} EQUAL 0)
    message(WARNING "Failed to generate security artifacts: ${GENERATE_ARTIFACTS_ERROR}")
  else()
    message(STATUS "Artifacts generated successfully")
  endif()
endmacro()

