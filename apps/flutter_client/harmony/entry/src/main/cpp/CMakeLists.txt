cmake_minimum_required(VERSION 3.5.0)
project(p2wlan_harmony_native LANGUAGES C CXX)

set(P2WLAN_OHOS_ABI "arm64-v8a" CACHE STRING "OHOS package ABI")
set_property(CACHE P2WLAN_OHOS_ABI PROPERTY STRINGS arm64-v8a x86_64)
if(NOT P2WLAN_OHOS_ABI STREQUAL "arm64-v8a" AND NOT P2WLAN_OHOS_ABI STREQUAL "x86_64")
  message(FATAL_ERROR "Unsupported P2WLAN_OHOS_ABI: ${P2WLAN_OHOS_ABI}")
endif()

get_filename_component(P2WLAN_REPO_ROOT
  "${CMAKE_CURRENT_LIST_DIR}/../../../../../../.." ABSOLUTE)
get_filename_component(P2WLAN_WORKSPACE_ROOT "${P2WLAN_REPO_ROOT}/.." ABSOLUTE)
if(DEFINED ENV{P2WLAN_TOOLCHAIN_DIR} AND NOT "$ENV{P2WLAN_TOOLCHAIN_DIR}" STREQUAL "")
  set(P2WLAN_TOOLCHAIN_DIR "$ENV{P2WLAN_TOOLCHAIN_DIR}")
else()
  set(P2WLAN_TOOLCHAIN_DIR "${P2WLAN_WORKSPACE_ROOT}/toolchains")
endif()

if(DEFINED ENV{DEVECO_SDK_HOME} AND NOT "$ENV{DEVECO_SDK_HOME}" STREQUAL "")
  set(P2WLAN_DEVECO_SDK_HOME "$ENV{DEVECO_SDK_HOME}")
else()
  get_filename_component(P2WLAN_NATIVE_ROOT "${CMAKE_SYSROOT}/.." ABSOLUTE)
  get_filename_component(P2WLAN_OHOS_ROOT "${P2WLAN_NATIVE_ROOT}/.." ABSOLUTE)
  get_filename_component(P2WLAN_SDK_DEFAULT "${P2WLAN_OHOS_ROOT}/.." ABSOLUTE)
  get_filename_component(P2WLAN_DEVECO_SDK_HOME "${P2WLAN_SDK_DEFAULT}/.." ABSOLUTE)
endif()

execute_process(
  COMMAND "${CMAKE_COMMAND}" -E env
    "DEVECO_SDK_HOME=${P2WLAN_DEVECO_SDK_HOME}"
    "P2WLAN_TOOLCHAIN_DIR=${P2WLAN_TOOLCHAIN_DIR}"
    "P2WLAN_OHOS_ABI=${P2WLAN_OHOS_ABI}"
    /bin/bash "${P2WLAN_REPO_ROOT}/scripts/build_harmony_native.sh"
  WORKING_DIRECTORY "${P2WLAN_REPO_ROOT}"
  RESULT_VARIABLE P2WLAN_RUST_BUILD_RESULT
)
if(NOT P2WLAN_RUST_BUILD_RESULT EQUAL 0)
  message(FATAL_ERROR "Building the P2WLAN Harmony Rust cdylib failed (${P2WLAN_RUST_BUILD_RESULT}).")
endif()

set(P2WLAN_RUST_LIBRARY
  "${P2WLAN_TOOLCHAIN_DIR}/p2wlan-harmony-native/${P2WLAN_OHOS_ABI}/libp2wlan_harmony_core.so")
if(NOT EXISTS "${P2WLAN_RUST_LIBRARY}")
  message(FATAL_ERROR "The P2WLAN Rust cdylib is missing: ${P2WLAN_RUST_LIBRARY}")
endif()

add_library(p2wlan_harmony_core SHARED IMPORTED GLOBAL)
set_target_properties(p2wlan_harmony_core PROPERTIES
  IMPORTED_LOCATION "${P2WLAN_RUST_LIBRARY}")

if(P2WLAN_OHOS_ABI STREQUAL "arm64-v8a")
  set(P2WLAN_NAPI_LIBDIR "aarch64-linux-ohos")
else()
  set(P2WLAN_NAPI_LIBDIR "x86_64-linux-ohos")
endif()
find_library(P2WLAN_NAPI_LIBRARY ace_napi.z
  PATHS "${P2WLAN_DEVECO_SDK_HOME}/default/openharmony/native/sysroot/usr/lib/${P2WLAN_NAPI_LIBDIR}"
  NO_DEFAULT_PATH)
if(NOT P2WLAN_NAPI_LIBRARY)
  message(FATAL_ERROR "The DevEco SDK libace_napi.z library is missing for ${P2WLAN_OHOS_ABI}.")
endif()

add_library(p2wlan_harmony_native SHARED napi_init.cpp)
target_compile_features(p2wlan_harmony_native PRIVATE cxx_std_17)
target_include_directories(p2wlan_harmony_native PRIVATE
  "${CMAKE_CURRENT_LIST_DIR}/include")
target_link_libraries(p2wlan_harmony_native PUBLIC
  p2wlan_harmony_core
  "${P2WLAN_NAPI_LIBRARY}")
set_target_properties(p2wlan_harmony_native PROPERTIES
  BUILD_WITH_INSTALL_RPATH TRUE
  BUILD_RPATH "$ORIGIN"
  INSTALL_RPATH "$ORIGIN")

add_custom_command(TARGET p2wlan_harmony_native POST_BUILD
  COMMAND "${CMAKE_COMMAND}" -E copy_if_different
    "${P2WLAN_RUST_LIBRARY}"
    "$<TARGET_FILE_DIR:p2wlan_harmony_native>/libp2wlan_harmony_core.so"
  COMMENT "Packaging the Rust Harmony core dependency")
