#ifndef P2WLAN_HARMONY_FFI_H
#define P2WLAN_HARMONY_FFI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct P2wlanBuildInfoV1 {
  uint32_t abi_version;
  uint32_t struct_size;
  const char *engine_version;
  const char *target;
  const char *arch;
} P2wlanBuildInfoV1;

typedef struct P2wlanPreparedVpnEngineV1 P2wlanPreparedVpnEngineV1;

typedef struct P2wlanStringViewV1 {
  const uint8_t *data;
  size_t len;
} P2wlanStringViewV1;

typedef struct P2wlanStringListV1 {
  const P2wlanStringViewV1 *items;
  size_t len;
} P2wlanStringListV1;

typedef struct P2wlanVpnIdentityV1 {
  P2wlanStringViewV1 instance_id;
  uint64_t generation;
} P2wlanVpnIdentityV1;

typedef struct P2wlanVpnSettingsV1 {
  P2wlanStringViewV1 control_server;
  P2wlanStringViewV1 auth_token;
  P2wlanStringViewV1 network_id;
  uint8_t manual_mode;
  P2wlanStringViewV1 virtual_ip;
  P2wlanStringViewV1 device_name;
  P2wlanStringViewV1 overlay_cidr;
  P2wlanStringViewV1 tun_interface;
  uint32_t mtu;
  P2wlanStringViewV1 udp_bind;
  P2wlanStringViewV1 udp_advertise;
  P2wlanStringViewV1 socket_pool;
  P2wlanStringListV1 relay_servers;
} P2wlanVpnSettingsV1;

typedef struct P2wlanVpnSettingsSnapshotV1 {
  uint32_t schema_version;
  uint64_t revision;
  P2wlanVpnSettingsV1 settings;
} P2wlanVpnSettingsSnapshotV1;

typedef struct P2wlanVpnNetworkRequestV1 {
  P2wlanStringViewV1 identity_store_path;
  P2wlanVpnSettingsSnapshotV1 settings_snapshot;
} P2wlanVpnNetworkRequestV1;

typedef struct P2wlanVpnStartRequestV1 {
  uint32_t version;
  P2wlanVpnIdentityV1 identity;
  int32_t fd;
  P2wlanStringListV1 configured_routes;
  uint8_t process_protected;
  P2wlanStringViewV1 identity_store_path;
  P2wlanVpnSettingsSnapshotV1 settings_snapshot;
} P2wlanVpnStartRequestV1;

enum {
  P2WLAN_HARMONY_ABI_VERSION = 1,
  P2WLAN_HARMONY_STATUS_OK = 0,
  P2WLAN_HARMONY_STATUS_NULL_OUTPUT = 1,
  P2WLAN_HARMONY_STATUS_BAD_ARGUMENT = 2,
  P2WLAN_HARMONY_STATUS_INVALID_REQUEST = 3,
  P2WLAN_HARMONY_STATUS_TUN_FD_DUP_FAILED = 4,
  P2WLAN_HARMONY_STATUS_TUN_FD_NOT_NONBLOCKING = 5,
  P2WLAN_HARMONY_STATUS_ALREADY_RUNNING = 6,
  P2WLAN_HARMONY_STATUS_ENGINE_BUSY = 7,
  P2WLAN_HARMONY_STATUS_STALE_GENERATION = 8,
  P2WLAN_HARMONY_STATUS_STALE_SETTINGS_SNAPSHOT = 9,
  P2WLAN_HARMONY_STATUS_START_TIMEOUT = 10,
  P2WLAN_HARMONY_STATUS_START_CANCELLED = 11,
  P2WLAN_HARMONY_STATUS_IDENTITY_STORE_FAILED = 12,
  P2WLAN_HARMONY_STATUS_ROUTE_PROOF_INVALID = 13,
  P2WLAN_HARMONY_STATUS_CONFIG_INVALID = 14,
  P2WLAN_HARMONY_STATUS_AUTH_FAILED = 15,
  P2WLAN_HARMONY_STATUS_DAEMON_START_FAILED = 16,
  P2WLAN_HARMONY_STATUS_STOPPED = 17,
  P2WLAN_HARMONY_STATUS_DRAINING = 18,
  P2WLAN_HARMONY_STATUS_UNKNOWN_IDENTITY = 19,
  P2WLAN_HARMONY_STATUS_TUN_FD_INVALID_MODE = 20,
  P2WLAN_HARMONY_STATUS_ENGINE_HISTORY_FULL = 21,
  P2WLAN_HARMONY_STATUS_NETWORK_PREFLIGHT_FAILED = 22,
  P2WLAN_HARMONY_ENGINE_STARTING = 0,
  P2WLAN_HARMONY_ENGINE_READY = 1,
  P2WLAN_HARMONY_ENGINE_STOPPING = 2,
  P2WLAN_HARMONY_ENGINE_STOPPED = 3,
  P2WLAN_HARMONY_ENGINE_FAILED_BASE = 100,
};

int32_t p2wlan_harmony_get_build_info_v1(P2wlanBuildInfoV1 *output);
int32_t p2wlan_harmony_prepare_vpn_engine_v1(
    const P2wlanVpnStartRequestV1 *request,
    P2wlanPreparedVpnEngineV1 **output);
int32_t p2wlan_harmony_prepare_vpn_network_v1(
    const P2wlanVpnNetworkRequestV1 *request, uint8_t *virtual_ip_output,
    size_t virtual_ip_capacity, uint8_t *cidr_output, size_t cidr_capacity);
int32_t p2wlan_harmony_discard_vpn_network_v1(
    const uint8_t *identity_store_path, size_t path_len);
int32_t p2wlan_harmony_activate_vpn_engine_v1(
    P2wlanPreparedVpnEngineV1 *prepared);
void p2wlan_harmony_abort_vpn_engine_v1(
    P2wlanPreparedVpnEngineV1 *prepared);
int32_t p2wlan_harmony_stop_vpn_engine_v1(
    const uint8_t *instance_id, size_t instance_id_len, uint64_t generation);
int32_t p2wlan_harmony_stop_vpn_engine_bounded_v1(
    const uint8_t *instance_id, size_t instance_id_len, uint64_t generation,
    uint32_t timeout_ms);
int32_t p2wlan_harmony_get_vpn_engine_status_v1(
    const uint8_t *instance_id, size_t instance_id_len, uint64_t generation,
    int32_t *output);

#ifdef __cplusplus
}
#endif

#endif  // P2WLAN_HARMONY_FFI_H
