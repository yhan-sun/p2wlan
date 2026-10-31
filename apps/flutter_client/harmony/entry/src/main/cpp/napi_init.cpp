#include "napi/native_api.h"
#include "node_api.h"
#include "p2wlan_harmony_ffi.h"

#include <cmath>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace {

enum class AsyncKind { Start, Stop, NetworkPreflight };

struct StartRequestStorage {
  P2wlanVpnStartRequestV1 abi{};
  std::string instance_id;
  std::string identity_store_path;
  std::vector<std::string> configured_routes;
  std::string control_server;
  std::string auth_token;
  std::string network_id;
  std::string virtual_ip;
  std::string device_name;
  std::string overlay_cidr;
  std::string tun_interface;
  std::string udp_bind;
  std::string udp_advertise;
  std::string socket_pool;
  bool has_udp_advertise = false;
  std::vector<std::string> relay_servers;
  std::vector<P2wlanStringViewV1> route_views;
  std::vector<P2wlanStringViewV1> relay_views;

  static P2wlanStringViewV1 View(const std::string &value) {
    return {reinterpret_cast<const uint8_t *>(value.data()), value.size()};
  }

  void SetViews() {
    route_views.clear();
    relay_views.clear();
    route_views.reserve(configured_routes.size());
    relay_views.reserve(relay_servers.size());
    for (const auto &route : configured_routes) {
      route_views.push_back(View(route));
    }
    for (const auto &server : relay_servers) {
      relay_views.push_back(View(server));
    }
    abi.identity.instance_id = View(instance_id);
    abi.identity_store_path = View(identity_store_path);
    abi.configured_routes = {route_views.data(), route_views.size()};
    abi.settings_snapshot.settings.control_server = View(control_server);
    abi.settings_snapshot.settings.auth_token = View(auth_token);
    abi.settings_snapshot.settings.network_id = View(network_id);
    abi.settings_snapshot.settings.virtual_ip = View(virtual_ip);
    abi.settings_snapshot.settings.device_name = View(device_name);
    abi.settings_snapshot.settings.overlay_cidr = View(overlay_cidr);
    abi.settings_snapshot.settings.tun_interface = View(tun_interface);
    abi.settings_snapshot.settings.udp_bind = View(udp_bind);
    abi.settings_snapshot.settings.udp_advertise =
        has_udp_advertise ? View(udp_advertise) : P2wlanStringViewV1{nullptr, 0};
    abi.settings_snapshot.settings.socket_pool = View(socket_pool);
    abi.settings_snapshot.settings.relay_servers =
        {relay_views.data(), relay_views.size()};
  }
};

struct NetworkRequestStorage {
  P2wlanVpnNetworkRequestV1 abi{};
  StartRequestStorage settings;
  std::string identity_store_path;

  void SetViews() {
    settings.SetViews();
    abi.identity_store_path = StartRequestStorage::View(identity_store_path);
    abi.settings_snapshot = settings.abi.settings_snapshot;
  }
};

struct AsyncWork {
  napi_async_work work = nullptr;
  napi_deferred deferred = nullptr;
  AsyncKind kind = AsyncKind::Start;
  P2wlanPreparedVpnEngineV1 *prepared = nullptr;
  std::string instance_id;
  uint64_t generation = 0;
  NetworkRequestStorage network_request;
  std::string virtual_ip_output = std::string(64, '\0');
  std::string cidr_output = std::string(64, '\0');
  int32_t result_code = P2WLAN_HARMONY_STATUS_DAEMON_START_FAILED;
};

const char *StartErrorCode(int32_t code);

napi_value ThrowNativeError(napi_env env, const char *code, const char *message) {
  napi_throw_error(env, code, message);
  return nullptr;
}

napi_value SetString(napi_env env, napi_value object, const char *name,
                     const char *value) {
  napi_value string_value = nullptr;
  if (napi_create_string_utf8(env, value, NAPI_AUTO_LENGTH, &string_value) !=
          napi_ok ||
      napi_set_named_property(env, object, name, string_value) != napi_ok) {
    return nullptr;
  }
  return object;
}

napi_value CreateFailureResult(napi_env env, const char *code) {
  napi_value result = nullptr;
  napi_value error = nullptr;
  napi_value ok = nullptr;
  napi_value code_value = nullptr;
  if (napi_create_object(env, &result) != napi_ok ||
      napi_create_object(env, &error) != napi_ok ||
      napi_get_boolean(env, false, &ok) != napi_ok ||
      napi_create_string_utf8(env, code, NAPI_AUTO_LENGTH, &code_value) !=
          napi_ok ||
      napi_set_named_property(env, error, "code", code_value) != napi_ok ||
      napi_set_named_property(env, result, "ok", ok) != napi_ok ||
      napi_set_named_property(env, result, "error", error) != napi_ok) {
    return nullptr;
  }
  return result;
}

napi_value CreateStartResult(napi_env env, int32_t code) {
  napi_value result = nullptr;
  if (napi_create_object(env, &result) != napi_ok) {
    return nullptr;
  }
  if (code == P2WLAN_HARMONY_STATUS_OK) {
    napi_value status = nullptr;
    if (napi_create_string_utf8(env, "ready", NAPI_AUTO_LENGTH, &status) !=
            napi_ok ||
        napi_set_named_property(env, result, "status", status) != napi_ok) {
      return nullptr;
    }
    return result;
  }

  napi_value status = nullptr;
  napi_value code_value = nullptr;
  if (napi_create_string_utf8(env, "failed", NAPI_AUTO_LENGTH, &status) !=
          napi_ok ||
      napi_create_string_utf8(env, StartErrorCode(code), NAPI_AUTO_LENGTH,
                              &code_value) != napi_ok ||
      napi_set_named_property(env, result, "status", status) != napi_ok ||
      napi_set_named_property(env, result, "code", code_value) != napi_ok) {
    return nullptr;
  }
  return result;
}

bool ResolveStartResult(napi_env env, napi_deferred deferred, int32_t code) {
  napi_value result = CreateStartResult(env, code);
  return result != nullptr && napi_resolve_deferred(env, deferred, result) == napi_ok;
}

const char *StartErrorCode(int32_t code) {
  switch (code) {
    case P2WLAN_HARMONY_STATUS_BAD_ARGUMENT:
    case P2WLAN_HARMONY_STATUS_INVALID_REQUEST:
      return "invalid_request";
    case P2WLAN_HARMONY_STATUS_TUN_FD_DUP_FAILED:
      return "vpn_fd_dup_failed";
    case P2WLAN_HARMONY_STATUS_TUN_FD_NOT_NONBLOCKING:
      return "vpn_fd_not_nonblocking";
    case P2WLAN_HARMONY_STATUS_TUN_FD_INVALID_MODE:
      return "vpn_fd_invalid_mode";
    case P2WLAN_HARMONY_STATUS_ALREADY_RUNNING:
      return "already_running";
    case P2WLAN_HARMONY_STATUS_ENGINE_BUSY:
      return "engine_busy";
    case P2WLAN_HARMONY_STATUS_STALE_GENERATION:
      return "stale_generation";
    case P2WLAN_HARMONY_STATUS_STALE_SETTINGS_SNAPSHOT:
      return "stale_settings_snapshot";
    case P2WLAN_HARMONY_STATUS_START_TIMEOUT:
      return "start_timeout";
    case P2WLAN_HARMONY_STATUS_START_CANCELLED:
      return "start_cancelled";
    case P2WLAN_HARMONY_STATUS_IDENTITY_STORE_FAILED:
      return "identity_store_failed";
    case P2WLAN_HARMONY_STATUS_ROUTE_PROOF_INVALID:
      return "route_proof_invalid";
    case P2WLAN_HARMONY_STATUS_CONFIG_INVALID:
      return "config_invalid";
    case P2WLAN_HARMONY_STATUS_AUTH_FAILED:
      return "auth_failed";
    case P2WLAN_HARMONY_STATUS_DAEMON_START_FAILED:
      return "daemon_start_failed";
    case P2WLAN_HARMONY_STATUS_UNKNOWN_IDENTITY:
      return "unknown_identity";
    case P2WLAN_HARMONY_STATUS_ENGINE_HISTORY_FULL:
      return "engine_history_full";
    case P2WLAN_HARMONY_STATUS_NETWORK_PREFLIGHT_FAILED:
      return "vpn_network_preflight_failed";
    case P2WLAN_HARMONY_STATUS_DRAINING:
      return "native_stop_failed";
    default:
      if (code >= P2WLAN_HARMONY_ENGINE_FAILED_BASE) {
        return StartErrorCode(code - P2WLAN_HARMONY_ENGINE_FAILED_BASE);
      }
      return "native_start_failed";
  }
}

napi_value CreateNetworkPreflightResult(napi_env env, int32_t code,
                                        const std::string &virtual_ip,
                                        const std::string &cidr) {
  napi_value result = nullptr;
  if (napi_create_object(env, &result) != napi_ok) {
    return nullptr;
  }
  if (code == P2WLAN_HARMONY_STATUS_OK) {
    if (SetString(env, result, "status", "ready") == nullptr ||
        SetString(env, result, "virtualIp", virtual_ip.c_str()) == nullptr ||
        SetString(env, result, "cidr", cidr.c_str()) == nullptr) {
      return nullptr;
    }
    return result;
  }
  if (SetString(env, result, "status", "failed") == nullptr ||
      SetString(env, result, "code", StartErrorCode(code)) == nullptr) {
    return nullptr;
  }
  return result;
}

napi_value CreateStopResult(napi_env env, int32_t code) {
  napi_value result = nullptr;
  napi_value status = nullptr;
  if (napi_create_object(env, &result) != napi_ok) {
    return nullptr;
  }
  if (code == P2WLAN_HARMONY_STATUS_STOPPED) {
    if (napi_create_string_utf8(env, "stopped", NAPI_AUTO_LENGTH, &status) !=
            napi_ok ||
        napi_set_named_property(env, result, "status", status) != napi_ok) {
      return nullptr;
    }
  } else {
    napi_value error_code = nullptr;
    const char *stop_code =
        code == P2WLAN_HARMONY_STATUS_DRAINING ? "stop_timeout"
                                               : "native_stop_failed";
    if (napi_create_string_utf8(env, "draining", NAPI_AUTO_LENGTH, &status) !=
            napi_ok ||
        napi_create_string_utf8(env, stop_code, NAPI_AUTO_LENGTH,
                                &error_code) != napi_ok ||
        napi_set_named_property(env, result, "status", status) != napi_ok ||
        napi_set_named_property(env, result, "code", error_code) != napi_ok) {
      return nullptr;
    }
  }
  return result;
}

const char *EngineStatusName(int32_t code) {
  switch (code) {
    case P2WLAN_HARMONY_ENGINE_STARTING:
      return "starting";
    case P2WLAN_HARMONY_ENGINE_READY:
      return "ready";
    case P2WLAN_HARMONY_ENGINE_STOPPING:
      return "stopping";
    case P2WLAN_HARMONY_ENGINE_STOPPED:
      return "stopped";
    default:
      return "failed";
  }
}

napi_value CreateStatusResult(napi_env env, int32_t code) {
  napi_value result = nullptr;
  napi_value status = nullptr;
  if (napi_create_object(env, &result) != napi_ok ||
      napi_create_string_utf8(env, EngineStatusName(code), NAPI_AUTO_LENGTH,
                              &status) != napi_ok ||
      napi_set_named_property(env, result, "status", status) != napi_ok) {
    return nullptr;
  }
  if (code >= P2WLAN_HARMONY_ENGINE_FAILED_BASE) {
    napi_value error_code = nullptr;
    if (napi_create_string_utf8(env, StartErrorCode(code -
                                                        P2WLAN_HARMONY_ENGINE_FAILED_BASE),
                                NAPI_AUTO_LENGTH, &error_code) != napi_ok ||
        napi_set_named_property(env, result, "code", error_code) != napi_ok) {
      return nullptr;
    }
  }
  return result;
}

bool GetNamed(napi_env env, napi_value object, const char *name,
              napi_value *value) {
  return napi_get_named_property(env, object, name, value) == napi_ok;
}

bool ReadString(napi_env env, napi_value value, std::string *output) {
  napi_valuetype type;
  if (napi_typeof(env, value, &type) != napi_ok || type != napi_string) {
    return false;
  }
  size_t length = 0;
  if (napi_get_value_string_utf8(env, value, nullptr, 0, &length) != napi_ok ||
      length > 64 * 1024) {
    return false;
  }
  output->resize(length + 1);
  size_t copied = 0;
  if (napi_get_value_string_utf8(env, value, output->data(), output->size(),
                                 &copied) != napi_ok ||
      copied != length) {
    return false;
  }
  output->resize(length);
  return true;
}

bool ReadStringProperty(napi_env env, napi_value object, const char *name,
                        std::string *output) {
  napi_value value = nullptr;
  return GetNamed(env, object, name, &value) && ReadString(env, value, output);
}

bool ReadSafeUint(napi_env env, napi_value value, uint64_t maximum,
                  uint64_t *output) {
  double number = 0;
  if (napi_get_value_double(env, value, &number) != napi_ok ||
      !std::isfinite(number) || number < 0 || std::floor(number) != number ||
      number > static_cast<double>(maximum)) {
    return false;
  }
  *output = static_cast<uint64_t>(number);
  return true;
}

bool ReadUintProperty(napi_env env, napi_value object, const char *name,
                      uint64_t maximum, uint64_t *output) {
  napi_value value = nullptr;
  return GetNamed(env, object, name, &value) &&
         ReadSafeUint(env, value, maximum, output);
}

bool ReadStringArray(napi_env env, napi_value value,
                     std::vector<std::string> *output, uint32_t maximum) {
  bool is_array = false;
  uint32_t length = 0;
  if (napi_is_array(env, value, &is_array) != napi_ok || !is_array ||
      napi_get_array_length(env, value, &length) != napi_ok ||
      length > maximum) {
    return false;
  }
  output->clear();
  output->reserve(length);
  for (uint32_t index = 0; index < length; ++index) {
    napi_value item = nullptr;
    std::string text;
    if (napi_get_element(env, value, index, &item) != napi_ok ||
        !ReadString(env, item, &text)) {
      return false;
    }
    output->push_back(std::move(text));
  }
  return true;
}

bool HasExactProperties(napi_env env, napi_value object,
                        const char *const *expected, size_t expected_count) {
  napi_value names = nullptr;
  uint32_t count = 0;
  if (napi_get_property_names(env, object, &names) != napi_ok ||
      napi_get_array_length(env, names, &count) != napi_ok ||
      count != expected_count) {
    return false;
  }
  for (uint32_t index = 0; index < count; ++index) {
    napi_value name_value = nullptr;
    std::string name;
    if (napi_get_element(env, names, index, &name_value) != napi_ok ||
        !ReadString(env, name_value, &name)) {
      return false;
    }
    bool found = false;
    for (size_t candidate = 0; candidate < expected_count; ++candidate) {
      if (name == expected[candidate]) {
        found = true;
        break;
      }
    }
    if (!found) {
      return false;
    }
  }
  return true;
}

bool GetIdentity(napi_env env, napi_value value, std::string *instance_id,
                 uint64_t *generation) {
  static const char *const identity_fields[] = {"instanceId", "generation"};
  napi_value instance_value = nullptr;
  napi_value generation_value = nullptr;
  if (!HasExactProperties(env, value, identity_fields,
                          sizeof(identity_fields) / sizeof(identity_fields[0])) ||
      !GetNamed(env, value, "instanceId", &instance_value) ||
      !GetNamed(env, value, "generation", &generation_value)) {
    return false;
  }
  size_t length = 0;
  if (napi_get_value_string_utf8(env, instance_value, nullptr, 0, &length) !=
          napi_ok ||
      length == 0 || length > 128) {
    return false;
  }
  instance_id->resize(length + 1);
  size_t copied = 0;
  if (napi_get_value_string_utf8(env, instance_value, instance_id->data(),
                                 instance_id->size(), &copied) != napi_ok ||
      copied != length) {
    return false;
  }
  instance_id->resize(length);

  double numeric_generation = 0;
  if (napi_get_value_double(env, generation_value, &numeric_generation) !=
          napi_ok ||
      !std::isfinite(numeric_generation) || numeric_generation <= 0 ||
      std::floor(numeric_generation) != numeric_generation ||
      numeric_generation > 9007199254740991.0) {
    return false;
  }
  *generation = static_cast<uint64_t>(numeric_generation);
  return true;
}

bool ReadOptionalStringProperty(napi_env env, napi_value object,
                                const char *name, std::string *output,
                                bool *present) {
  napi_value value = nullptr;
  napi_valuetype type;
  if (!GetNamed(env, object, name, &value) ||
      napi_typeof(env, value, &type) != napi_ok) {
    return false;
  }
  if (type == napi_null) {
    *present = false;
    output->clear();
    return true;
  }
  *present = true;
  return ReadString(env, value, output);
}

bool ReadSettingsSnapshot(napi_env env, napi_value snapshot,
                          StartRequestStorage *storage) {
  static const char *const snapshot_fields[] = {
      "schemaVersion", "revision", "settings"};
  static const char *const settings_fields[] = {
      "controlServer", "authToken", "networkId", "manualMode", "virtualIp",
      "deviceName", "overlayCidr", "tunInterface", "mtu", "udpBind",
      "udpAdvertise", "socketPool", "relayServers"};
  napi_value settings = nullptr;
  napi_value field = nullptr;
  uint64_t snapshot_version = 0;
  uint64_t revision = 0;
  uint64_t mtu = 0;
  bool manual_mode = false;
  if (!HasExactProperties(env, snapshot, snapshot_fields,
                          sizeof(snapshot_fields) / sizeof(snapshot_fields[0])) ||
      !ReadUintProperty(env, snapshot, "schemaVersion", UINT32_MAX,
                        &snapshot_version) ||
      snapshot_version != 1 ||
      !ReadUintProperty(env, snapshot, "revision", 9007199254740991ULL,
                        &revision) ||
      !GetNamed(env, snapshot, "settings", &settings) ||
      !HasExactProperties(env, settings, settings_fields,
                          sizeof(settings_fields) / sizeof(settings_fields[0]))) {
    return false;
  }

  if (!ReadStringProperty(env, settings, "controlServer",
                          &storage->control_server) ||
      !ReadStringProperty(env, settings, "authToken", &storage->auth_token) ||
      !ReadStringProperty(env, settings, "networkId", &storage->network_id) ||
      !GetNamed(env, settings, "manualMode", &field) ||
      napi_get_value_bool(env, field, &manual_mode) != napi_ok ||
      !ReadStringProperty(env, settings, "virtualIp", &storage->virtual_ip) ||
      !ReadStringProperty(env, settings, "deviceName", &storage->device_name) ||
      !ReadStringProperty(env, settings, "overlayCidr", &storage->overlay_cidr) ||
      !ReadStringProperty(env, settings, "tunInterface", &storage->tun_interface) ||
      !ReadUintProperty(env, settings, "mtu", UINT32_MAX, &mtu) ||
      !ReadStringProperty(env, settings, "udpBind", &storage->udp_bind) ||
      !ReadOptionalStringProperty(env, settings, "udpAdvertise",
                                  &storage->udp_advertise,
                                  &storage->has_udp_advertise) ||
      !ReadStringProperty(env, settings, "socketPool", &storage->socket_pool) ||
      !GetNamed(env, settings, "relayServers", &field) ||
      !ReadStringArray(env, field, &storage->relay_servers, 64)) {
    return false;
  }
  storage->abi.settings_snapshot.schema_version =
      static_cast<uint32_t>(snapshot_version);
  storage->abi.settings_snapshot.revision = revision;
  storage->abi.settings_snapshot.settings.manual_mode = manual_mode ? 1 : 0;
  storage->abi.settings_snapshot.settings.mtu = static_cast<uint32_t>(mtu);
  storage->SetViews();
  return true;
}

bool ReadNetworkRequest(napi_env env, napi_value value,
                        NetworkRequestStorage *storage) {
  static const char *const request_fields[] = {
      "identityStorePath", "settingsSnapshot"};
  napi_value snapshot = nullptr;
  if (!HasExactProperties(env, value, request_fields,
                          sizeof(request_fields) / sizeof(request_fields[0])) ||
      !ReadStringProperty(env, value, "identityStorePath",
                          &storage->identity_store_path) ||
      !GetNamed(env, value, "settingsSnapshot", &snapshot) ||
      !ReadSettingsSnapshot(env, snapshot, &storage->settings)) {
    return false;
  }
  storage->SetViews();
  return true;
}

bool ReadStartRequest(napi_env env, napi_value value,
                      StartRequestStorage *storage) {
  static const char *const request_fields[] = {
      "version", "identity", "fd", "configuredRoutes", "processProtected",
      "identityStorePath", "settingsSnapshot"};
  napi_value identity = nullptr;
  napi_value routes = nullptr;
  napi_value snapshot = nullptr;
  napi_value field = nullptr;
  uint64_t version = 0;
  uint64_t generation = 0;
  uint64_t fd = 0;
  bool process_protected = false;
  if (!HasExactProperties(env, value, request_fields,
                          sizeof(request_fields) / sizeof(request_fields[0])) ||
      !ReadUintProperty(env, value, "version", UINT32_MAX, &version) ||
      version != 1 || !GetNamed(env, value, "identity", &identity) ||
      !GetIdentity(env, identity, &storage->instance_id, &generation) ||
      !ReadUintProperty(env, value, "fd", INT32_MAX, &fd) ||
      !GetNamed(env, value, "configuredRoutes", &routes) ||
      !ReadStringArray(env, routes, &storage->configured_routes, 256) ||
      !GetNamed(env, value, "processProtected", &field) ||
      napi_get_value_bool(env, field, &process_protected) != napi_ok ||
      !ReadStringProperty(env, value, "identityStorePath",
                          &storage->identity_store_path) ||
      !GetNamed(env, value, "settingsSnapshot", &snapshot) ||
      !ReadSettingsSnapshot(env, snapshot, storage)) {
    return false;
  }
  storage->abi.version = static_cast<uint32_t>(version);
  storage->abi.identity.generation = generation;
  storage->abi.fd = static_cast<int32_t>(fd);
  storage->abi.process_protected = process_protected ? 1 : 0;
  storage->SetViews();
  return true;
}

void StartExecute(napi_env, void *data) {
  auto *work = static_cast<AsyncWork *>(data);
  work->result_code = p2wlan_harmony_activate_vpn_engine_v1(work->prepared);
  work->prepared = nullptr;  // The Rust FFI consumed the opaque handle.
}

void StopExecute(napi_env, void *data) {
  auto *work = static_cast<AsyncWork *>(data);
  work->result_code = p2wlan_harmony_stop_vpn_engine_v1(
      reinterpret_cast<const uint8_t *>(work->instance_id.data()),
      work->instance_id.size(), work->generation);
}

void NetworkPreflightExecute(napi_env, void *data) {
  auto *work = static_cast<AsyncWork *>(data);
  work->result_code = p2wlan_harmony_prepare_vpn_network_v1(
      &work->network_request.abi,
      reinterpret_cast<uint8_t *>(work->virtual_ip_output.data()),
      work->virtual_ip_output.size(),
      reinterpret_cast<uint8_t *>(work->cidr_output.data()),
      work->cidr_output.size());
}

void CompleteStart(napi_env env, napi_status status, void *data) {
  std::unique_ptr<AsyncWork> work(static_cast<AsyncWork *>(data));
  bool aborted_before_activation = false;
  if (work->prepared != nullptr) {
    p2wlan_harmony_abort_vpn_engine_v1(work->prepared);
    work->prepared = nullptr;
    aborted_before_activation = true;
  }
  if (status != napi_ok) {
    work->result_code = aborted_before_activation
                            ? P2WLAN_HARMONY_STATUS_DAEMON_START_FAILED
                            : P2WLAN_HARMONY_STATUS_START_CANCELLED;
  }
  napi_value result = CreateStartResult(env, work->result_code);
  if (result != nullptr) {
    napi_resolve_deferred(env, work->deferred, result);
  } else {
    napi_value error = nullptr;
    napi_create_error(env, nullptr, nullptr, &error);
    napi_reject_deferred(env, work->deferred, error);
  }
  napi_delete_async_work(env, work->work);
}

void CompleteStop(napi_env env, napi_status status, void *data) {
  std::unique_ptr<AsyncWork> work(static_cast<AsyncWork *>(data));
  if (status != napi_ok) {
    work->result_code = P2WLAN_HARMONY_STATUS_UNKNOWN_IDENTITY;
  }
  if (work->result_code == P2WLAN_HARMONY_STATUS_STOPPED) {
    napi_value result = CreateStopResult(env, work->result_code);
    if (result != nullptr) {
      napi_resolve_deferred(env, work->deferred, result);
    }
  } else {
    napi_value message = nullptr;
    napi_value code = nullptr;
    napi_value error = nullptr;
    napi_create_string_utf8(env, "Native VPN engine did not stop.",
                            NAPI_AUTO_LENGTH, &message);
    napi_create_string_utf8(env, "native_stop_failed", NAPI_AUTO_LENGTH, &code);
    napi_create_error(env, code, message, &error);
    napi_reject_deferred(env, work->deferred, error);
  }
  napi_delete_async_work(env, work->work);
}

void CompleteNetworkPreflight(napi_env env, napi_status status, void *data) {
  std::unique_ptr<AsyncWork> work(static_cast<AsyncWork *>(data));
  if (status != napi_ok) {
    work->result_code = P2WLAN_HARMONY_STATUS_NETWORK_PREFLIGHT_FAILED;
  }
  napi_value result = CreateNetworkPreflightResult(
      env, work->result_code, work->virtual_ip_output, work->cidr_output);
  if (result != nullptr) {
    napi_resolve_deferred(env, work->deferred, result);
  } else {
    napi_value error = nullptr;
    napi_create_error(env, nullptr, nullptr, &error);
    napi_reject_deferred(env, work->deferred, error);
  }
  napi_delete_async_work(env, work->work);
}

napi_value QueueStart(napi_env env, napi_value request, napi_deferred *deferred,
                      napi_value *promise) {
  if (napi_create_promise(env, deferred, promise) != napi_ok) {
    return nullptr;
  }

  StartRequestStorage request_storage;
  if (!ReadStartRequest(env, request, &request_storage)) {
    return ResolveStartResult(env, *deferred, P2WLAN_HARMONY_STATUS_INVALID_REQUEST)
               ? *promise
               : nullptr;
  }

  P2wlanPreparedVpnEngineV1 *prepared = nullptr;
  const int32_t prepare_code = p2wlan_harmony_prepare_vpn_engine_v1(
      &request_storage.abi, &prepared);
  if (prepare_code != P2WLAN_HARMONY_STATUS_OK) {
    return ResolveStartResult(env, *deferred, prepare_code) ? *promise : nullptr;
  }

  auto work = std::make_unique<AsyncWork>();
  work->prepared = prepared;
  work->deferred = *deferred;
  work->kind = AsyncKind::Start;
  napi_value resource_name = nullptr;
  if (napi_create_string_utf8(env, "p2wlan:startVpnEngineV1", NAPI_AUTO_LENGTH,
                              &resource_name) != napi_ok ||
      napi_create_async_work(env, nullptr, resource_name, StartExecute,
                             CompleteStart, work.get(), &work->work) != napi_ok) {
    p2wlan_harmony_abort_vpn_engine_v1(prepared);
    work->prepared = nullptr;
    return ResolveStartResult(env, *deferred,
                              P2WLAN_HARMONY_STATUS_DAEMON_START_FAILED)
               ? *promise
               : nullptr;
  }
  AsyncWork *queued = work.release();
  if (napi_queue_async_work(env, queued->work) != napi_ok) {
    p2wlan_harmony_abort_vpn_engine_v1(queued->prepared);
    queued->prepared = nullptr;
    napi_delete_async_work(env, queued->work);
    delete queued;
    return ResolveStartResult(env, *deferred,
                              P2WLAN_HARMONY_STATUS_DAEMON_START_FAILED)
               ? *promise
               : nullptr;
  }
  return *promise;
}

napi_value StartVpnEngine(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1] = {nullptr};
  if (napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr) != napi_ok ||
      argc != 1) {
    return ThrowNativeError(env, "invalid_request", "A versioned VPN start request is required.");
  }
  napi_deferred deferred = nullptr;
  napi_value promise = nullptr;
  napi_value queued = QueueStart(env, argv[0], &deferred, &promise);
  if (queued == nullptr) {
    return ThrowNativeError(env, "invalid_request", "The VPN start request is invalid.");
  }
  return queued;
}

napi_value PrepareVpnNetwork(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1] = {nullptr};
  if (napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr) != napi_ok ||
      argc != 1) {
    return ThrowNativeError(env, "invalid_request",
                            "A versioned VPN network request is required.");
  }
  napi_deferred deferred = nullptr;
  napi_value promise = nullptr;
  if (napi_create_promise(env, &deferred, &promise) != napi_ok) {
    return nullptr;
  }
  auto work = std::make_unique<AsyncWork>();
  if (!ReadNetworkRequest(env, argv[0], &work->network_request)) {
    napi_value result = CreateNetworkPreflightResult(
        env, P2WLAN_HARMONY_STATUS_INVALID_REQUEST, "", "");
    if (result == nullptr || napi_resolve_deferred(env, deferred, result) != napi_ok) {
      return nullptr;
    }
    return promise;
  }
  work->deferred = deferred;
  work->kind = AsyncKind::NetworkPreflight;
  napi_value resource_name = nullptr;
  if (napi_create_string_utf8(env, "p2wlan:prepareVpnNetworkV1",
                              NAPI_AUTO_LENGTH, &resource_name) != napi_ok ||
      napi_create_async_work(env, nullptr, resource_name, NetworkPreflightExecute,
                             CompleteNetworkPreflight, work.get(),
                             &work->work) != napi_ok) {
    return ThrowNativeError(env, "native_preflight_failed",
                            "Unable to queue VPN network preparation.");
  }
  AsyncWork *queued = work.release();
  if (napi_queue_async_work(env, queued->work) != napi_ok) {
    napi_delete_async_work(env, queued->work);
    delete queued;
    return ThrowNativeError(env, "native_preflight_failed",
                            "Unable to queue VPN network preparation.");
  }
  return promise;
}

napi_value DiscardVpnNetwork(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1] = {nullptr};
  if (napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr) != napi_ok ||
      argc != 1) {
    return ThrowNativeError(env, "invalid_request",
                            "An identity store path is required.");
  }
  std::string path;
  if (!ReadString(env, argv[0], &path)) {
    return ThrowNativeError(env, "invalid_request",
                            "The identity store path is invalid.");
  }
  const int32_t code = p2wlan_harmony_discard_vpn_network_v1(
      reinterpret_cast<const uint8_t *>(path.data()), path.size());
  napi_value result = nullptr;
  if (napi_get_boolean(env, code == P2WLAN_HARMONY_STATUS_OK, &result) != napi_ok) {
    return nullptr;
  }
  return result;
}

napi_value QueueStop(napi_env env, napi_value identity) {
  auto work = std::make_unique<AsyncWork>();
  if (!GetIdentity(env, identity, &work->instance_id, &work->generation)) {
    return ThrowNativeError(env, "invalid_identity", "A valid VPN identity is required.");
  }
  work->kind = AsyncKind::Stop;
  napi_deferred deferred = nullptr;
  napi_value promise = nullptr;
  if (napi_create_promise(env, &deferred, &promise) != napi_ok) {
    return nullptr;
  }
  work->deferred = deferred;
  napi_value resource_name = nullptr;
  if (napi_create_string_utf8(env, "p2wlan:stopVpnEngineV1", NAPI_AUTO_LENGTH,
                              &resource_name) != napi_ok ||
      napi_create_async_work(env, nullptr, resource_name, StopExecute,
                             CompleteStop, work.get(), &work->work) != napi_ok) {
    return nullptr;
  }
  AsyncWork *queued = work.release();
  if (napi_queue_async_work(env, queued->work) != napi_ok) {
    napi_delete_async_work(env, queued->work);
    delete queued;
    return nullptr;
  }
  return promise;
}

napi_value StopVpnEngine(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1] = {nullptr};
  if (napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr) != napi_ok ||
      argc != 1) {
    return ThrowNativeError(env, "invalid_identity", "A VPN identity is required.");
  }
  return QueueStop(env, argv[0]);
}

napi_value StopVpnEngineForExtensionDestroy(napi_env env,
                                             napi_callback_info info) {
  size_t argc = 2;
  napi_value argv[2] = {nullptr, nullptr};
  if (napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr) != napi_ok ||
      argc != 2) {
    return ThrowNativeError(env, "invalid_identity", "A VPN identity and stop timeout are required.");
  }
  std::string instance_id;
  uint64_t generation = 0;
  uint32_t timeout_ms = 0;
  if (!GetIdentity(env, argv[0], &instance_id, &generation) ||
      napi_get_value_uint32(env, argv[1], &timeout_ms) != napi_ok ||
      timeout_ms > 30000) {
    return ThrowNativeError(env, "invalid_identity", "The VPN identity or timeout is invalid.");
  }
  const int32_t code = p2wlan_harmony_stop_vpn_engine_bounded_v1(
      reinterpret_cast<const uint8_t *>(instance_id.data()), instance_id.size(),
      generation, timeout_ms);
  napi_value result = CreateStopResult(env, code);
  return result;
}

napi_value GetVpnEngineStatus(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1] = {nullptr};
  if (napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr) != napi_ok ||
      argc != 1) {
    return ThrowNativeError(env, "invalid_identity", "A VPN identity is required.");
  }
  std::string instance_id;
  uint64_t generation = 0;
  if (!GetIdentity(env, argv[0], &instance_id, &generation)) {
    return ThrowNativeError(env, "invalid_identity", "A valid VPN identity is required.");
  }
  int32_t status = P2WLAN_HARMONY_ENGINE_STOPPED;
  const int32_t result_code = p2wlan_harmony_get_vpn_engine_status_v1(
      reinterpret_cast<const uint8_t *>(instance_id.data()), instance_id.size(),
      generation, &status);
  if (result_code != P2WLAN_HARMONY_STATUS_OK) {
    return CreateStatusResult(
        env, P2WLAN_HARMONY_ENGINE_FAILED_BASE + result_code);
  }
  return CreateStatusResult(env, status);
}

napi_value GetBuildInfo(napi_env env, napi_callback_info) {
  P2wlanBuildInfoV1 info{};
  if (p2wlan_harmony_get_build_info_v1(&info) != P2WLAN_HARMONY_STATUS_OK) {
    return CreateFailureResult(env, "NATIVE_QUERY_FAILED");
  }
  if (info.abi_version != P2WLAN_HARMONY_ABI_VERSION ||
      info.struct_size != sizeof(P2wlanBuildInfoV1) ||
      info.engine_version == nullptr || info.target == nullptr ||
      info.arch == nullptr) {
    return CreateFailureResult(env, "NATIVE_ABI_MISMATCH");
  }

  napi_value result = nullptr;
  napi_value data = nullptr;
  napi_value abi_version = nullptr;
  napi_value ok = nullptr;
  if (napi_create_object(env, &result) != napi_ok ||
      napi_create_object(env, &data) != napi_ok ||
      napi_get_boolean(env, true, &ok) != napi_ok ||
      napi_create_uint32(env, info.abi_version, &abi_version) != napi_ok ||
      napi_set_named_property(env, data, "abiVersion", abi_version) != napi_ok) {
    return nullptr;
  }
  if (SetString(env, data, "engineVersion", info.engine_version) == nullptr ||
      SetString(env, data, "target", info.target) == nullptr ||
      SetString(env, data, "arch", info.arch) == nullptr ||
      napi_set_named_property(env, result, "ok", ok) != napi_ok ||
      napi_set_named_property(env, result, "data", data) != napi_ok) {
    return nullptr;
  }
  return result;
}

napi_value Initialize(napi_env env, napi_value exports) {
  napi_property_descriptor methods[] = {
      {"getBuildInfo", nullptr, GetBuildInfo, nullptr, nullptr, nullptr,
       napi_default, nullptr},
      {"startVpnEngineV1", nullptr, StartVpnEngine, nullptr, nullptr, nullptr,
       napi_default, nullptr},
      {"prepareVpnNetworkV1", nullptr, PrepareVpnNetwork, nullptr, nullptr,
       nullptr, napi_default, nullptr},
      {"discardVpnNetworkV1", nullptr, DiscardVpnNetwork, nullptr, nullptr,
       nullptr, napi_default, nullptr},
      {"stopVpnEngineV1", nullptr, StopVpnEngine, nullptr, nullptr, nullptr,
       napi_default, nullptr},
      {"stopVpnEngineForExtensionDestroyV1", nullptr,
       StopVpnEngineForExtensionDestroy, nullptr, nullptr, nullptr, napi_default,
       nullptr},
      {"getVpnEngineStatusV1", nullptr, GetVpnEngineStatus, nullptr, nullptr,
       nullptr, napi_default, nullptr},
  };
  if (napi_define_properties(env, exports,
                             sizeof(methods) / sizeof(methods[0]), methods) !=
      napi_ok) {
    return ThrowNativeError(env, "P2WLAN_NAPI_FAILED",
                            "Unable to register the Harmony native APIs.");
  }
  return exports;
}

napi_module g_native_module = {
    NAPI_MODULE_VERSION,
    0,
    nullptr,
    Initialize,
    "p2wlan_harmony_native",
    nullptr,
    {nullptr, nullptr, nullptr, nullptr},
};

}  // namespace

extern "C" __attribute__((constructor)) void RegisterP2wlanHarmonyNativeModule() {
  napi_module_register(&g_native_module);
}
