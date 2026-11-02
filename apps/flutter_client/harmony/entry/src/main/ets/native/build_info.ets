export interface NativeBuildInfo {
  abiVersion: number;
  engineVersion: string;
  target: string;
  arch: string;
}

export type NativeBuildInfoErrorCode =
  | 'NATIVE_LIBRARY_LOAD_FAILED'
  | 'NATIVE_ABI_MISMATCH'
  | 'NATIVE_QUERY_FAILED'
  | 'NATIVE_RESULT_INVALID';

export interface NativeBuildInfoError {
  code: NativeBuildInfoErrorCode;
}

export interface NativeBuildInfoSuccess {
  ok: true;
  data: NativeBuildInfo;
}

export interface NativeBuildInfoFailure {
  ok: false;
  error: NativeBuildInfoError;
}

export type NativeBuildInfoResult = NativeBuildInfoSuccess | NativeBuildInfoFailure;

interface NativeBuildInfoModule {
  getBuildInfo(): NativeBuildInfoResult;
}

interface NativeBuildInfoModuleNamespace {
  default: NativeBuildInfoModule;
}

function failure(code: NativeBuildInfoErrorCode): NativeBuildInfoFailure {
  const error: NativeBuildInfoError = { code: code };
  const result: NativeBuildInfoFailure = { ok: false, error: error };
  return result;
}

export async function queryNativeBuildInfo(): Promise<NativeBuildInfoResult> {
  let loaded: NativeBuildInfoModuleNamespace;
  try {
    loaded = await import('libp2wlan_harmony_native.so');
  } catch {
    return failure('NATIVE_LIBRARY_LOAD_FAILED');
  }

  const nativeModule = loaded.default;
  if (nativeModule == undefined || typeof nativeModule.getBuildInfo != 'function') {
    return failure('NATIVE_RESULT_INVALID');
  }

  let result: NativeBuildInfoResult;
  try {
    result = nativeModule.getBuildInfo();
  } catch {
    return failure('NATIVE_QUERY_FAILED');
  }

  if (result == undefined) {
    return failure('NATIVE_RESULT_INVALID');
  }
  if (result.ok == false) {
    return result;
  }

  const info = result.data;
  if (info == undefined || info.abiVersion != 1 ||
      typeof info.engineVersion != 'string' || typeof info.target != 'string' ||
      typeof info.arch != 'string') {
    return failure('NATIVE_ABI_MISMATCH');
  }
  const success: NativeBuildInfoSuccess = { ok: true, data: info };
  return success;
}
