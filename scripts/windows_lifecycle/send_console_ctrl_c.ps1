[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateRange(1, 2147483647)][int]$ProcessId,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{32}$')][string]$RequestId,
    [Parameter(Mandatory = $true)][string]$EvidencePath,
    [string]$DiagnosticDirectory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$stage = 'initialize'
$broadcastSucceeded = $false
$nativeErrorCode = $null
$detail = ''
function Initialize-CtrlCDiagnosticDirectory {
    param([Parameter(Mandatory = $true)][string]$Directory)
    try {
        $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
        if (-not (Test-Path -LiteralPath $Directory)) {
            [void][System.IO.Directory]::CreateDirectory($Directory)
            $acl = [System.Security.AccessControl.DirectorySecurity]::new()
            $acl.SetOwner($sid)
            $acl.SetAccessRuleProtection($true, $false)
            $inheritance = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
            $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
                $sid, [System.Security.AccessControl.FileSystemRights]::FullControl,
                $inheritance, [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow)
            $acl.AddAccessRule($rule)
            Set-Acl -LiteralPath $Directory -AclObject $acl
        }
        $actual = Get-Acl -LiteralPath $Directory
        $rules = @($actual.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
        if (-not $actual.AreAccessRulesProtected -or
            $actual.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -ne $sid.Value -or
            $rules.Count -ne 1 -or $rules[0].IdentityReference.Value -ne $sid.Value -or
            $rules[0].AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or
            $rules[0].FileSystemRights -ne [System.Security.AccessControl.FileSystemRights]::FullControl -or
            $rules[0].InheritanceFlags -ne [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit') {
            throw 'Ctrl+C diagnostic directory lacks the protected owner-only ACL'
        }
        return $true
    } catch {
        Write-Warning -WarningAction Continue "Ctrl+C diagnostic directory unavailable: $($_.Exception.Message)"
        return $false
    }
}

function Write-ExclusiveCtrlCDiagnostic {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Record
    )
    try {
        $encoding = [System.Text.UTF8Encoding]::new($false)
        $bytes = $encoding.GetBytes(($Record | ConvertTo-Json -Depth 5 -Compress) + "`n")
        if ($bytes.Length -gt 2048) { throw 'Ctrl+C diagnostic record exceeded 2048 bytes' }
        $stream = [System.IO.FileStream]::new(
            $Path, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::Read)
        try { $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }
    } catch {
        # Diagnostics never substitute a successful native result or mask the
        # original injector failure. Missing/partial records remain unknown.
        Write-Warning -WarningAction Continue "Ctrl+C diagnostic record unavailable: $($_.Exception.Message)"
    }
}

$exitCode = 1
$diagnosticStarted = 0
$diagnosticSequence = 0
$diagnosticReady = $false
try {
    $diagnosticStarted = [System.Diagnostics.Stopwatch]::GetTimestamp()
    $expectedDiagnosticDirectory = [System.IO.Path]::GetFullPath($EvidencePath + '.diagnostic')
    if (-not $DiagnosticDirectory) {
        $DiagnosticDirectory = $expectedDiagnosticDirectory
        if (Test-Path -LiteralPath $DiagnosticDirectory) {
            Write-Warning -WarningAction Continue 'Ctrl+C default diagnostic directory already exists; diagnostics disabled'
        } else {
            $diagnosticReady = Initialize-CtrlCDiagnosticDirectory -Directory $DiagnosticDirectory
        }
    } elseif ([System.IO.Path]::GetFullPath($DiagnosticDirectory) -ceq $expectedDiagnosticDirectory) {
        # The parent may explicitly supply its newly prepared private directory.
        $diagnosticReady = Initialize-CtrlCDiagnosticDirectory -Directory $DiagnosticDirectory
    } else {
        Write-Warning -WarningAction Continue 'Ctrl+C diagnostic directory does not match the request evidence path'
    }
} catch {
    $diagnosticReady = $false
    Write-Warning -WarningAction Continue "Ctrl+C diagnostic setup unavailable: $($_.Exception.Message)"
}
function Write-InjectorPhase {
    param([Parameter(Mandatory = $true)][ValidateSet(
        'initialize', 'native_helper_ready', 'attach_console', 'attached_console',
        'protect_injector', 'protected_injector', 'broadcast_ctrl_c',
        'broadcast_succeeded', 'caught_exception', 'write_native_evidence',
        'native_evidence_written')][string]$Phase)
    try {
        if (-not $script:diagnosticReady) { return }
        $script:diagnosticSequence++
        if ($script:diagnosticSequence -gt 12) { return }
        $path = Join-Path $DiagnosticDirectory ('phase-{0:D2}-{1}.json' -f $script:diagnosticSequence, $Phase)
        Write-ExclusiveCtrlCDiagnostic -Path $path -Record ([ordered]@{
            schema_version = 1
            request_id = $RequestId
            target_process_id = $ProcessId
            helper_process_id = $PID
            sequence = $script:diagnosticSequence
            phase = $Phase
            native_stage = $stage
            elapsed_monotonic_ticks = [System.Diagnostics.Stopwatch]::GetTimestamp() - $diagnosticStarted
            monotonic_frequency_hz = [System.Diagnostics.Stopwatch]::Frequency
            broadcast_succeeded = $broadcastSucceeded
        })
    } catch {
        $script:diagnosticReady = $false
        Write-Warning -WarningAction Continue "Ctrl+C phase diagnostic unavailable: $($_.Exception.Message)"
    }
}
function Initialize-CtrlCNativeMethods {
    # Keep the same in-process Winapi imports without starting a C# compiler.
    # BOOL marshalling, SetLastError and PreserveSig remain part of the ABI.
    $name = [System.Reflection.AssemblyName]::new('P2WlanCtrlCInjector')
    $access = [System.Reflection.Emit.AssemblyBuilderAccess]::Run
    $factory = [System.Reflection.Emit.AssemblyBuilder].GetMethod(
        'DefineDynamicAssembly', [Type[]]@([System.Reflection.AssemblyName],
            [System.Reflection.Emit.AssemblyBuilderAccess]))
    $assembly = if ($null -ne $factory) {
        [System.Reflection.Emit.AssemblyBuilder]::DefineDynamicAssembly($name, $access)
    } else {
        # Windows PowerShell uses the existing .NET Framework AppDomain.
        [AppDomain]::CurrentDomain.DefineDynamicAssembly($name, $access)
    }
    $module = $assembly.DefineDynamicModule($name.Name)
    $native = $module.DefineType('P2WlanCtrlCInjector',
        [System.Reflection.TypeAttributes]'Public, Abstract, Sealed')
    $importConstructor = [System.Runtime.InteropServices.DllImportAttribute].GetConstructor(
        [Type[]]@([string]))
    $importFields = [System.Reflection.FieldInfo[]]@(
        'EntryPoint', 'SetLastError', 'CallingConvention', 'CharSet', 'PreserveSig' |
            ForEach-Object { [System.Runtime.InteropServices.DllImportAttribute].GetField($_) }
    )
    $definitions = @(
        @{ Name = 'AttachConsole'; Parameters = [Type[]]@([uint32]) }
        @{ Name = 'FreeConsole'; Parameters = [Type[]]@() }
        @{ Name = 'GenerateConsoleCtrlEvent'; Parameters = [Type[]]@([uint32], [uint32]) }
        @{ Name = 'SetConsoleCtrlHandler'; Parameters = [Type[]]@([IntPtr], [bool]) }
    )
    foreach ($definition in $definitions) {
        $method = $native.DefineMethod($definition.Name,
            [System.Reflection.MethodAttributes]'Public, Static, HideBySig, PinvokeImpl',
            [System.Reflection.CallingConventions]::Standard, [bool],
            [Type[]]$definition.Parameters)
        $attribute = [System.Reflection.Emit.CustomAttributeBuilder]::new(
            $importConstructor, [object[]]@('kernel32.dll'),
            $importFields, [object[]]@($definition.Name, $true,
                [System.Runtime.InteropServices.CallingConvention]::Winapi,
                [System.Runtime.InteropServices.CharSet]::None, $true))
        $method.SetCustomAttribute($attribute)
        $method.SetImplementationFlags([System.Reflection.MethodImplAttributes]::PreserveSig)
    }
    [void]$native.CreateType()
}
try {
    Write-InjectorPhase -Phase initialize
    Initialize-CtrlCNativeMethods
    Write-InjectorPhase -Phase native_helper_ready
    $stage = 'attach_console'
    Write-InjectorPhase -Phase attach_console
    [void][P2WlanCtrlCInjector]::FreeConsole()
    if (-not [P2WlanCtrlCInjector]::AttachConsole([uint32]$ProcessId)) {
        $nativeErrorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw [System.ComponentModel.Win32Exception]::new($nativeErrorCode)
    }
    Write-InjectorPhase -Phase attached_console
    # Attaching resets this process's handlers. Protect only the injector
    # from its own broadcast; the existing daemon is still required to stop.
    $stage = 'protect_injector'
    Write-InjectorPhase -Phase protect_injector
    if (-not [P2WlanCtrlCInjector]::SetConsoleCtrlHandler([IntPtr]::Zero, $true)) {
        $nativeErrorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw [System.ComponentModel.Win32Exception]::new($nativeErrorCode)
    }
    Write-InjectorPhase -Phase protected_injector
    $stage = 'broadcast_ctrl_c'
    Write-InjectorPhase -Phase broadcast_ctrl_c
    if (-not [P2WlanCtrlCInjector]::GenerateConsoleCtrlEvent(0, 0)) {
        $nativeErrorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw [System.ComponentModel.Win32Exception]::new($nativeErrorCode)
    }
    $broadcastSucceeded = $true
    $exitCode = 0
    Write-InjectorPhase -Phase broadcast_succeeded
} catch {
    $detail = $_.Exception.Message
    Write-InjectorPhase -Phase caught_exception
}
# Keep the ignore attribute until this helper exits. Detaching here resets
# handlers before a pending self-broadcast has necessarily been delivered.
# Process exit releases the console attachment within the parent's deadline.
Write-InjectorPhase -Phase write_native_evidence
[ordered]@{
    request_id = $RequestId
    target_process_id = $ProcessId
    broadcast_succeeded = $broadcastSucceeded
    stage = $stage
    native_error_code = $nativeErrorCode
    detail = $detail
} | ConvertTo-Json | Set-Content -LiteralPath $EvidencePath -Encoding utf8
Write-InjectorPhase -Phase native_evidence_written
exit $exitCode
