using System;
using System.Threading;
using System.Diagnostics;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;
using System.Text;
using System.Linq;

namespace Windows.Utilities
{
    #region Enumerations
    /// <summary>
    /// The Windows security model enables you to control access to the service control manager (SCM) and service objects.
    /// 
    /// Minimum supported client: Windows XP [desktop apps only]
    /// Minimum supported server: Windows Server 2003 [desktop apps only]
    /// Header: winsvc.h (include Windows.h)
    /// 
    /// Documentation: https://learn.microsoft.com/windows/win32/services/service-security-and-access-rights
    /// </summary>
    internal enum SC_MANAGER_SECURITY : uint
    {
        SC_MANAGER_CONNECT = 0x0001,
        SC_MANAGER_CREATE_SERVICE = 0x0002,
        SC_MANAGER_ENUMERATE_SERVICE = 0x0004,
        SC_MANAGER_LOCK = 0x0008,
        SC_MANAGER_QUERY_LOCK_STATUS = 0x0010,
        SC_MANAGER_MODIFY_BOOT_CONFIG = 0x0020,
        SC_MANAGER_ALL_ACCESS = 0xF003F,
        GENERIC_READ = ACCESS_TYPE.STANDARD_RIGHTS_READ |
                       SC_MANAGER_ENUMERATE_SERVICE |
                       SC_MANAGER_QUERY_LOCK_STATUS,

        GENERIC_WRITE = ACCESS_TYPE.STANDARD_RIGHTS_WRITE |
                        SC_MANAGER_CREATE_SERVICE |
                        SC_MANAGER_MODIFY_BOOT_CONFIG,

        GENERIC_EXECUTE = ACCESS_TYPE.STANDARD_RIGHTS_EXECUTE |
                          SC_MANAGER_CONNECT |
                          SC_MANAGER_LOCK,

        GENERIC_ALL = SC_MANAGER_ALL_ACCESS
    }

    /// <summary>
    /// The Windows security model enables you to control access to the service control manager (SCM) and service objects.
    /// 
    /// Minimum supported client: Windows XP [desktop apps only]
    /// Minimum supported server: Windows Server 2003 [desktop apps only]
    /// Header: winsvc.h (include Windows.h)
    /// 
    /// Documentation: https://learn.microsoft.com/windows/win32/services/service-security-and-access-rights
    /// </summary>
    internal enum SERVICE_SECURITY : uint
    {
        SERVICE_QUERY_CONFIG = 0x0001,
        SERVICE_CHANGE_CONFIG = 0x0002,
        SERVICE_QUERY_STATUS = 0x0004,
        SERVICE_ENUMERATE_DEPENDENTS = 0x0008,
        SERVICE_START = 0x0010,
        SERVICE_STOP = 0x0020,
        SERVICE_PAUSE_CONTINUE = 0x0040,
        SERVICE_INTERROGATE = 0x0080,
        SERVICE_USER_DEFINED_CONTROL = 0x0100,
        SERVICE_ALL_ACCESS = 0xF01FF,
        ACCESS_SYSTEM_SECURITY = ACCESS_TYPE.ACCESS_SYSTEM_SECURITY,
        DELETE = 0x10000,
        READ_CONTROL = 0x20000,
        WRITE_DAC = 0x40000,
        WRITE_OWNER = 0x80000,
        GENERIC_READ = ACCESS_TYPE.STANDARD_RIGHTS_READ |
                       SERVICE_QUERY_CONFIG |
                       SERVICE_QUERY_STATUS |
                       SERVICE_INTERROGATE |
                       SERVICE_ENUMERATE_DEPENDENTS,

        GENERIC_WRITE = ACCESS_TYPE.STANDARD_RIGHTS_WRITE | SERVICE_CHANGE_CONFIG,
        GENERIC_EXECUTE = ACCESS_TYPE.STANDARD_RIGHTS_EXECUTE |
                          SERVICE_START |
                          SERVICE_STOP |
                          SERVICE_PAUSE_CONTINUE |
                          SERVICE_USER_DEFINED_CONTROL
    }

    /// <summary>
    /// Minimum supported client:
    /// Minimum supported server:
    /// Header: winsvc.h (include Windows.h)
    /// 
    /// Documentation: https://learn.microsoft.com/windows/win32/api/winsvc/nf-winsvc-queryservicestatusex
    /// </summary>
    internal enum SC_STATUS_TYPE : uint
    {
        SC_STATUS_PROCESS_INFO = 0
    }

    /// <summary>
    /// Control codes to send to a service using 'ControlService'.
    /// Minimum supported client: Windows XP [desktop apps only]
    /// Minimum supported server: Windows Server 2003 [desktop apps only]
    /// Header: winsvc.h (include Windows.h)
    /// 
    /// Documentation: https://learn.microsoft.com/windows/win32/api/winsvc/nf-winsvc-controlservice
    /// </summary>
    internal enum SERVICE_CONTROL : uint
    {
        SERVICE_CONTROL_STOP = 0x00000001,
        SERVICE_CONTROL_PAUSE = 0x00000002,
        SERVICE_CONTROL_CONTINUE = 0x00000003,
        SERVICE_CONTROL_INTERROGATE = 0x00000004,
        SERVICE_CONTROL_SHUTDOWN = 0x00000005,
        SERVICE_CONTROL_PARAMCHANGE = 0x00000006,
        SERVICE_CONTROL_NETBINDADD = 0x00000007,
        SERVICE_CONTROL_NETBINDREMOVE = 0x00000008,
        SERVICE_CONTROL_NETBINDENABLE = 0x00000009,
        SERVICE_CONTROL_NETBINDDISABLE = 0x0000000A,
        SERVICE_CONTROL_DEVICEEVENT = 0x0000000B,
        SERVICE_CONTROL_HARDWAREPROFILECHANGE = 0x0000000C,
        SERVICE_CONTROL_POWEREVENT = 0x0000000D,
        SERVICE_CONTROL_SESSIONCHANGE = 0x0000000E,
        SERVICE_CONTROL_PRESHUTDOWN = 0x0000000F,
        SERVICE_CONTROL_TIMECHANGE = 0x00000010,
        SERVICE_CONTROL_TRIGGEREVENT = 0x00000020,
        SERVICE_CONTROL_LOWRESOURCES = 0x00000060,
        SERVICE_CONTROL_SYSTEMLOWRESOURCES = 0x00000061
    }

    /// <summary>
    /// Service State for Enum Requests (Bit Mask).
    /// Minimum supported client: Windows XP [desktop apps only]
    /// Minimum supported server: Windows Server 2003 [desktop apps only]
    /// Header: winsvc.h (include Windows.h)
    /// 
    /// Documentation: https://learn.microsoft.com/windows/win32/api/winsvc/nf-winsvc-enumdependentservicesw
    /// </summary>
    internal enum SERVICE_ENUM_STATE : uint
    {
        SERVICE_ACTIVE = 0x00000001,
        SERVICE_INACTIVE = 0x00000002,
        SERVICE_STATE_ALL = SERVICE_ACTIVE | SERVICE_INACTIVE
    }

    /// <summary>
    /// 'System.ServiceProcess.ServiceStartMode' does not contains a definition for 'AutomaticDelayedStart'.
    /// Mimicing 'Microsoft.PowerShell.Commands.ServiceStartupType', we add 'AutomaticDelayedStart', and the methods to get it.
    /// </summary>
    public enum ServiceStartupType : uint
    {
        Boot,
        System,
        Automatic,
        Manual,
        Disabled,
        AutomaticDelayedStart
    }

    /// <summary>
    /// System.ServiceProcess.ServiceControllerStatus
    /// </summary>
    public enum ServiceStatus : uint
    {
        Stopped = 0x00000001,
        StartPending = 0x00000002,
        StopPending = 0x00000003,
        Running = 0x00000004,
        ContinuePending = 0x00000005,
        PausePending = 0x00000006,
        Paused = 0x00000007
    }

    public enum ServiceType : uint
    {
        KernelDriver = 0x00000001,
        FileSystemDriver = 0x00000002,
        Win32OwnProcess = 0x00000010,
        Win32ShareProcess = 0x00000020,
        InteractiveProcess = 0x00000100
    }
    #endregion

    #region Structures
    /// <summary>
    /// Contains configuration information for an installed service. It is used by the QueryServiceConfig function.
    /// 
    /// Minimum supported client: Windows XP [desktop apps only]
    /// Minimum supported server: Windows Server 2003 [desktop apps only]
    /// Header: winsvc.h (include Windows.h)
    /// 
    /// P/Invoke:
    /// Documentation: https://learn.microsoft.com/windows/win32/api/winsvc/ns-winsvc-query_service_configa
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct QUERY_SERVICE_CONFIG
    {
        internal ServiceType dwServiceType;
        internal uint dwStartType;
        internal uint dwErrorControl;
        internal string lpBinaryPathName;
        internal string lpLoadOrderGroup;
        internal uint dwTagId;
        internal IntPtr lpDependencies;
        internal string lpServiceStartName;
        internal string lpDisplayName;
    }

    /// <summary>
    /// Contains status information for a service. The ControlService, EnumDependentServices, EnumServicesStatus, and QueryServiceStatus functions use this structure.
    /// 
    /// Minimum supported client: Windows XP [desktop apps only]
    /// Minimum supported server: Windows Server 2003 [desktop apps only]
    /// Header: winsvc.h (include Windows.h)
    /// 
    /// P/Invoke:
    /// Documentation: https://learn.microsoft.com/windows/win32/api/winsvc/ns-winsvc-service_status
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct SERVICE_STATUS
    {
        internal uint dwServiceType;
        internal ServiceStatus dwCurrentState;
        internal uint dwControlsAccepted;
        internal uint dwWin32ExitCode;
        internal uint dwServiceSpecificExitCode;
        internal uint dwCheckPoint;
        internal uint dwWaitHint;
    }

    /// <summary>
    /// Contains status information for a service. The ControlService, EnumDependentServices, EnumServicesStatus, and QueryServiceStatus functions use this structure.
    /// 
    /// Minimum supported client: Windows XP [desktop apps only]
    /// Minimum supported server: Windows Server 2003 [desktop apps only]
    /// Header: winsvc.h (include Windows.h)
    /// 
    /// P/Invoke:
    /// Documentation: https://learn.microsoft.com/windows/win32/api/winsvc/ns-winsvc-service_status_process
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct SERVICE_STATUS_PROCESS
    {
        internal ServiceType dwServiceType;
        internal ServiceStatus dwCurrentState;
        internal uint dwControlsAccepted;
        internal uint dwWin32ExitCode;
        internal uint dwServiceSpecificExitCode;
        internal uint dwCheckPoint;
        internal uint dwWaitHint;
        internal uint dwProcessId;
        internal uint dwServiceFlags;
    }

    /// <summary>
    /// Contains the delayed auto-start setting of an auto-start service.
    /// 
    /// Minimum supported client: Windows XP [desktop apps only]
    /// Minimum supported server: Windows Server 2003 [desktop apps only]
    /// Header: winsvc.h (include Windows.h)
    /// 
    /// P/Invoke:
    /// Documentation: https://learn.microsoft.com/windows/win32/api/winsvc/ns-winsvc-service_delayed_auto_start_info
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct SERVICE_DELAYED_AUTO_START_INFO
    {
        internal bool fDelayedAutostart;
    }

    /// <summary>
    /// Contains the name of a service in a service control manager database and information about that service.
    /// It is used by the EnumDependentServices and EnumServicesStatus functions.
    /// 
    /// Minimum supported client: Windows XP [desktop apps only]
    /// Minimum supported server: Windows Server 2003 [desktop apps only]
    /// Header: winsvc.h (include Windows.h)
    /// 
    /// P/Invoke:
    /// Documentation: https://learn.microsoft.com/windows/win32/api/winsvc/ns-winsvc-enum_service_statusw
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct ENUM_SERVICE_STATUS
    {
        internal string lpServiceName;
        internal string lpDisplayName;
        internal SERVICE_STATUS ServiceStatus;
    }
    #endregion

    internal partial class NativeFunctions
    {
        // winsvc.h (include Windows.h)
        internal static readonly uint SERVICE_NO_CHANGE = uint.MaxValue;

        /// <summary>
        /// Establishes a connection to the service control manager on the specified computer and opens the specified service control manager database.
        /// 
        /// Minimum supported client: Windows XP [desktop apps only]
        /// Minimum supported server: Windows Server 2003 [desktop apps only]
        /// Header: winsvc.h (include Windows.h)
        /// 
        /// P/Invoke: http://pinvoke.net/default.aspx/advapi32/OpenSCManager.html?diff=y
        /// Documentation: https://learn.microsoft.com/windows/win32/api/winsvc/nf-winsvc-openscmanagerw
        /// </summary>
        [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "OpenSCManagerW")]
        public static extern ServiceSafeHandle OpenSCManager(
            string lpMachineName,
            string lpDatabaseName,
            SC_MANAGER_SECURITY dwDesiredAccess
        );

        /// <summary>
        /// Opens an existing service.
        /// 
        /// Minimum supported client: Windows XP [desktop apps only]
        /// Minimum supported server: Windows Server 2003 [desktop apps only]
        /// Header: winsvc.h (include Windows.h)
        /// 
        /// P/Invoke: https://www.pinvoke.net/default.aspx/advapi32.openservice
        /// Documentation: https://learn.microsoft.com/windows/win32/api/winsvc/nf-winsvc-openservicew
        /// </summary>
        [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "OpenServiceW")]
        public static extern ServiceSafeHandle OpenService(
            ServiceSafeHandle hSCManager,
            string lpServiceName,
            SERVICE_SECURITY dwDesiredAccess
        );

        /// <summary>
        /// The QueryServiceObjectSecurity function retrieves a copy of the security descriptor associated with a service object.
        /// You can also use the GetNamedSecurityInfo function to retrieve a security descriptor.
        /// 
        /// Minimum supported client: Windows XP [desktop apps only]
        /// Minimum supported server: Windows Server 2003 [desktop apps only]
        /// Header: winsvc.h (include Windows.h)
        /// 
        /// P/Invoke: https://www.pinvoke.net/default.aspx/advapi32.queryserviceobjectsecurity
        /// Documentation: https://learn.microsoft.com/windows/win32/api/winsvc/nf-winsvc-queryserviceobjectsecurity
        /// </summary>
        [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool QueryServiceObjectSecurity(
            ServiceSafeHandle hService,
            uint dwSecurityInformation,
            IntPtr lpSecurityDescriptor,
            uint cbBufSize,
            out uint pcbBytesNeeded
        );

        /// <summary>
        /// The SetServiceObjectSecurity function sets the security descriptor of a service object.
        /// 
        /// Minimum supported client: Windows XP [desktop apps only]
        /// Minimum supported server: Windows Server 2003 [desktop apps only]
        /// Header: winsvc.h (include Windows.h)
        /// 
        /// P/Invoke: https://www.pinvoke.net/default.aspx/advapi32.setserviceobjectsecurity
        /// Documentation: https://learn.microsoft.com/windows/win32/api/winsvc/nf-winsvc-setserviceobjectsecurity
        /// </summary>
        [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool SetServiceObjectSecurity(
            ServiceSafeHandle hService,
            uint dwSecurityInformation,
            IntPtr lpSecurityDescriptor
        );

        /// <summary>
        /// Changes the optional configuration parameters of a service.
        /// 
        /// Minimum supported client: Windows XP [desktop apps only]
        /// Minimum supported server: Windows Server 2003 [desktop apps only]
        /// Header: winsvc.h (include Windows.h)
        /// 
        /// P/Invoke: https://www.pinvoke.net/default.aspx/advapi32.changeserviceconfig2
        /// Documentation: https://learn.microsoft.com/windows/win32/api/winsvc/nf-winsvc-changeserviceconfig2w
        /// </summary>
        [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "ChangeServiceConfig2W")]
        internal static extern bool ChangeServiceConfig2(
            ServiceSafeHandle hService,
            uint dwInfoLevel,
            IntPtr lpInfo
        );

        /// <summary>
        /// Retrieves the optional configuration parameters of the specified service.
        /// 
        /// Minimum supported client: Windows XP [desktop apps only]
        /// Minimum supported server: Windows Server 2003 [desktop apps only]
        /// Header: winsvc.h (include Windows.h)
        /// 
        /// P/Invoke: https://www.pinvoke.net/default.aspx/advapi32/queryserviceconfig.html
        /// Documentation: https://learn.microsoft.com/windows/win32/api/winsvc/nf-winsvc-queryserviceconfigw
        /// </summary>
        [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "QueryServiceConfigW")]
        internal static extern bool QueryServiceConfig(
            ServiceSafeHandle hService,
            IntPtr lpServiceConfig,
            uint cbBufferSize,
            out uint pcbBytesNeeded
        );

        /// <summary>
        /// This function has been superseded by the QueryServiceStatusEx function.
        /// 
        /// Minimum supported client: Windows XP [desktop apps only]
        /// Minimum supported server: Windows Server 2003 [desktop apps only]
        /// Header: winsvc.h (include Windows.h)
        /// 
        /// P/Invoke:
        /// Documentation: https://learn.microsoft.com/windows/win32/api/winsvc/nf-winsvc-queryservicestatus
        /// </summary>
        [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern bool QueryServiceStatusEx(
            ServiceSafeHandle hService,
            SC_STATUS_TYPE InfoLevel,
            ref SERVICE_STATUS_PROCESS lpBuffer,
            uint cbBufSize,
            out uint pcbBytesNeeded
        );

        /// <summary>
        /// Retrieves the optional configuration parameters of the specified service.
        /// 
        /// Minimum supported client: Windows XP [desktop apps only]
        /// Minimum supported server: Windows Server 2003 [desktop apps only]
        /// Header: winsvc.h (include Windows.h)
        /// 
        /// P/Invoke: https://www.pinvoke.net/default.aspx/advapi32.changeserviceconfig2
        /// Documentation: https://learn.microsoft.com/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2w
        /// </summary>
        [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "QueryServiceConfig2W")]
        internal static extern bool QueryServiceConfig2(
            ServiceSafeHandle hService,
            uint dwInfoLevel,
            IntPtr buffer,
            uint cbBufSize,
            out uint pcbBytesNeeded
        );

        /// <summary>
        /// Changes the configuration parameters of a service.
        /// 
        /// Minimum supported client: Windows XP [desktop apps only]
        /// Minimum supported server: Windows Server 2003 [desktop apps only]
        /// Header: winsvc.h (include Windows.h)
        /// 
        /// P/Invoke: https://www.pinvoke.net/default.aspx/advapi32.changeserviceconfig
        /// Documentation: https://learn.microsoft.com/windows/win32/api/winsvc/nf-winsvc-changeserviceconfigw
        /// </summary>
        [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "ChangeServiceConfigW")]
        internal static extern bool ChangeServiceConfig(
            ServiceSafeHandle hService, uint dwServiceType, uint dwStartType, uint dwErrorControl,
            IntPtr lpBinaryPathName, IntPtr lpLoadOrderGroup, IntPtr lpdwTagId, string lpDependencies,
            IntPtr lpServiceStartName, IntPtr lpPassword, IntPtr lpDisplayName
        );

        /// <summary>
        /// Changes the configuration parameters of a service.
        /// 
        /// Minimum supported client: Windows XP [desktop apps only]
        /// Minimum supported server: Windows Server 2003 [desktop apps only]
        /// Header: winsvc.h (include Windows.h)
        /// 
        /// P/Invoke: https://www.pinvoke.net/default.aspx/advapi32.startservice
        /// Documentation: https://learn.microsoft.com/windows/win32/api/winsvc/nf-winsvc-startservicew
        /// </summary>
        [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "StartServiceW")]
        internal static extern bool StartService(
            ServiceSafeHandle hService,
            uint dwNumServiceArgs,
            string[] lpServiceArgVectors
        );

        /// <summary>
        /// Changes the configuration parameters of a service.
        /// 
        /// Minimum supported client: Windows XP [desktop apps only]
        /// Minimum supported server: Windows Server 2003 [desktop apps only]
        /// Header: winsvc.h (include Windows.h)
        /// 
        /// P/Invoke: https://www.pinvoke.net/default.aspx/advapi32.startservice
        /// Documentation: https://learn.microsoft.com/windows/win32/api/winsvc/nf-winsvc-startservicew
        /// </summary>
        [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern bool ControlService(
            ServiceSafeHandle hService,
            SERVICE_CONTROL dwControl,
            ref SERVICE_STATUS lpServiceStatus
        );

        /// <summary>
        /// Changes the configuration parameters of a service.
        /// 
        /// Minimum supported client: Windows XP [desktop apps only]
        /// Minimum supported server: Windows Server 2003 [desktop apps only]
        /// Header: winsvc.h (include Windows.h)
        /// 
        /// P/Invoke: https://www.pinvoke.net/default.aspx/advapi32.startservice
        /// Documentation: https://learn.microsoft.com/windows/win32/api/winsvc/nf-winsvc-startservicew
        /// </summary>
        [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "EnumDependentServicesW")]
        internal static extern bool EnumDependentServices(
            ServiceSafeHandle hService,
            SERVICE_ENUM_STATE dwServiceState,
            IntPtr lpServices,
            uint cbBufferSize,
            out uint pcbBytesNeeded,
            out uint lpServicesReturned
        );

        /// <summary>
        /// This function has been superseded by the QueryServiceStatusEx function.
        /// 
        /// Minimum supported client: Windows XP [desktop apps only]
        /// Minimum supported server: Windows Server 2003 [desktop apps only]
        /// Header: winsvc.h (include Windows.h)
        /// 
        /// P/Invoke:
        /// Documentation: https://learn.microsoft.com/windows/win32/api/winsvc/nf-winsvc-queryservicestatus
        /// </summary>
        [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern bool DeleteService(ServiceSafeHandle hService);

        /// <summary>
        /// This function has been superseded by the QueryServiceStatusEx function.
        /// 
        /// Minimum supported client: Windows XP [desktop apps only]
        /// Minimum supported server: Windows Server 2003 [desktop apps only]
        /// Header: winsvc.h (include Windows.h)
        /// 
        /// P/Invoke:
        /// Documentation: https://learn.microsoft.com/windows/win32/api/winsvc/nf-winsvc-queryservicestatus
        /// </summary>
        [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern bool QueryServiceStatus(ServiceSafeHandle hService, out SERVICE_STATUS lpServiceStatus);

        /// <summary>
        /// Closes a handle to a service control manager or service object.
        /// 
        /// Minimum supported client: Windows XP [desktop apps only]
        /// Minimum supported server: Windows Server 2003 [desktop apps only]
        /// Header: winsvc.h (include Windows.h)
        /// 
        /// P/Invoke: https://www.pinvoke.net/default.aspx/advapi32.closeservicehandl
        /// Documentation: https://learn.microsoft.com/windows/win32/api/winsvc/nf-winsvc-closeservicehandle
        /// </summary>
        [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CloseServiceHandle(IntPtr hSCObject);
    }

    /// <summary>
    /// This class manages handles to service control manager objects internally.
    /// It's responsible for opening, managing and closing safe handles.
    /// Using a singleton design pattern allows us to optimize the use of system handles.
    /// </summary>
    internal sealed class ServiceControlManager : IDisposable
    {
        private readonly ServiceSafeHandle _scm_handle;

        internal ServiceControlManager() => _scm_handle = NativeFunctions.OpenSCManager(".", "ServicesActive", SC_MANAGER_SECURITY.SC_MANAGER_CONNECT);
        internal ServiceControlManager(SC_MANAGER_SECURITY desired_access) => _scm_handle = NativeFunctions.OpenSCManager(".", "ServicesActive", desired_access);

        /// <summary>
        /// Kept to satisfy the IDisposable inheritance.
        /// </summary>
        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Static method to be called by the API to dispose of all unmanaged resources.
        /// </summary>
        /// <param name="disposing">Dispose of all unmanaged resources.</param>
        private void Dispose(bool disposing)
        {
            if (disposing)
                _scm_handle?.Dispose();
        }

        /// <summary>
        /// Returns a safe handle to a service.
        /// </summary>
        /// <param name="service_name">The service name.</param>
        /// <returns>Windows.Utilities.ServiceSafeHandle</returns>
        internal ServiceSafeHandle GetServiceSafeHandle(string service_name) => GetServiceSafeHandleWithSecurity(service_name, SERVICE_SECURITY.GENERIC_READ);

        /// <summary>
        /// Returns a safe handle to a service.
        /// </summary>
        /// <param name="service_name">The service name.</param>
        /// <param name="desired_access">Desired service access.</param>
        /// <returns>Windows.Utilities.ServiceSafeHandle</returns>
        internal ServiceSafeHandle GetServiceSafeHandle(string service_name, SERVICE_SECURITY desired_access) => GetServiceSafeHandleWithSecurity(service_name, desired_access);

        /// <summary>
        /// Returns a safe system handle for the given service name.
        /// This method manages the handle to the service control manager, and checks
        /// if a handle for that service is already opened.
        /// </summary>
        /// <param name="service_name">The service name.</param>
        /// <param name="scm_access">Desired service control manager access.</param>
        /// <param name="svc_access">Desired service access.</param>
        /// <returns>Windows.Utilities.ServiceSafeHandle</returns>
        private ServiceSafeHandle GetServiceSafeHandleWithSecurity(string service_name, SERVICE_SECURITY desired_access)
        {
            if (null == _scm_handle || _scm_handle.IsClosed || _scm_handle.IsInvalid)
                throw new ArgumentException("Invalid service control manager handle.");

            ServiceSafeHandle safe_handle = NativeFunctions.OpenService(_scm_handle, service_name, desired_access);
            if (safe_handle.IsInvalid)
                NativeException.ThrowNativeException(Marshal.GetLastWin32Error(), Environment.StackTrace);

            return safe_handle;
        }
    }

    public class ServiceDependentInformation
    {
        public string Name { get; }
        public string DisplayName { get; }
        public ServiceStatus Status { get; }

        internal ServiceDependentInformation(ENUM_SERVICE_STATUS unmanaged_status) =>
            (Name, DisplayName, Status) =
                (unmanaged_status.lpServiceName, unmanaged_status.lpDisplayName, unmanaged_status.ServiceStatus.dwCurrentState);
    }

    /// <summary>
    /// This is the main API exposed externally.
    /// Design to manage service control manager objects.
    /// </summary>
    public sealed class Service
    {
        public string Name { get { return _service_name; } }
        public string DisplayName { get { return _display_name; } }
        public string StartAccount { get { return _start_name; } }
        public ServiceStatus Status { get { return _status; } }
        public ServiceStartupType StartupType { get { return _startup_type; } }
        public string[] Dependencies { get { return _dependencies; } }
        public string BynaryPath { get { return _bin_path; } }

        private readonly string _service_name;
        private readonly string _display_name;
        private readonly string _start_name;
        private readonly string _bin_path;
        private string[] _dependencies;
        private ServiceStatus _status;
        private ServiceStartupType _startup_type;

        public Service(string service_name)
        {
            _service_name = service_name;
            QUERY_SERVICE_CONFIG svc_config;

            using ServiceControlManager scm = new();
            ServiceSafeHandle h_service = scm.GetServiceSafeHandle(service_name);

            try
            {
                svc_config = QueryServiceConfigInternal(h_service);

                switch (svc_config.dwStartType)
                {
                    case 0x00000002:
                        if (IsServiceDelayedStart(ref h_service))
                            _startup_type = ServiceStartupType.AutomaticDelayedStart;
                        break;

                    default:
                        _startup_type = (ServiceStartupType)svc_config.dwStartType;
                        break;
                }

                SERVICE_STATUS_PROCESS svc_status = new();
                if (!NativeFunctions.QueryServiceStatusEx(h_service, SC_STATUS_TYPE.SC_STATUS_PROCESS_INFO, ref svc_status, (uint)Marshal.SizeOf(svc_status), out uint bytes_needed))
                    NativeException.ThrowNativeException(Marshal.GetLastWin32Error(), Environment.StackTrace);

                // _dependencies = svc_config.lpDependencies.Split('\0').Where(x => !string.IsNullOrEmpty(x)).ToArray();
                _dependencies = NativeFunctions.GetStringArrayFromDoubleNullTermninatedCStyleArray(svc_config.lpDependencies);
                _status = svc_status.dwCurrentState;
                _display_name = svc_config.lpDisplayName;
                _start_name = svc_config.lpServiceStartName;
                _bin_path = svc_config.lpBinaryPathName;
            }
            finally
            {
                h_service.Dispose();
            }
        }

        /// <summary>
        /// This method sets a service who the given service depends on.
        /// TODO: Set lists of services.
        /// </summary>
        /// <param name="service_name">The service name to change the config.</param>
        /// <param name="service_depended_on">The service name to include in the dependency list.</param>
        /// <exception cref="ArgumentException">Service dependency cannot be null or empty.</exception>
        /// <exception cref="NativeException">Native function call failed.</exception>
        public void SetDependency(string[]? service_depended_on)
        {
            string svc_dependency_string = string.Empty;
            if (service_depended_on is not null)
            {
                // From the 'ChangeServiceConfig' documentation about the parameter 'lpDependencies':
                // "A pointer to a double null-terminated array of null-separated names of services or load ordering groups
                // that the system must start before this service can be started."

                StringBuilder c_string_array_buffer = new();
                foreach (string service_name in service_depended_on)
                    c_string_array_buffer.Append(service_name + "\0");

                c_string_array_buffer.Append("\0\0");

                svc_dependency_string = c_string_array_buffer.ToString();
            }

            using ServiceControlManager scm = new();
            ServiceSafeHandle h_service = scm.GetServiceSafeHandle(_service_name, SERVICE_SECURITY.SERVICE_CHANGE_CONFIG | SERVICE_SECURITY.SERVICE_QUERY_CONFIG);

            try
            {
                if (!NativeFunctions.ChangeServiceConfig(h_service, NativeFunctions.SERVICE_NO_CHANGE, NativeFunctions.SERVICE_NO_CHANGE, NativeFunctions.SERVICE_NO_CHANGE, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, svc_dependency_string, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero))
                    NativeException.ThrowNativeException(Marshal.GetLastWin32Error(), Environment.StackTrace);

                QUERY_SERVICE_CONFIG svc_config = QueryServiceConfigInternal(h_service);
                //_dependencies = svc_config.lpDependencies.Split('\0').Where(x => !string.IsNullOrEmpty(x)).ToArray();
                _dependencies = NativeFunctions.GetStringArrayFromDoubleNullTermninatedCStyleArray(svc_config.lpDependencies);
            }
            finally
            {
                h_service.Dispose();
            }
        }

        /// <summary>
        /// This method returns true if the service is set to Automatic with Delayed Start.
        /// TODO: Convert to 'GetServiceStartupType(string service_name)'.
        /// </summary>
        /// <param name="service_name">The service name.</param>
        /// <returns>System.Bool</returns>
        /// <exception cref="NativeException">Native function call failed.</exception>
        internal bool IsServiceDelayedStart(ref ServiceSafeHandle h_service)
        {
            bool is_delayed_start = false;
            IntPtr buffer = IntPtr.Zero;
            try
            {
                // Getting buffer size.
                if (!NativeFunctions.QueryServiceConfig2(h_service, 3, IntPtr.Zero, 0, out uint bytes_needed))
                {
                    int last_error = Marshal.GetLastWin32Error();
                    if (last_error != NativeFunctions.ERROR_INSUFFICIENT_BUFFER)
                        NativeException.ThrowNativeException(Marshal.GetLastWin32Error(), Environment.StackTrace);
                }

                buffer = Marshal.AllocHGlobal((int)bytes_needed);

                if (!NativeFunctions.QueryServiceConfig2(h_service, 3, buffer, bytes_needed, out bytes_needed)) // 3: SERVICE_CONFIG_DELAYED_AUTO_START_INFO.
                    NativeException.ThrowNativeException(Marshal.GetLastWin32Error(), Environment.StackTrace);

                SERVICE_DELAYED_AUTO_START_INFO svc_del_auto_start_info = (SERVICE_DELAYED_AUTO_START_INFO)Marshal.PtrToStructure(buffer, typeof(SERVICE_DELAYED_AUTO_START_INFO));
                is_delayed_start = svc_del_auto_start_info.fDelayedAutostart;
            }
            finally { Marshal.FreeHGlobal(buffer); }

            return is_delayed_start;
        }

        /// <summary>
        /// This method sets the given service's startup type, including Automatic - Delayed Start.
        /// </summary>
        /// <param name="service_name">The service name.</param>
        /// <param name="startup_type">The startup type desired.</param>
        /// <exception cref="ArgumentException">Invalid service start type.</exception>
        /// <exception cref="NativeException">Native function call failed.</exception>
        public void SetStartupType(ServiceStartupType startup_type)
        {
            bool set_auto_delayed = false;
            uint op_code;
            IntPtr buffer = IntPtr.Zero;

            using ServiceControlManager scm = new();
            ServiceSafeHandle h_service = scm.GetServiceSafeHandle(_service_name, SERVICE_SECURITY.SERVICE_QUERY_CONFIG | SERVICE_SECURITY.SERVICE_CHANGE_CONFIG);

            try
            {
                switch (startup_type)
                {
                    case ServiceStartupType.Automatic:
                        op_code = 0x00000002;
                        break;
                    case ServiceStartupType.AutomaticDelayedStart:
                        op_code = 0x00000002;
                        set_auto_delayed = true;
                        break;
                    case ServiceStartupType.Manual:
                        op_code = 0x00000003;
                        break;
                    case ServiceStartupType.Disabled:
                        op_code = 0x00000004;
                        break;
                    default:
                        throw new ArgumentException(string.Format("Invalid start type '{0}'", startup_type.ToString()));
                }

                if (!NativeFunctions.ChangeServiceConfig(h_service, NativeFunctions.SERVICE_NO_CHANGE, op_code, NativeFunctions.SERVICE_NO_CHANGE, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, string.Empty, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero))
                    NativeException.ThrowNativeException(Marshal.GetLastWin32Error(), Environment.StackTrace);

                if (set_auto_delayed)
                {
                    SERVICE_DELAYED_AUTO_START_INFO svc_del_auto_start_info = new()
                    {
                        fDelayedAutostart = true
                    };
                    buffer = IntPtr.Zero;
                    try
                    {
                        buffer = Marshal.AllocHGlobal(Marshal.SizeOf(svc_del_auto_start_info));
                        Marshal.StructureToPtr(svc_del_auto_start_info, buffer, false);

                        if (!NativeFunctions.ChangeServiceConfig2(h_service, 3, buffer)) // 3: SERVICE_CONFIG_DELAYED_AUTO_START_INFO.
                            NativeException.ThrowNativeException(Marshal.GetLastWin32Error(), Environment.StackTrace);
                    }
                    finally { Marshal.FreeHGlobal(buffer); }
                }

                // Updating service startup type information.
                QUERY_SERVICE_CONFIG svc_config = QueryServiceConfigInternal(h_service);

                if (svc_config.dwStartType == 0x00000002 && IsServiceDelayedStart(ref h_service))
                    _startup_type = ServiceStartupType.AutomaticDelayedStart;
                else
                    _startup_type = (ServiceStartupType)svc_config.dwStartType;
            }
            finally
            {
                h_service.Dispose();
            }
        }

        /// <summary>
        /// This method tries to start this service.
        /// We call it here so we can wrap native exceptions.
        /// 
        /// Based on: https://learn.microsoft.com/windows/win32/services/starting-a-service
        /// </summary>
        /// <param name="service_name">The service name.</param>
        /// <exception cref="NativeException">Native function call failed.</exception>
        /// <exception cref="InvalidObjectStateException">Call to 'QueryServiceStatusEx' didn't returned 'ServiceState.Running'.</exception>
        public void Start(uint wait_stop_timeout = 60, bool wait = true)
        {
            // Opening the database, and getting a handle to the service.
            using ServiceControlManager scm = new();
            using ServiceSafeHandle h_service = scm.GetServiceSafeHandle(_service_name, SERVICE_SECURITY.SERVICE_START | SERVICE_SECURITY.SERVICE_QUERY_STATUS);

            // Check the status.
            SERVICE_STATUS_PROCESS svc_status = new();
            if (!NativeFunctions.QueryServiceStatusEx(h_service, SC_STATUS_TYPE.SC_STATUS_PROCESS_INFO, ref svc_status, (uint)Marshal.SizeOf(svc_status), out uint bytes_needed))
                NativeException.ThrowNativeException(Marshal.GetLastWin32Error(), Environment.StackTrace);

            if (svc_status.dwCurrentState != ServiceStatus.Stopped && svc_status.dwCurrentState != ServiceStatus.StopPending)
                return;

            // If the service status is 'StopPending' we wait until it stops.
            Stopwatch sw = Stopwatch.StartNew();
            while (svc_status.dwCurrentState == ServiceStatus.StopPending)
            {
                // Do not wait longer than the wait hint. A good interval is 
                // one-tenth of the wait hint but not less than 1 second  
                // and not more than 10 seconds.
                uint wait_time = svc_status.dwWaitHint / 10;
                if (wait_time < 1000)
                    wait_time = 1000;
                if (wait_time > 10000)
                    wait_time = 10000;

                Thread.Sleep((int)wait_time);

                if (sw.Elapsed.TotalSeconds > wait_stop_timeout)
                    throw new TimeoutException("Timed out waiting for the service to stop.");

                if (!NativeFunctions.QueryServiceStatusEx(h_service, SC_STATUS_TYPE.SC_STATUS_PROCESS_INFO, ref svc_status, (uint)Marshal.SizeOf(svc_status), out bytes_needed))
                    NativeException.ThrowNativeException(Marshal.GetLastWin32Error(), Environment.StackTrace);
            }
            sw.Stop();

            // Attempt to start the service.
            if (!NativeFunctions.StartService(h_service, 0, new string[] { }))
                NativeException.ThrowNativeException(Marshal.GetLastWin32Error(), Environment.StackTrace);

            if (!NativeFunctions.QueryServiceStatusEx(h_service, SC_STATUS_TYPE.SC_STATUS_PROCESS_INFO, ref svc_status, (uint)Marshal.SizeOf(svc_status), out bytes_needed))
                NativeException.ThrowNativeException(Marshal.GetLastWin32Error(), Environment.StackTrace);

            if (wait)
            {
                while (svc_status.dwCurrentState == ServiceStatus.StartPending)
                {
                    uint wait_time = svc_status.dwWaitHint / 10;
                    if (wait_time < 1000)
                        wait_time = 1000;
                    if (wait_time > 10000)
                        wait_time = 10000;

                    if (!NativeFunctions.QueryServiceStatusEx(h_service, SC_STATUS_TYPE.SC_STATUS_PROCESS_INFO, ref svc_status, (uint)Marshal.SizeOf(svc_status), out bytes_needed))
                        NativeException.ThrowNativeException(Marshal.GetLastWin32Error(), Environment.StackTrace);
                }

                if (svc_status.dwCurrentState != ServiceStatus.Running)
                    throw new InvalidObjectStateException(string.Format("Unexpected service state '{0}'", svc_status.dwCurrentState.ToString()));

            }

            // Updating service status information.
            if (!NativeFunctions.QueryServiceStatusEx(h_service, SC_STATUS_TYPE.SC_STATUS_PROCESS_INFO, ref svc_status, (uint)Marshal.SizeOf(svc_status), out bytes_needed))
                NativeException.ThrowNativeException(Marshal.GetLastWin32Error(), Environment.StackTrace);

            _status = svc_status.dwCurrentState;
        }
        
        /// <summary>
        /// This method attempts to stop the service.
        /// </summary>
        /// <param name="wait_stop_timeout"></param>
        /// <param name="force"></param>
        /// <param name="wait"></param>
        /// <exception cref="TimeoutException"></exception>
        /// <exception cref="InvalidOperationException"></exception>
        public void Stop(uint wait_stop_timeout = 120, bool force = false, bool wait = true)
        {
            using ServiceControlManager scm = new();
            ServiceSafeHandle h_service = scm.GetServiceSafeHandle(_service_name, SERVICE_SECURITY.SERVICE_ENUMERATE_DEPENDENTS | SERVICE_SECURITY.SERVICE_QUERY_STATUS | SERVICE_SECURITY.SERVICE_STOP);

            try
            {
                if (!NativeFunctions.QueryServiceStatus(h_service, out SERVICE_STATUS svc_status))
                    NativeException.ThrowNativeException(Marshal.GetLastWin32Error(), Environment.StackTrace);

                if (svc_status.dwCurrentState == ServiceStatus.Stopped)
                    return;

                // Waiting the service to stop if it's already stopping.
                Stopwatch sw = Stopwatch.StartNew();
                while (svc_status.dwCurrentState == ServiceStatus.StopPending)
                {
                    uint wait_time = svc_status.dwWaitHint / 10;
                    if (wait_time < 1000)
                        wait_time = 1000;
                    if (wait_time > 10000)
                        wait_time = 10000;

                    Thread.Sleep((int)wait_time);

                    if (sw.Elapsed.TotalSeconds > wait_stop_timeout)
                        throw new TimeoutException("Timed out waiting for the service to stop.");

                    if (!NativeFunctions.QueryServiceStatus(h_service, out svc_status))
                        NativeException.ThrowNativeException(Marshal.GetLastWin32Error(), Environment.StackTrace);

                    if (svc_status.dwCurrentState == ServiceStatus.Stopped)
                        return;
                }
                sw.Stop();

                if (force)
                    StopDependentServices(ref h_service, wait_stop_timeout);
                else
                {
                    IntPtr buffer = IntPtr.Zero;
                    if (!NativeFunctions.EnumDependentServices(h_service, SERVICE_ENUM_STATE.SERVICE_ACTIVE, buffer, 0, out uint bytes_needed, out _))
                    {
                        int last_error = Marshal.GetLastWin32Error();
                        if (last_error == NativeFunctions.ERROR_MORE_DATA)
                            throw new InvalidOperationException("Cannot stop service, it has dependents. To stop the service and dependents use the 'force' parameter.");
                        else
                            NativeException.ThrowNativeException(last_error, Environment.StackTrace);
                    }
                }

                // Attempting to stop service.
                if (!NativeFunctions.ControlService(h_service, SERVICE_CONTROL.SERVICE_CONTROL_STOP, ref svc_status))
                    NativeException.ThrowNativeException(Marshal.GetLastWin32Error(), Environment.StackTrace);

                if (wait)
                {
                    // Waiting the service to stop.
                    while (svc_status.dwCurrentState != ServiceStatus.Stopped)
                    {
                        uint wait_time = svc_status.dwWaitHint / 10;
                        if (wait_time < 1000)
                            wait_time = 1000;
                        if (wait_time > 10000)
                            wait_time = 10000;

                        Thread.Sleep((int)wait_time);

                        if (!NativeFunctions.QueryServiceStatus(h_service, out svc_status))
                            NativeException.ThrowNativeException(Marshal.GetLastWin32Error(), Environment.StackTrace);
                    }
                }

                // Updating service status information.
                if (!NativeFunctions.QueryServiceStatus(h_service, out svc_status))
                    NativeException.ThrowNativeException(Marshal.GetLastWin32Error(), Environment.StackTrace);

                _status = svc_status.dwCurrentState;
            }
            finally
            {
                h_service.Dispose();
            }
        }

        public void Delete(bool force = false)
        {
            if (force)
                Stop(force: true);
            
            else
            {
                // If force was not specified, we try to stop the service.
                // If the service have dependents, we continue and mark it to deletion.
                // It will be deleted when all handles for the service are closed, and the service is stopped.
                try
                {
                    Stop();
                }
                catch (InvalidOperationException) { }
                catch (Exception ex) { throw ex; }
            }

            using ServiceControlManager scm = new();
            using ServiceSafeHandle h_serivce = scm.GetServiceSafeHandle(_service_name, SERVICE_SECURITY.DELETE);

            if (!NativeFunctions.DeleteService(h_serivce))
                NativeException.ThrowNativeException(Marshal.GetLastWin32Error(), Environment.StackTrace);
        }

        /// <summary>
        /// This method returns a list of dependent services.
        /// </summary>
        /// <returns></returns>
        public List<ServiceDependentInformation> GetDependentServices()
        {
            List<ServiceDependentInformation> dependent_services = new();
            IntPtr buffer = IntPtr.Zero;

            using ServiceControlManager scm = new();
            using ServiceSafeHandle h_service = scm.GetServiceSafeHandle(_service_name, SERVICE_SECURITY.SERVICE_ENUMERATE_DEPENDENTS);

            // If the call succeeds with no buffer, the service has no dependents.
            if (NativeFunctions.EnumDependentServices(h_service, SERVICE_ENUM_STATE.SERVICE_STATE_ALL, buffer, 0, out uint bytes_needed, out uint services_returned))
                return dependent_services;

            else
            {
                int last_error = Marshal.GetLastWin32Error();
                if (last_error != NativeFunctions.ERROR_MORE_DATA)
                    NativeException.ThrowNativeException(last_error, Environment.StackTrace);

                buffer = Marshal.AllocHGlobal((int)bytes_needed);
                try
                {
                    if (!NativeFunctions.EnumDependentServices(h_service, SERVICE_ENUM_STATE.SERVICE_STATE_ALL, buffer, bytes_needed, out bytes_needed, out services_returned))
                        NativeException.ThrowNativeException(Marshal.GetLastWin32Error(), Environment.StackTrace);

                    int unit_size = Marshal.SizeOf(typeof(ENUM_SERVICE_STATUS));
                    for (int i = 0; i < services_returned; i++)
                        dependent_services.Add(new ServiceDependentInformation((ENUM_SERVICE_STATUS)Marshal.PtrToStructure((IntPtr)(buffer.ToInt64() + (unit_size * i)), typeof(ENUM_SERVICE_STATUS))));
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }

            return dependent_services;
        }

        /// <summary>
        /// This method attempts to stop all dependent services.
        /// </summary>
        /// <param name="h_service"></param>
        /// <param name="wait_stop_timeout"></param>
        /// <exception cref="TimeoutException"></exception>
        private void StopDependentServices(ref ServiceSafeHandle h_service, uint wait_stop_timeout)
        {
            IntPtr buffer = IntPtr.Zero;

            // If the call succeeds with no buffer, the service has no dependents.
            if (NativeFunctions.EnumDependentServices(h_service, SERVICE_ENUM_STATE.SERVICE_ACTIVE, buffer, 0, out uint bytes_needed, out _))
                return;

            else
            {
                int last_error = Marshal.GetLastWin32Error();
                if (last_error != NativeFunctions.ERROR_MORE_DATA)
                    NativeException.ThrowNativeException(last_error, Environment.StackTrace);

                buffer = Marshal.AllocHGlobal((int)bytes_needed);
                try
                {
                    if (!NativeFunctions.EnumDependentServices(h_service, SERVICE_ENUM_STATE.SERVICE_ACTIVE, buffer, bytes_needed, out bytes_needed, out uint services_returned))
                        NativeException.ThrowNativeException(Marshal.GetLastWin32Error(), Environment.StackTrace);

                    int unit_size = Marshal.SizeOf(typeof(ENUM_SERVICE_STATUS));
                    using ServiceControlManager scm = new();
                    for (int i = 0; i < services_returned; i++)
                    {
                        // You cannot do 'pointer arithmetic' with IntPtr, we cast it to a long.
                        ENUM_SERVICE_STATUS dep_info = (ENUM_SERVICE_STATUS)Marshal.PtrToStructure((IntPtr)(buffer.ToInt64() + (unit_size * i)), typeof(ENUM_SERVICE_STATUS));
                        using ServiceSafeHandle h_dep_svc = scm.GetServiceSafeHandle(dep_info.lpServiceName, SERVICE_SECURITY.SERVICE_QUERY_CONFIG | SERVICE_SECURITY.SERVICE_STOP);

                        SERVICE_STATUS dep_stat = new();
                        if (!NativeFunctions.ControlService(h_dep_svc, SERVICE_CONTROL.SERVICE_CONTROL_STOP, ref dep_stat))
                            NativeException.ThrowNativeException(Marshal.GetLastWin32Error(), Environment.StackTrace);

                        // Waiting the service to stop.
                        Stopwatch sw = Stopwatch.StartNew();
                        while (dep_stat.dwCurrentState != ServiceStatus.Stopped)
                        {
                            uint wait_time = dep_stat.dwWaitHint / 10;
                            if (wait_time < 1000)
                                wait_time = 1000;
                            if (wait_time > 10000)
                                wait_time = 10000;

                            Thread.Sleep((int)wait_time);

                            if (sw.Elapsed.TotalSeconds > wait_stop_timeout)
                                throw new TimeoutException("Timed out waiting for the service to stop.");

                            if (!NativeFunctions.QueryServiceStatus(h_dep_svc, out dep_stat))
                                NativeException.ThrowNativeException(Marshal.GetLastWin32Error(), Environment.StackTrace);
                        }
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
        }

        private QUERY_SERVICE_CONFIG QueryServiceConfigInternal(ServiceSafeHandle h_service)
        {
            IntPtr buffer = IntPtr.Zero;
            QUERY_SERVICE_CONFIG svc_config;
            if (!NativeFunctions.QueryServiceConfig(h_service, buffer, 0, out uint bytes_needed))
            {
                int last_error = Marshal.GetLastWin32Error();
                if (last_error != NativeFunctions.ERROR_INSUFFICIENT_BUFFER)
                    NativeException.ThrowNativeException(last_error, Environment.StackTrace);
            }

            buffer = Marshal.AllocHGlobal((int)bytes_needed);
            try
            {
                if (!NativeFunctions.QueryServiceConfig(h_service, buffer, bytes_needed, out bytes_needed))
                    NativeException.ThrowNativeException(Marshal.GetLastWin32Error(), Environment.StackTrace);

                svc_config = (QUERY_SERVICE_CONFIG)Marshal.PtrToStructure(buffer, typeof(QUERY_SERVICE_CONFIG));
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }

            return svc_config;
        }
    }
}