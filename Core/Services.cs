using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

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
        GENERIC_READ = AccessControl.ACCESS_TYPE.STANDARD_RIGHTS_READ |
                       SC_MANAGER_ENUMERATE_SERVICE |
                       SC_MANAGER_QUERY_LOCK_STATUS,

        GENERIC_WRITE = AccessControl.ACCESS_TYPE.STANDARD_RIGHTS_WRITE |
                        SC_MANAGER_CREATE_SERVICE |
                        SC_MANAGER_MODIFY_BOOT_CONFIG,

        GENERIC_EXECUTE = AccessControl.ACCESS_TYPE.STANDARD_RIGHTS_EXECUTE |
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
        ACCESS_SYSTEM_SECURITY = AccessControl.ACCESS_TYPE.ACCESS_SYSTEM_SECURITY,
        DELETE = 0x10000,
        READ_CONTROL = 0x20000,
        WRITE_DAC = 0x40000,
        WRITE_OWNER = 0x80000,
        GENERIC_READ = AccessControl.ACCESS_TYPE.STANDARD_RIGHTS_READ |
                       SERVICE_QUERY_CONFIG |
                       SERVICE_QUERY_STATUS |
                       SERVICE_INTERROGATE |
                       SERVICE_ENUMERATE_DEPENDENTS,

        GENERIC_WRITE = AccessControl.ACCESS_TYPE.STANDARD_RIGHTS_WRITE | SERVICE_CHANGE_CONFIG,
        GENERIC_EXECUTE = AccessControl.ACCESS_TYPE.STANDARD_RIGHTS_EXECUTE |
                          SERVICE_START |
                          SERVICE_STOP |
                          SERVICE_PAUSE_CONTINUE |
                          SERVICE_USER_DEFINED_CONTROL
    }

    /// <summary>
    /// 'System.ServiceProcess.ServiceStartMode' does not contains a definition for 'AutomaticDelayedStart'.
    /// Mimicing 'Microsoft.PowerShell.Commands.ServiceStartupType', we add 'AutomaticDelayedStart', and the methods to get it.
    /// </summary>
    public enum ServiceStartupType : uint
    {
        Boot = 0x00000000,
        System = 0x00000001,
        Automatic = 0x00000002,
        Manual = 0x00000003,
        Disabled = 0x00000004,
        AutomaticDelayedStart = 0x00001000
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
    internal struct QUERY_SERVICE_CONFIGW
    {
        internal ServiceType dwServiceType;
        internal uint dwStartType;
        internal uint dwErrorControl;
        internal string lpBinaryPathName;
        internal string lpLoadOrderGroup;
        internal uint dwTagId;
        internal string lpDependencies;
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
        public static extern SystemSafeHandle OpenSCManager(
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
        public static extern SystemSafeHandle OpenService(
            SystemSafeHandle hSCManager,
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
            SystemSafeHandle hService,
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
            SystemSafeHandle hService,
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
            SystemSafeHandle hService,
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
        internal static extern bool QueryServiceconfig(
            SystemSafeHandle hService,
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
        internal static extern bool QueryServiceStatus(SystemSafeHandle hService, out SERVICE_STATUS lpServiceStatus);

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
        public static extern bool QueryServiceConfig2(
            SystemSafeHandle hService,
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
            SystemSafeHandle hService, uint dwServiceType, uint dwStartType, uint dwErrorControl,
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
            SystemSafeHandle hService,
            uint dwNumServiceArgs,
            string[] lpServiceArgVectors
        );

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
        internal SystemSafeHandle? ScmHandle
        {
            get { return _scm_handle; }
        }
        internal List<SC_MANAGER_SECURITY> ScmPrivilegeList
        {
            get { return _scm_priv_list; }
        }

        private enum ServiceHandleType
        {
            ServiceControlManager,
            Service
        }

        private SystemSafeHandle? _scm_handle;
        private readonly List<SC_MANAGER_SECURITY> _scm_priv_list;
        private static ServiceControlManager? _instance;

        private ServiceControlManager() => _scm_priv_list = new();

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
            if (_instance is not null)
            {
                if (disposing)
                    _instance.ScmHandle?.Dispose();
            }
        }

        /// <summary>
        /// Returns a safe handle to a service.
        /// </summary>
        /// <param name="service_name">The service name.</param>
        /// <returns>Windows.Utilities.SystemSafeHandle</returns>
        internal static SystemSafeHandle GetServiceSafeHandle(string service_name) =>
            GetServiceSafeHandleWithSecurity(service_name,
                new List<SC_MANAGER_SECURITY>() { SC_MANAGER_SECURITY.SC_MANAGER_CONNECT },
                new List<SERVICE_SECURITY>() { SERVICE_SECURITY.GENERIC_READ });

        /// <summary>
        /// Returns a safe handle to a service.
        /// </summary>
        /// <param name="service_name">The service name.</param>
        /// <param name="desired_access">Desired service access.</param>
        /// <returns>Windows.Utilities.SystemSafeHandle</returns>
        internal static SystemSafeHandle GetServiceSafeHandle(string service_name, List<SERVICE_SECURITY> desired_access) =>
            GetServiceSafeHandleWithSecurity(service_name, new List<SC_MANAGER_SECURITY>() { SC_MANAGER_SECURITY.SC_MANAGER_CONNECT }, desired_access);

        /// <summary>
        /// Returns a safe handle to a service.
        /// </summary>
        /// <param name="service_name">The service name.</param>
        /// <param name="scm_access">Desired service control manager access.</param>
        /// <param name="svc_access">Desired service access.</param>
        /// <returns>Windows.Utilities.SystemSafeHandle</returns>
        internal static SystemSafeHandle GetServiceSafeHandle(string service_name, List<SC_MANAGER_SECURITY> scm_access, List<SERVICE_SECURITY> svc_access) =>
            GetServiceSafeHandleWithSecurity(service_name, scm_access, svc_access);

        /// <summary>
        /// Returns a safe system handle for the given service name.
        /// This method manages the handle to the service control manager, and checks
        /// if a handle for that service is already opened.
        /// </summary>
        /// <param name="service_name">The service name.</param>
        /// <param name="scm_access">Desired service control manager access.</param>
        /// <param name="svc_access">Desired service access.</param>
        /// <returns>Windows.Utilities.SystemSafeHandle</returns>
        private static SystemSafeHandle GetServiceSafeHandleWithSecurity(string service_name, List<SC_MANAGER_SECURITY> scm_access, List<SERVICE_SECURITY> svc_access)
        {
            _instance ??= new();

            // bit-wise ORing all itens in the access lists.
            SC_MANAGER_SECURITY scm_sec = 0;
            scm_access.ForEach(f => scm_sec |= f);

            SERVICE_SECURITY svc_sec = 0;
            svc_access.ForEach(f => svc_sec |= f);

            _instance._scm_handle = null == _instance._scm_handle ? _instance.OpenHandleWithCheck(ServiceHandleType.ServiceControlManager, scm_sec, svc_sec, null) :
                    _instance._scm_handle.IsInvalid || _instance._scm_handle.IsClosed ? _instance.OpenHandleWithCheck(ServiceHandleType.ServiceControlManager, scm_sec, svc_sec, null) : _instance._scm_handle;

            return _instance.OpenHandleWithCheck(ServiceHandleType.Service, scm_sec, svc_sec, service_name);
        }

        /// <summary>
        /// This method opens the handle by calling the native functions.
        /// It's called by the 'OpenHandleWithCheck()' overloads.
        /// </summary>
        /// <param name="handle_type">Handle type to be opened. Service or SCM.</param>
        /// <param name="scm_desired_access">Desired service control manager access.</param>
        /// <param name="service_desired_access">Desired service access.</param>
        /// <param name="service_name">The service name.</param>
        /// <returns>Windows.Utilities.SystemSafeHandle</returns>
        /// <exception cref="ArgumentNullException">Instance not initialized correctly.</exception>
        /// <exception cref="ArgumentException">Service control manager handle provided is invalid.</exception>
        /// <exception cref="NativeException">Native function call failed.</exception>
        private SystemSafeHandle OpenHandleWithCheck(ServiceHandleType handle_type, SC_MANAGER_SECURITY scm_desired_access, SERVICE_SECURITY service_desired_access, string? service_name)
        {
            SystemSafeHandle? safe_handle = null;
            if (_instance is null)
                throw new ArgumentNullException();

            switch (handle_type)
            {
                case ServiceHandleType.Service:
                    if (null == service_name)
                        throw new ArgumentNullException("Service name cannot be null.");

                    if (null == _instance._scm_handle || _instance._scm_handle.IsClosed || _instance._scm_handle.IsInvalid)
                        throw new ArgumentException("Invalid service control manager handle.");

                    safe_handle = NativeFunctions.OpenService(_instance._scm_handle, service_name, service_desired_access);
                    if (safe_handle.IsInvalid)
                        NativeException.ThrowNativeException(Marshal.GetLastWin32Error(), Environment.StackTrace);
                    break;
                case ServiceHandleType.ServiceControlManager:
                    safe_handle = NativeFunctions.OpenSCManager(".", "ServicesActive", scm_desired_access);
                    if (safe_handle.IsInvalid)
                        NativeException.ThrowNativeException(Marshal.GetLastWin32Error(), Environment.StackTrace);
                    break;
            }

            if (safe_handle is null)
                throw new ArgumentNullException("Unable to open handle to service control manager object.");

            return safe_handle;
        }
    }

    /// <summary>
    /// This is the main API exposed externally.
    /// Design to manage service control manager objects.
    /// </summary>
    public sealed class Service : IDisposable
    {

        public string Name { get { return _service_name; } }
        public string DisplayName { get { return _display_name; } }
        public string StartAccount { get { return _start_name; } }
        public ServiceStatus Status { get { return _status; } }
        public ServiceStartupType StartupType { get { return _startup_type; } }
        public string BynaryPath { get { return _bin_path; } }

        private readonly string _service_name;
        private readonly string _display_name;
        private readonly string _start_name;
        private readonly string _bin_path;
        private ServiceStatus _status;
        private ServiceStartupType _startup_type;
        private SystemSafeHandle _h_service;
        private List<SERVICE_SECURITY> _service_priv_list;

        public Service(string service_name)
        {
            _service_priv_list = new() { SERVICE_SECURITY.GENERIC_READ };
            _service_name = service_name;
            _h_service = ServiceControlManager.GetServiceSafeHandle(service_name);
            QUERY_SERVICE_CONFIGW svc_config;

            IntPtr buffer = IntPtr.Zero;
            if (!NativeFunctions.QueryServiceconfig(_h_service, buffer, 0, out uint bytes_needed))
            {
                int last_error = Marshal.GetLastWin32Error();
                if (last_error != NativeFunctions.ERROR_INSUFFICIENT_BUFFER)
                    NativeException.ThrowNativeException(last_error, Environment.StackTrace);
            }
            try
            {
                buffer = Marshal.AllocHGlobal((int)bytes_needed);
                if (!NativeFunctions.QueryServiceconfig(_h_service, buffer, bytes_needed, out bytes_needed))
                    NativeException.ThrowNativeException(Marshal.GetLastWin32Error(), Environment.StackTrace);

                svc_config = (QUERY_SERVICE_CONFIGW)Marshal.PtrToStructure(buffer, typeof(QUERY_SERVICE_CONFIGW));
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }

            switch (svc_config.dwStartType)
            {
                case 0x00000002:
                    if (IsServiceDelayedStart())
                        _startup_type = ServiceStartupType.AutomaticDelayedStart;
                    break;
                
                default:
                    _startup_type = (ServiceStartupType)svc_config.dwStartType;
                    break;
            }

            if (!NativeFunctions.QueryServiceStatus(_h_service, out SERVICE_STATUS status))
                NativeException.ThrowNativeException(Marshal.GetLastWin32Error(), Environment.StackTrace);

            _status = status.dwCurrentState;
            _display_name = svc_config.lpDisplayName;
            _start_name = svc_config.lpServiceStartName;
            _bin_path = svc_config.lpBinaryPathName;
        }

        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        private void Dispose(bool disposing)
        {
            if (disposing)
                _h_service.Dispose();
        }

        /// <summary>
        /// This method sets a service who the given service depends on.
        /// TODO: Set lists of services.
        /// </summary>
        /// <param name="service_name">The service name to change the config.</param>
        /// <param name="service_depended_on">The service name to include in the dependency list.</param>
        /// <exception cref="ArgumentException">Service dependency cannot be null or empty.</exception>
        /// <exception cref="NativeException">Native function call failed.</exception>
        public void SetServiceDependency(string service_name, string service_depended_on)
        {
            if (string.IsNullOrEmpty(service_depended_on))
                throw new ArgumentException("The service dependency cannot be null or empty.");

            SystemSafeHandle h_service = ServiceControlManager.GetServiceSafeHandle(service_name);
            if (!NativeFunctions.ChangeServiceConfig(h_service, NativeFunctions.SERVICE_NO_CHANGE, NativeFunctions.SERVICE_NO_CHANGE, NativeFunctions.SERVICE_NO_CHANGE, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, service_depended_on, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero))
                NativeException.ThrowNativeException(Marshal.GetLastWin32Error(), Environment.StackTrace);
        }

        /// <summary>
        /// This method returns true if the service is set to Automatic with Delayed Start.
        /// TODO: Convert to 'GetServiceStartupType(string service_name)'.
        /// </summary>
        /// <param name="service_name">The service name.</param>
        /// <returns>System.Bool</returns>
        /// <exception cref="NativeException">Native function call failed.</exception>
        internal bool IsServiceDelayedStart()
        {
            bool is_delayed_start = false;
            IntPtr buffer = IntPtr.Zero;
            try
            {
                // Getting buffer size.
                if (!NativeFunctions.QueryServiceConfig2(_h_service, 3, IntPtr.Zero, 0, out uint bytes_needed))
                {
                    int last_error = Marshal.GetLastWin32Error();
                    if (last_error != NativeFunctions.ERROR_INSUFFICIENT_BUFFER)
                        NativeException.ThrowNativeException(Marshal.GetLastWin32Error(), Environment.StackTrace);
                }

                buffer = Marshal.AllocHGlobal((int)bytes_needed);

                if (!NativeFunctions.QueryServiceConfig2(_h_service, 3, buffer, bytes_needed, out bytes_needed)) // 3: SERVICE_CONFIG_DELAYED_AUTO_START_INFO.
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
        public void SetServiceStartType(string service_name, ServiceStartupType startup_type)
        {
            bool set_auto_delayed = false;
            uint op_code;

            SystemSafeHandle h_service = ServiceControlManager.GetServiceSafeHandle(service_name);

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
                IntPtr buffer = IntPtr.Zero;
                try
                {
                    buffer = Marshal.AllocHGlobal(Marshal.SizeOf(svc_del_auto_start_info));
                    Marshal.StructureToPtr(svc_del_auto_start_info, buffer, false);

                    if (!NativeFunctions.ChangeServiceConfig2(h_service, 3, buffer)) // 3: SERVICE_CONFIG_DELAYED_AUTO_START_INFO.
                        NativeException.ThrowNativeException(Marshal.GetLastWin32Error(), Environment.StackTrace);
                }
                finally { Marshal.FreeHGlobal(buffer); }
            }
        }

        /// <summary>
        /// This method starts a service by name.
        /// We call it here so we can wrap native exceptions.
        /// </summary>
        /// <param name="service_name">The service name.</param>
        /// <exception cref="NativeException">Native function call failed.</exception>
        public void StartService(string service_name)
        {
            SystemSafeHandle h_service = ServiceControlManager.GetServiceSafeHandle(service_name, new List<SERVICE_SECURITY>() { SERVICE_SECURITY.SERVICE_START });
            if (!NativeFunctions.StartService(h_service, 0, new string[] { }))
                NativeException.ThrowNativeException(Marshal.GetLastWin32Error(), Environment.StackTrace);
        }
    }
}
