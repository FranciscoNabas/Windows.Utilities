using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace Windows.Utilities
{
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
            Services.SC_MANAGER_SECURITY dwDesiredAccess
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
            Services.SERVICE_SECURITY dwDesiredAccess
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
        private enum ServiceHandleType
        {
            ServiceControlManager,
            Service
        }

        private SystemSafeHandle? _scm_handle;
        private readonly Dictionary<string, SystemSafeHandle> _service_handle_list;
        private static ServiceControlManager? _instance;

        private ServiceControlManager() => _service_handle_list = new();

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
        /// <param name="disposing"></param>
        internal static void Dispose(bool disposing)
        {
            if (_instance is not null)
            {
                if (disposing)
                    foreach (KeyValuePair<string, SystemSafeHandle> safe_handle in _instance._service_handle_list)
                    {
                        if (!safe_handle.Value.IsInvalid && !safe_handle.Value.IsClosed)
                            safe_handle.Value.Dispose();
                    }
                if (null != _instance._scm_handle && !_instance._scm_handle.IsInvalid && !_instance._scm_handle.IsClosed)
                    _instance._scm_handle.Dispose();
            }
        }

        /// <summary>
        /// Returns a safe system handle for the given service name.
        /// This method manages the handle to the service control manager, and checks
        /// if a handle for that service is already opened.
        /// </summary>
        /// <param name="service_name"></param>
        /// <returns></returns>
        internal static SystemSafeHandle GetServiceSafeHandle(string service_name)
        {
            _instance ??= new();
            if (!_instance._service_handle_list.TryGetValue(service_name, out SystemSafeHandle service_handle))
            {
                _instance._scm_handle = null == _instance._scm_handle ? _instance.OpenHandleWithCheck(ServiceHandleType.ServiceControlManager) :
                    _instance._scm_handle.IsInvalid || _instance._scm_handle.IsClosed ? _instance.OpenHandleWithCheck(ServiceHandleType.ServiceControlManager) : _instance._scm_handle;

                service_handle = _instance.OpenHandleWithCheck(ServiceHandleType.Service, service_name);

                _instance._service_handle_list.Add(service_name, service_handle);
            }
            else
            {
                if (service_handle.IsClosed || service_handle.IsInvalid)
                    service_handle = _instance.OpenHandleWithCheck(ServiceHandleType.Service, service_name);
            }

            return service_handle;
        }

        /// <summary>
        /// This method opens the handle by calling the native functions.
        /// It does the error handling for us.
        /// </summary>
        /// <param name="handle_type"></param>
        /// <param name="service_name"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="SystemException"></exception>
        private SystemSafeHandle OpenHandleWithCheck(ServiceHandleType handle_type, string? service_name = null)
        {
            SystemSafeHandle? safe_handle =  null;
            if (_instance is null)
                throw new ArgumentNullException();

            switch (handle_type)
            {
                case ServiceHandleType.Service:
                    if (null == service_name)
                        throw new ArgumentNullException("Service name cannot be null.");

                    if (null == _instance._scm_handle || _instance._scm_handle.IsClosed || _instance._scm_handle.IsInvalid)
                        throw new ArgumentException("Invalid service control manager handle.");

                    safe_handle = NativeFunctions.OpenService(_instance._scm_handle, service_name, Services.SERVICE_SECURITY.SERVICE_QUERY_CONFIG | Services.SERVICE_SECURITY.SERVICE_CHANGE_CONFIG);
                    if (safe_handle.IsInvalid)
                        throw new SystemException(Base.GetSystemErrorText(Marshal.GetLastWin32Error()));
                    break;
                case ServiceHandleType.ServiceControlManager:
                    safe_handle = NativeFunctions.OpenSCManager(".", "ServicesActive", Services.SC_MANAGER_SECURITY.SC_MANAGER_CONNECT);
                    if (safe_handle.IsInvalid)
                        throw new SystemException(Base.GetSystemErrorText(Marshal.GetLastWin32Error()));
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
    public sealed class Services : IDisposable
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
        public enum SC_MANAGER_SECURITY : uint
        {
            SC_MANAGER_CONNECT = 0x0001,
            SC_MANAGER_CREATE_SERVICE = 0x0002,
            SC_MANAGER_ENUMERATE_SERVICE = 0x0004,
            SC_MANAGER_LOCK = 0x0008,
            SC_MANAGER_QUERY_LOCK_STATUS = 0x0010,
            SC_MANAGER_MODIFY_BOOT_CONFIG = 0x0020,
            SC_MANAGER_ALL_ACCESS = 0xF003F
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
        public enum SERVICE_SECURITY : uint
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
            SERVICE_ALL_ACCESS = 0xF01FF
        }

        /// <summary>
        /// 'System.ServiceProcess.ServiceStartMode' does not contains a definition for 'AutomaticDelayedStart'.
        /// Mimicing 'Microsoft.PowerShell.Commands.ServiceStartupType', we add 'AutomaticDelayedStart', and the methods to get it.
        /// </summary>
        public enum ServiceStartupType : uint
        {
            Automatic,
            Manual,
            Disabled,
            AutomaticDelayedStart
        }
        #endregion

        #region Structures

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

        public Services() { }

        public void Dispose() => ServiceControlManager.Dispose(disposing: true);

        /// <summary>
        /// This method sets a service who the given service depends on.
        /// TODO: Set lists of services.
        /// </summary>
        /// <param name="service_name"></param>
        /// <param name="service_depended_on"></param>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="SystemException"></exception>
        public void SetServiceDependency(string service_name, string service_depended_on)
        {
            if (string.IsNullOrEmpty(service_depended_on))
                throw new ArgumentException("The service dependency cannot be null or empty.");

            SystemSafeHandle h_service = ServiceControlManager.GetServiceSafeHandle(service_name);
            if (!NativeFunctions.ChangeServiceConfig(h_service, NativeFunctions.SERVICE_NO_CHANGE, NativeFunctions.SERVICE_NO_CHANGE, NativeFunctions.SERVICE_NO_CHANGE, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, service_depended_on, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero))
                throw new SystemException(Base.GetSystemErrorText(Marshal.GetLastWin32Error()));
        }

        /// <summary>
        /// This method returns true if the service is set to Automatic with Delayed Start.
        /// TODO: Convert to 'GetServiceStartupType(string service_name)'.
        /// </summary>
        /// <param name="service_name"></param>
        /// <returns></returns>
        /// <exception cref="SystemException"></exception>
        public bool IsServiceDelayedStart(string service_name)
        {
            bool is_delayed_start = false;
            SystemSafeHandle h_service = ServiceControlManager.GetServiceSafeHandle(service_name);
            IntPtr buffer = IntPtr.Zero;
            try
            {
                // Getting buffer size.
                if (!NativeFunctions.QueryServiceConfig2(h_service, 3, IntPtr.Zero, 0, out uint bytes_needed))
                {
                    int last_error = Marshal.GetLastWin32Error();
                    if (last_error != NativeFunctions.ERROR_INSUFFICIENT_BUFFER)
                        throw new SystemException(Base.GetSystemErrorText(last_error));
                }

                buffer = Marshal.AllocHGlobal((int)bytes_needed);

                if (!NativeFunctions.QueryServiceConfig2(h_service, 3, buffer, bytes_needed, out bytes_needed)) // 3: SERVICE_CONFIG_DELAYED_AUTO_START_INFO.
                    throw new SystemException(Base.GetSystemErrorText(Marshal.GetLastWin32Error()));

                SERVICE_DELAYED_AUTO_START_INFO svc_del_auto_start_info = (SERVICE_DELAYED_AUTO_START_INFO)Marshal.PtrToStructure(buffer, typeof(SERVICE_DELAYED_AUTO_START_INFO));
                is_delayed_start = svc_del_auto_start_info.fDelayedAutostart;
            }
            finally { Marshal.FreeHGlobal(buffer); }

            return is_delayed_start;
        }

        /// <summary>
        /// This method sets the given service's startup type, including Automatic - Delayed Start.
        /// </summary>
        /// <param name="service_name"></param>
        /// <param name="startup_type"></param>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="SystemException"></exception>
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
                throw new SystemException(Base.GetSystemErrorText(Marshal.GetLastWin32Error()));

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
                        throw new SystemException(Base.GetSystemErrorText(Marshal.GetLastWin32Error()));
                }
                finally { Marshal.FreeHGlobal(buffer); }
            }
        }
    }
}
