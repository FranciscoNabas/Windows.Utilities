using System;
using System.Linq;
using System.Runtime.InteropServices;

namespace Windows.Utilities
{
    internal partial class NativeFunctions
    {
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
        public static extern IntPtr OpenSCManager(
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
        public static extern IntPtr OpenService(
            IntPtr hSCManager,
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
            IntPtr hService,
            AccessControl.SECURITY_INFORMATION dwSecurityInformation,
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
            IntPtr hService,
            AccessControl.SECURITY_INFORMATION dwSecurityInformation,
            IntPtr lpSecurityDescriptor
        );

        /// <summary>
        /// Closes a handle to a service control manager or service object.
        /// 
        /// Minimum supported client: Windows XP [desktop apps only]
        /// Minimum supported server: Windows Server 2003 [desktop apps only]
        /// Header: winsvc.h (include Windows.h)
        /// 
        /// P/Invoke: https://www.pinvoke.net/default.aspx/advapi32.closeservicehandle
        /// Documentation: https://learn.microsoft.com/windows/win32/api/winsvc/nf-winsvc-closeservicehandle
        /// </summary>
        [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CloseServiceHandle(IntPtr hSCObject);
    }

    public class Services
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
        public sealed class SC_MANAGER_SECURITY : Enumeration
        {
            public static SC_MANAGER_SECURITY SC_MANAGER_CONNECT = new(0x0001, "SC_MANAGER_CONNECT");
            public static SC_MANAGER_SECURITY SC_MANAGER_CREATE_SERVICE = new(0x0002, "SC_MANAGER_CREATE_SERVICE");
            public static SC_MANAGER_SECURITY SC_MANAGER_ENUMERATE_SERVICE = new(0x0004, "SC_MANAGER_ENUMERATE_SERVICE");
            public static SC_MANAGER_SECURITY SC_MANAGER_LOCK = new(0x0008, "SC_MANAGER_LOCK");
            public static SC_MANAGER_SECURITY SC_MANAGER_QUERY_LOCK_STATUS = new(0x0010, "SC_MANAGER_QUERY_LOCK_STATUS");
            public static SC_MANAGER_SECURITY SC_MANAGER_MODIFY_BOOT_CONFIG = new(0x0020, "SC_MANAGER_MODIFY_BOOT_CONFIG");
            public static SC_MANAGER_SECURITY SC_MANAGER_ALL_ACCESS = new(0xF003F, "SC_MANAGER_ALL_ACCESS");

            public static implicit operator SC_MANAGER_SECURITY(uint id) => GetAll<SC_MANAGER_SECURITY>().First(f => f.Id == id);
            private SC_MANAGER_SECURITY(uint id, string name) : base(id, name) { }
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
        public sealed class SERVICE_SECURITY : Enumeration
        {
            public static SERVICE_SECURITY SERVICE_QUERY_CONFIG = new(0x0001, "SERVICE_QUERY_CONFIG");
            public static SERVICE_SECURITY SERVICE_CHANGE_CONFIG = new(0x0002, "SERVICE_CHANGE_CONFIG");
            public static SERVICE_SECURITY SERVICE_QUERY_STATUS = new(0x0004, "SERVICE_QUERY_STATUS");
            public static SERVICE_SECURITY SERVICE_ENUMERATE_DEPENDENTS = new(0x0008, "SERVICE_ENUMERATE_DEPENDENTS");
            public static SERVICE_SECURITY SERVICE_START = new(0x0010, "SERVICE_START");
            public static SERVICE_SECURITY SERVICE_STOP = new(0x0020, "SERVICE_STOP");
            public static SERVICE_SECURITY SERVICE_PAUSE_CONTINUE = new(0x0040, "SERVICE_PAUSE_CONTINUE");
            public static SERVICE_SECURITY SERVICE_INTERROGATE = new(0x0080, "SERVICE_INTERROGATE");
            public static SERVICE_SECURITY SERVICE_USER_DEFINED_CONTROL = new(0x0100, "SERVICE_USER_DEFINED_CONTROL");
            public static SERVICE_SECURITY SERVICE_ALL_ACCESS = new(0xF01FF, "SERVICE_ALL_ACCESS");

            public static implicit operator SERVICE_SECURITY(uint id) => GetAll<SERVICE_SECURITY>().First(f => f.Id == id);
            private SERVICE_SECURITY(uint id, string name) : base(id, name) { }
        }
        #endregion
    }
}
