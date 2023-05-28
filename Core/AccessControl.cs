using System;
using System.Linq;
using System.Diagnostics;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Windows.Utilities
{
    internal partial class NativeFunctions
    {
        // winnt.h
        internal static readonly uint SECURITY_DESCRIPTOR_REVISION = 1;

        // winnt.h
        // TODO: Turn into a 'text enumeration'.
        internal static readonly string SE_SECURITY_NAME = "SeSecurityPrivilege";
        internal static readonly string SE_DEBUG_NAME = "SeDebugPrivilege";

        /// <summary>
        /// The OpenProcessToken function opens the access token associated with a process.
        /// 
        /// Minimum supported client: Windows XP [desktop apps | UWP apps]
        /// Minimum supported server: Windows Windows Server 2003 [desktop apps | UWP apps]
        /// Header: processthreadsapi.h (include Windows.h)
        /// 
        /// P/Invoke: https://www.pinvoke.net/default.aspx/advapi32.openprocesstoken
        /// Documentation: https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken
        /// </summary>
        [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern bool OpenProcessToken(
            SystemSafeHandle ProcessHandle,
            uint DesiredAccess,
            out SystemSafeHandle pHandle
        );

        /// <summary>
        /// The LookupPrivilegeValue function retrieves the locally unique identifier (LUID)
        /// used on a specified system to locally represent the specified privilege name.
        /// 
        /// Minimum supported client: Windows XP [desktop apps | UWP apps]
        /// Minimum supported server: Windows Windows Server 2003 [desktop apps | UWP apps]
        /// Header: winbase.h (include Windows.h)
        /// 
        /// P/Invoke: https://www.pinvoke.net/default.aspx/advapi32.lookupprivilegevalue
        /// Documentation: https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-lookupprivilegevaluew
        /// </summary>
        [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "LookupPrivilegeValueW")]
        public static extern bool LookupPrivilegeValue(
            string lpSystemName,
            string lpName,
            ref AccessControl.LUID lpLuid
        );

        /// <summary>
        /// The AdjustTokenPrivileges function enables or disables privileges in the specified access token.
        /// Enabling or disabling privileges in an access token requires TOKEN_ADJUST_PRIVILEGES access.
        /// 
        /// Minimum supported client: Windows XP [desktop apps | UWP apps]
        /// Minimum supported server: Windows Windows Server 2003 [desktop apps | UWP apps]
        /// Header: securitybaseapi.h (include Windows.h)
        /// 
        /// P/Invoke: https://www.pinvoke.net/default.aspx/advapi32.adjusttokenprivileges
        /// Documentation: https://learn.microsoft.com/en-us/windows/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges
        /// </summary>
        [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool AdjustTokenPrivileges(
            SystemSafeHandle TokenHandle,
            [MarshalAs(UnmanagedType.Bool)] bool DisableAllPrivileges,
            ref AccessControl.TOKEN_PRIVILEGES NewState,
            uint Zero,
            IntPtr Null1,
            IntPtr Null2
        );

        /// <summary>
        /// The BuildExplicitAccessWithName function initializes an EXPLICIT_ACCESS structure with data specified by the caller.
        /// The trustee is identified by a name string.
        /// 
        /// Minimum supported client: Windows XP [desktop apps only]
        /// Minimum supported server: Windows Server 2003 [desktop apps only]
        /// Header: aclapi.h
        /// 
        /// P/Invoke: https://www.pinvoke.net/default.aspx/advapi32.buildexplicitaccesswithname
        /// Documentation: https://learn.microsoft.com/windows/win32/api/aclapi/nf-aclapi-buildexplicitaccesswithnamew
        /// </summary>
        [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "BuildExplicitAccessWithNameW")]
        public static extern void BuildExplicitAccessWithName(
            ref AccessControl.EXPLICIT_ACCESS_W pExplicitAccess,
            string pTrusteeName,
            uint AccessMode,
            uint Inheritance
        );

        /// <summary>
        /// The SetEntriesInAcl function creates a new access control list (ACL) by merging new access control
        /// or audit control information into an existing ACL structure.
        /// 
        /// Minimum supported client: Windows XP [desktop apps | UWP apps]
        /// Minimum supported server: Windows Server 2003 [desktop apps | UWP apps]
        /// Header: aclapi.h
        /// 
        /// P/Invoke: https://www.pinvoke.net/default.aspx/advapi32.setentriesinacl
        /// Documentation: https://learn.microsoft.com/windows/win32/api/aclapi/nf-aclapi-setentriesinaclw
        /// </summary>
        [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "SetEntriesInAclW")]
        public static extern uint SetEntriesInAcl(
            uint cCountOfExplicitEntries,
            ref AccessControl.EXPLICIT_ACCESS_W pListOfExplicitEntries,
            AccessControl.ACL OldAcl,
            out AccessControl.ACL NewAcl
        );

        /// <summary>
        /// The SetSecurityDescriptorDacl function sets information in a discretionary access control list (DACL).
        /// If a DACL is already present in the security descriptor, the DACL is replaced.
        /// 
        /// Minimum supported client: Windows XP [desktop apps | UWP apps]
        /// Minimum supported server: Windows Server 2003 [desktop apps | UWP apps]
        /// Header: securitybaseapi.h (include Windows.h)
        /// 
        /// P/Invoke: https://www.pinvoke.net/default.aspx/advapi32.setsecuritydescriptordacl
        /// Documentation: https://learn.microsoft.com/windows/win32/api/securitybaseapi/nf-securitybaseapi-setsecuritydescriptordacl
        /// </summary>
        [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool SetSecurityDescriptorDacl(
            ref AccessControl.SECURITY_DESCRIPTOR pSecurityDescriptor,
            bool bDaclPresent,
            AccessControl.ACL pDacl,
            bool bDaclDefaulted
        );

        /// <summary>
        /// The InitializeSecurityDescriptor function initializes a new security descriptor
        /// 
        /// Minimum supported client: Windows XP [desktop apps | UWP apps]
        /// Minimum supported server: Windows Server 2003 [desktop apps | UWP apps]
        /// Header: securitybaseapi.h (include Windows.h)
        /// 
        /// P/Invoke: https://www.pinvoke.net/default.aspx/advapi32.initializesecuritydescriptor
        /// Documentation: https://learn.microsoft.com/windows/win32/api/securitybaseapi/nf-securitybaseapi-initializesecuritydescriptor
        /// </summary>
        [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool InitializeSecurityDescriptor(out AccessControl.SECURITY_DESCRIPTOR pSecurityDescriptor, uint dwRevision);
    }

    /// <summary>
    /// This class manages access token handles internally.
    /// </summary>
    internal sealed class AccessControlManager : IDisposable
    {
        private readonly Dictionary<uint, SystemSafeHandle> _process_token_list;
        private static AccessControlManager? _instance;

        private AccessControlManager() => _process_token_list = new();

        /// <summary>
        /// Included to satisfy the IDisposable inheritance.
        /// </summary>
        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Disposes of all unmanaged resources.
        /// </summary>
        /// <param name="disposing"></param>
        internal static void Dispose(bool disposing)
        {
            if (_instance is not null)
            {
                if (disposing)
                    foreach (KeyValuePair<uint, SystemSafeHandle> safe_handle in _instance._process_token_list)
                    {
                        if (!safe_handle.Value.IsInvalid && !safe_handle.Value.IsClosed)
                            safe_handle.Value.Dispose();
                    }
            }
        }

        ///// <summary>
        ///// This method opens a safe handle to a process token with the desired access.
        ///// </summary>
        ///// <param name="process_id"></param>
        ///// <param name="desired_access"></param>
        ///// <returns></returns>
        //internal static SystemSafeHandle GetProcessTokenSafeHandle(uint process_id, AccessControl.TOKEN_ACCESS_RIGHT desired_access)
        //{
        //    _instance ??= new();
        //    if (!_instance._process_token_list.TryGetValue(process_id, out SystemSafeHandle token_handle))
        //    {
        //        token_handle = _instance.OpenHandleWithCheck(process_id, desired_access);

        //        _instance._process_token_list.Add(process_id, token_handle);
        //    }
        //    else
        //    {
        //        if (token_handle.IsClosed || token_handle.IsInvalid)
        //            token_handle = _instance.OpenHandleWithCheck(process_id, desired_access);
        //    }

        //    return token_handle;
        //}

        /// <summary>
        /// This method opens a safe handle to the current process token with the desired access.
        /// </summary>
        /// <param name="process_id"></param>
        /// <param name="desired_access"></param>
        /// <returns></returns>
        internal static SystemSafeHandle GetProcessTokenSafeHandle(AccessControl.TOKEN_ACCESS_RIGHT desired_access)
        {
            _instance ??= new();
            using Process current_process =  Process.GetCurrentProcess();
            if (!_instance._process_token_list.TryGetValue((uint)current_process.Id, out SystemSafeHandle token_handle))
            {
                token_handle = _instance.OpenHandleWithCheck(desired_access);

                _instance._process_token_list.Add((uint)current_process.Id, token_handle);
            }
            else
            {
                if (token_handle.IsClosed || token_handle.IsInvalid)
                    token_handle = _instance.OpenHandleWithCheck(desired_access);
            }

            return token_handle;
        }

        /// <summary>
        /// Used internally to open a safe token handle to the current process, with error handling.
        /// </summary>
        /// <param name="process_id"></param>
        /// <param name="desired_access"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="SystemException"></exception>
        private SystemSafeHandle OpenHandleWithCheck(AccessControl.TOKEN_ACCESS_RIGHT desired_access)
        {
            if (_instance is null)
                throw new ArgumentNullException();

            SystemSafeHandle current_process_handle = NativeFunctions.GetCurrentProcess();
            if (!NativeFunctions.OpenProcessToken(current_process_handle, desired_access, out SystemSafeHandle token_handle))
                throw new SystemException(Base.GetSystemErrorText(Marshal.GetLastWin32Error()));

            if (token_handle.IsInvalid)
                throw new SystemException(Base.GetSystemErrorText(Marshal.GetLastWin32Error()));

            return token_handle;
        }
    }

    /// <summary>
    /// This class is the main API for access control utilities.
    /// </summary>
    public class AccessControl : IDisposable
    {
        #region Enumerations

        /// <summary>
        /// The SECURITY_DESCRIPTOR_CONTROL data type is a set of bit flags that qualify the meaning of a security descriptor or its components.
        /// Each security descriptor has a Control member that stores the SECURITY_DESCRIPTOR_CONTROL bits.
        /// 
        /// Minimum supported client: Windows XP [desktop apps only]
        /// Minimum supported server: Windows Server 2003 [desktop apps only]
        /// Header: Winnt.h (include Windows.h)
        /// 
        /// Documentation: https://learn.microsoft.com/windows/win32/secauthz/security-descriptor-control
        /// </summary>
        public sealed class SECURITY_DESCRIPTOR_CONTROL : Enumeration
        {
            public static SECURITY_DESCRIPTOR_CONTROL SE_OWNER_DEFAULTED = new(0x0001, "SE_OWNER_DEFAULTED");
            public static SECURITY_DESCRIPTOR_CONTROL SE_GROUP_DEFAULTED = new(0x0002, "SE_GROUP_DEFAULTED");
            public static SECURITY_DESCRIPTOR_CONTROL SE_DACL_PRESENT = new(0x0004, "SE_DACL_PRESENT");
            public static SECURITY_DESCRIPTOR_CONTROL SE_DACL_DEFAULTED = new(0x0008, "SE_DACL_DEFAULTED");
            public static SECURITY_DESCRIPTOR_CONTROL SE_SACL_PRESENT = new(0x0010, "SE_SACL_PRESENT");
            public static SECURITY_DESCRIPTOR_CONTROL SE_DACL_AUTO_INHERIT_REQ = new(0x0100, "SE_DACL_AUTO_INHERIT_REQ");
            public static SECURITY_DESCRIPTOR_CONTROL SE_SACL_AUTO_INHERIT_REQ = new(0x0200, "SE_SACL_AUTO_INHERIT_REQ");
            public static SECURITY_DESCRIPTOR_CONTROL SE_DACL_AUTO_INHERITED = new(0x0400, "SE_DACL_AUTO_INHERITED");
            public static SECURITY_DESCRIPTOR_CONTROL SE_SACL_AUTO_INHERITED = new(0x0800, "SE_SACL_AUTO_INHERITED");
            public static SECURITY_DESCRIPTOR_CONTROL SE_DACL_PROTECTED = new(0x1000, "SE_DACL_PROTECTED");
            public static SECURITY_DESCRIPTOR_CONTROL SE_SACL_PROTECTED = new(0x2000, "SE_SACL_PROTECTED");
            public static SECURITY_DESCRIPTOR_CONTROL SE_RM_CONTROL_VALID = new(0x4000, "SE_RM_CONTROL_VALID");
            public static SECURITY_DESCRIPTOR_CONTROL SE_SELF_RELATIVE = new(0x8000, "SE_SELF_RELATIVE");

            public static implicit operator SECURITY_DESCRIPTOR_CONTROL(uint id) => GetAll<SECURITY_DESCRIPTOR_CONTROL>().Where(s => s.Id == id).FirstOrDefault();
            SECURITY_DESCRIPTOR_CONTROL(uint id, string name) : base(id, name) { }
        }

        /// <summary>
        /// The SECURITY_INFORMATION data type identifies the object-related security information being set or queried.
        /// 
        /// Minimum supported client: Windows XP [desktop apps only]
        /// Minimum supported server: Windows Server 2003 [desktop apps only]
        /// Header: Winnt.h (include Windows.h)
        /// 
        /// Documentation: https://learn.microsoft.com/windows/win32/secauthz/security-information
        /// </summary>
        public sealed class SECURITY_INFORMATION : Enumeration
        {
            public static SECURITY_INFORMATION OWNER_SECURITY_INFORMATION = new(0x00000001, "OWNER_SECURITY_INFORMATION");
            public static SECURITY_INFORMATION GROUP_SECURITY_INFORMATION = new(0x00000002, "GROUP_SECURITY_INFORMATION");
            public static SECURITY_INFORMATION DACL_SECURITY_INFORMATION = new(0x00000004, "DACL_SECURITY_INFORMATION");
            public static SECURITY_INFORMATION SACL_SECURITY_INFORMATION = new(0x00000008, "SACL_SECURITY_INFORMATION");
            public static SECURITY_INFORMATION LABEL_SECURITY_INFORMATION = new(0x00000010, "LABEL_SECURITY_INFORMATION");
            public static SECURITY_INFORMATION ATTRIBUTE_SECURITY_INFORMATION = new(0x00000020, "ATTRIBUTE_SECURITY_INFORMATION");
            public static SECURITY_INFORMATION SCOPE_SECURITY_INFORMATION = new(0x00000040, "SCOPE_SECURITY_INFORMATION");
            public static SECURITY_INFORMATION PROCESS_TRUST_LABEL_SECURITY_INFORMATION = new(0x00000080, "PROCESS_TRUST_LABEL_SECURITY_INFORMATION");
            public static SECURITY_INFORMATION ACCESS_FILTER_SECURITY_INFORMATION = new(0x00000100, "ACCESS_FILTER_SECURITY_INFORMATION");
            public static SECURITY_INFORMATION BACKUP_SECURITY_INFORMATION = new(0x00010000, "BACKUP_SECURITY_INFORMATION");
            public static SECURITY_INFORMATION PROTECTED_DACL_SECURITY_INFORMATION = new(0x80000000, "PROTECTED_DACL_SECURITY_INFORMATION");
            public static SECURITY_INFORMATION PROTECTED_SACL_SECURITY_INFORMATION = new(0x40000000, "PROTECTED_SACL_SECURITY_INFORMATION");
            public static SECURITY_INFORMATION UNPROTECTED_DACL_SECURITY_INFORMATION = new(0x20000000, "UNPROTECTED_DACL_SECURITY_INFORMATION");
            public static SECURITY_INFORMATION UNPROTECTED_SACL_SECURITY_INFORMATION = new(0x10000000, "UNPROTECTED_SACL_SECURITY_INFORMATION");

            public static implicit operator SECURITY_INFORMATION(uint id) => GetAll<SECURITY_INFORMATION>().Where(s => s.Id == id).FirstOrDefault();
            private SECURITY_INFORMATION(uint id, string name) : base (id, name) { }
        }

        /// <summary>
        /// The ACCESS_MODE enumeration contains values that indicate how the access rights in an EXPLICIT_ACCESS structure apply to the trustee.
        /// Functions such as SetEntriesInAcl and GetExplicitEntriesFromAcl use these values to set or retrieve information in an access control entry (ACE).
        /// 
        /// Minimum supported client: Windows XP [desktop apps only]
        /// Minimum supported server: Windows Server 2003 [desktop apps only]
        /// Header: accctrl.h
        /// 
        /// Documentation: https://learn.microsoft.com/windows/win32/api/accctrl/ne-accctrl-access_mode
        /// </summary>
        public sealed class ACCESS_MODE : Enumeration
        {
            public static ACCESS_MODE NOT_USED_ACCESS = new(0, "NOT_USED_ACCESS");
            public static ACCESS_MODE GRANT_ACCESS = new(1, "GRANT_ACCESS");
            public static ACCESS_MODE SET_ACCESS = new(2, "SET_ACCESS");
            public static ACCESS_MODE DENY_ACCESS = new(3, "DENY_ACCESS");
            public static ACCESS_MODE REVOKE_ACCESS = new(4, "REVOKE_ACCESS");
            public static ACCESS_MODE SET_AUDIT_SUCCESS = new(5, "SET_AUDIT_SUCCESS");
            public static ACCESS_MODE SET_AUDIT_FAILURE = new(6, "SET_AUDIT_FAILURE");

            public static implicit operator ACCESS_MODE(uint id) => GetAll<ACCESS_MODE>().Where(s => s.Id == id).FirstOrDefault();
            private ACCESS_MODE(uint id, string name) : base (id, name) { }
        }

        /// <summary>
        /// The following are the inherit flags that go into the AceFlags field of an Ace header.
        /// 
        /// Minimum supported client:
        /// Minimum supported server:
        /// Header: Winnt.h (include Windows.h)
        /// 
        /// Documentation:
        /// </summary>
        public sealed class ACE_FLAGS : Enumeration
        {
            public static ACE_FLAGS OBJECT_INHERIT_ACE = new(0x1, "OBJECT_INHERIT_ACE");
            public static ACE_FLAGS CONTAINER_INHERIT_ACE = new(0x2, "CONTAINER_INHERIT_ACE");
            public static ACE_FLAGS NO_PROPAGATE_INHERIT_ACE = new(0x4, "NO_PROPAGATE_INHERIT_ACE");
            public static ACE_FLAGS INHERIT_ONLY_ACE = new(0x8, "INHERIT_ONLY_ACE");
            public static ACE_FLAGS INHERITED_ACE = new(0x10, "INHERITED_ACE");
            public static ACE_FLAGS VALID_INHERIT_FLAGS = new(0x1F, "VALID_INHERIT_FLAGS");
            public static ACE_FLAGS SUCCESSFUL_ACCESS_ACE_FLAG = new(0x20, "SUCCESSFUL_ACCESS_ACE_FLAG");
            public static ACE_FLAGS CRITICAL_ACE_FLAG = new(0x40, "CRITICAL_ACE_FLAG");
            public static ACE_FLAGS TRUST_PROTECTED_FILTER_ACE_FLAG = new(0x40, "TRUST_PROTECTED_FILTER_ACE_FLAG");
            public static ACE_FLAGS FAILED_ACCESS_ACE_FLAG = new(0x80, "FAILED_ACCESS_ACE_FLAG");

            public static implicit operator ACE_FLAGS(uint id) => GetAll<ACE_FLAGS>().Where(s => s.Id == id).FirstOrDefault();
            private ACE_FLAGS(uint id, string name) : base (id, name) { }
        }

        /// <summary>
        /// The MULTIPLE_TRUSTEE_OPERATION enumeration contains values that indicate whether a TRUSTEE structure is an impersonation trustee.
        /// 
        /// Minimum supported client: Windows XP [desktop apps only]
        /// Minimum supported server: Windows Server 2003 [desktop apps only]
        /// Header: accctrl.h
        /// 
        /// Documentation: https://learn.microsoft.com/windows/win32/api/accctrl/ne-accctrl-multiple_trustee_operation
        /// </summary>
        public sealed class MULTIPLE_TRUSTEE_OPERATION : Enumeration
        {
            public static MULTIPLE_TRUSTEE_OPERATION NO_MULTIPLE_TRUSTEE = new(0, "NO_MULTIPLE_TRUSTEE");
            public static MULTIPLE_TRUSTEE_OPERATION TRUSTEE_IS_IMPERSONATE = new(1, "TRUSTEE_IS_IMPERSONATE");

            public static implicit operator MULTIPLE_TRUSTEE_OPERATION(uint id) => GetAll<MULTIPLE_TRUSTEE_OPERATION>().Where(s => s.Id == id).FirstOrDefault();
            private MULTIPLE_TRUSTEE_OPERATION(uint id, string name) : base (id, name) { }
        }

        /// <summary>
        /// The TRUSTEE_FORM enumeration contains values that indicate the type of data pointed to by the ptstrName member of the TRUSTEE structure.
        /// 
        /// Minimum supported client: Windows XP [desktop apps only]
        /// Minimum supported server: Windows Server 2003 [desktop apps only]
        /// Header: accctrl.h
        /// 
        /// Documentation: https://learn.microsoft.com/windows/win32/api/accctrl/ne-accctrl-trustee_form
        /// </summary>
        public sealed class TRUSTEE_FORM : Enumeration
        {
            public static TRUSTEE_FORM TRUSTEE_IS_SID = new(0, "TRUSTEE_IS_SID");
            public static TRUSTEE_FORM TRUSTEE_IS_NAME = new(1, "TRUSTEE_IS_NAME");
            public static TRUSTEE_FORM TRUSTEE_BAD_FORM = new(2, "TRUSTEE_BAD_FORM");
            public static TRUSTEE_FORM TRUSTEE_IS_OBJECTS_AND_SID = new(3, "TRUSTEE_IS_OBJECTS_AND_SID");
            public static TRUSTEE_FORM TRUSTEE_IS_OBJECTS_AND_NAME = new(4, "TRUSTEE_IS_OBJECTS_AND_NAME");

            public static implicit operator TRUSTEE_FORM(uint id) => GetAll<TRUSTEE_FORM>().Where(s => s.Id == id).FirstOrDefault();
            private TRUSTEE_FORM(uint id, string name) : base(id, name) { }
        }

        /// <summary>
        /// The TRUSTEE_TYPE enumeration contains values that indicate the type of trustee identified by a TRUSTEE structure.
        /// 
        /// Minimum supported client: Windows XP [desktop apps only]
        /// Minimum supported server: Windows Server 2003 [desktop apps only]
        /// Header: accctrl.h
        /// 
        /// Documentation: https://learn.microsoft.com/windows/win32/api/accctrl/ne-accctrl-trustee_type
        /// </summary>
        public sealed class TRUSTEE_TYPE : Enumeration
        {
            public static TRUSTEE_TYPE TRUSTEE_IS_UNKNOWN = new(0, "TRUSTEE_IS_UNKNOWN");
            public static TRUSTEE_TYPE TRUSTEE_IS_USER = new(1, "TRUSTEE_IS_USER");
            public static TRUSTEE_TYPE TRUSTEE_IS_GROUP = new(2, "TRUSTEE_IS_GROUP");
            public static TRUSTEE_TYPE TRUSTEE_IS_DOMAIN = new(3, "TRUSTEE_IS_DOMAIN");
            public static TRUSTEE_TYPE TRUSTEE_IS_ALIAS = new(4, "TRUSTEE_IS_ALIAS");
            public static TRUSTEE_TYPE TRUSTEE_IS_WELL_KNOWN_GROUP = new(5, "TRUSTEE_IS_WELL_KNOWN_GROUP");
            public static TRUSTEE_TYPE TRUSTEE_IS_DELETED = new(6, "TRUSTEE_IS_DELETED");
            public static TRUSTEE_TYPE TRUSTEE_IS_INVALID = new(7, "TRUSTEE_IS_INVALID");
            public static TRUSTEE_TYPE TRUSTEE_IS_COMPUTER = new(8, "TRUSTEE_IS_COMPUTER");

            public static implicit operator TRUSTEE_TYPE(uint id) => GetAll<TRUSTEE_TYPE>().Where(s => s.Id == id).FirstOrDefault();
            private TRUSTEE_TYPE(uint id, string name) : base(id, name) { }
        }

        /// <summary>
        /// Currently define Flags for "OBJECT" ACE types.
        /// 
        /// Minimum supported client:
        /// Minimum supported server:
        /// Header: Winnt.h (include Windows.h)
        /// 
        /// Documentation:
        /// </summary>
        public sealed class OBJECTS_PRESENT : Enumeration
        {
            public static OBJECTS_PRESENT ACE_OBJECT_TYPE_PRESENT = new(0x1, "ACE_OBJECT_TYPE_PRESENT");
            public static OBJECTS_PRESENT ACE_INHERITED_OBJECT_TYPE_PRESENT = new(0x2, "ACE_INHERITED_OBJECT_TYPE_PRESENT");

            public static implicit operator OBJECTS_PRESENT(uint id) => GetAll<OBJECTS_PRESENT>().Where(s => s.Id == id).FirstOrDefault();
            private OBJECTS_PRESENT(uint id, string name) : base (id, name) { }
        }

        /// <summary>
        /// The SE_OBJECT_TYPE enumeration contains values that correspond to the types of Windows objects that support security.
        /// The functions, such as GetSecurityInfo and SetSecurityInfo, that set and retrieve the security information of an object,
        /// use these values to indicate the type of object.
        /// 
        /// Minimum supported client: Windows XP [desktop apps only]
        /// Minimum supported server: Windows Server 2003 [desktop apps only]
        /// Header: accctrl.h
        /// 
        /// Documentation: https://learn.microsoft.com/windows/win32/api/accctrl/ne-accctrl-se_object_type
        /// </summary>
        public sealed class SE_OBJECT_TYPE : Enumeration
        {
            public static SE_OBJECT_TYPE SE_UNKNOWN_OBJECT_TYPE = new(0, "SE_UNKNOWN_OBJECT_TYPE");
            public static SE_OBJECT_TYPE SE_FILE_OBJECT = new(1, "SE_FILE_OBJECT");
            public static SE_OBJECT_TYPE SE_SERVICE = new(2, "SE_SERVICE");
            public static SE_OBJECT_TYPE SE_PRINTER = new(3, "SE_PRINTER");
            public static SE_OBJECT_TYPE SE_REGISTRY_KEY = new(4, "SE_REGISTRY_KEY");
            public static SE_OBJECT_TYPE SE_LMSHARE = new(5, "SE_LMSHARE");
            public static SE_OBJECT_TYPE SE_KERNEL_OBJECT = new(6, "SE_KERNEL_OBJECT");
            public static SE_OBJECT_TYPE SE_WINDOW_OBJECT = new(7, "SE_WINDOW_OBJECT");
            public static SE_OBJECT_TYPE SE_DS_OBJECT = new(8, "SE_DS_OBJECT");
            public static SE_OBJECT_TYPE SE_DS_OBJECT_ALL = new(9, "SE_DS_OBJECT_ALL");
            public static SE_OBJECT_TYPE SE_PROVIDER_DEFINED_OBJECT = new(10, "SE_PROVIDER_DEFINED_OBJECT");
            public static SE_OBJECT_TYPE SE_WMIGUID_OBJECT = new(11, "SE_WMIGUID_OBJECT");
            public static SE_OBJECT_TYPE SE_REGISTRY_WOW64_32KEY = new(12, "SE_REGISTRY_WOW64_32KEY");
            public static SE_OBJECT_TYPE SE_REGISTRY_WOW64_64KEY = new(13, "SE_REGISTRY_WOW64_64KEY");

            public static implicit operator SE_OBJECT_TYPE(uint id) => GetAll<SE_OBJECT_TYPE>().Where(s => s.Id == id).FirstOrDefault();
            private SE_OBJECT_TYPE(uint id, string name) : base (id, name) { }
        }

        /// <summary>
        /// ACCESS TYPES.
        /// The following are masks for the predefined standard access types.
        /// 
        /// Minimum supported client:
        /// Minimum supported server:
        /// Header: Winnt.h (include Windows.h)
        /// 
        /// Documentation:
        /// </summary>
        public class ACCESS_TYPE : Enumeration
        {
            // The following are masks for the predefined standard access types.
            public static ACCESS_TYPE DELETE = new(0x00010000, "DELETE");
            public static ACCESS_TYPE READ_CONTROL = new(0x00020000, "READ_CONTROL");
            public static ACCESS_TYPE WRITE_DAC = new(0x00040000, "WRITE_DAC");
            public static ACCESS_TYPE WRITE_OWNER = new(0x00080000, "WRITE_OWNER");
            public static ACCESS_TYPE SYNCHRONIZE = new(0x00100000, "SYNCHRONIZE");
            public static ACCESS_TYPE STANDARD_RIGHTS_REQUIRED = new(0x000F0000, "STANDARD_RIGHTS_REQUIRED");
            public static ACCESS_TYPE STANDARD_RIGHTS_READ = new(READ_CONTROL.Id, "STANDARD_RIGHTS_READ");
            public static ACCESS_TYPE STANDARD_RIGHTS_WRITE = new(READ_CONTROL.Id, "STANDARD_RIGHTS_WRITE");
            public static ACCESS_TYPE STANDARD_RIGHTS_EXECUTE = new(READ_CONTROL.Id, "STANDARD_RIGHTS_EXECUTE");
            public static ACCESS_TYPE STANDARD_RIGHTS_ALL = new(0x001F0000, "STANDARD_RIGHTS_ALL");
            public static ACCESS_TYPE SPECIFIC_RIGHTS_ALL = new(0x0000FFFF, "SPECIFIC_RIGHTS_ALL");

            // AccessSystemAcl access type
            public static ACCESS_TYPE ACCESS_SYSTEM_SECURITY = new(0x01000000, "ACCESS_SYSTEM_SECURITY");

            // MaximumAllowed access type
            public static ACCESS_TYPE MAXIMUM_ALLOWED = new(0x02000000, "MAXIMUM_ALLOWED");
            
            //  These are the generic rights.
            public static ACCESS_TYPE GENERIC_READ = new(0x80000000, "GENERIC_READ");
            public static ACCESS_TYPE GENERIC_WRITE = new(0x40000000, "GENERIC_WRITE");
            public static ACCESS_TYPE GENERIC_EXECUTE = new(0x20000000, "GENERIC_EXECUTE");
            public static ACCESS_TYPE GENERIC_ALL = new(0x10000000, "GENERIC_ALL");

            public static implicit operator ACCESS_TYPE(uint id) => GetAll<ACCESS_TYPE>().Where(s => s.Id == id).FirstOrDefault();
            protected ACCESS_TYPE(uint id, string name) : base(id, name) { }
        }

        /// <summary>
        /// Token Specific Access Rights.
        /// 
        /// Minimum supported client:
        /// Minimum supported server:
        /// Header: Winnt.h (include Windows.h)
        /// 
        /// Documentation:
        /// </summary>
        public sealed class TOKEN_ACCESS_RIGHT : ACCESS_TYPE
        {
            public static TOKEN_ACCESS_RIGHT TOKEN_ASSIGN_PRIMARY = new(0x0001, "TOKEN_ASSIGN_PRIMARY");
            public static TOKEN_ACCESS_RIGHT TOKEN_DUPLICATE = new(0x0002, "TOKEN_DUPLICATE");
            public static TOKEN_ACCESS_RIGHT TOKEN_IMPERSONATE = new(0x0004, "TOKEN_IMPERSONATE");
            public static TOKEN_ACCESS_RIGHT TOKEN_QUERY = new(0x0008, "TOKEN_QUERY");
            public static TOKEN_ACCESS_RIGHT TOKEN_QUERY_SOURCE = new(0x0010, "TOKEN_QUERY_SOURCE");
            public static TOKEN_ACCESS_RIGHT TOKEN_ADJUST_PRIVILEGES = new(0x0020, "TOKEN_ADJUST_PRIVILEGES");
            public static TOKEN_ACCESS_RIGHT TOKEN_ADJUST_GROUPS = new(0x0040, "TOKEN_ADJUST_GROUPS");
            public static TOKEN_ACCESS_RIGHT TOKEN_ADJUST_DEFAULT = new(0x0080, "TOKEN_ADJUST_DEFAULT");
            public static TOKEN_ACCESS_RIGHT TOKEN_ADJUST_SESSIONID = new(0x0100, "TOKEN_ADJUST_SESSIONID");
            public static TOKEN_ACCESS_RIGHT TOKEN_ALL_ACCESS_P = new(STANDARD_RIGHTS_REQUIRED |
                                                                      TOKEN_ASSIGN_PRIMARY |
                                                                      TOKEN_DUPLICATE |
                                                                      TOKEN_IMPERSONATE |
                                                                      TOKEN_QUERY |
                                                                      TOKEN_QUERY_SOURCE |
                                                                      TOKEN_ADJUST_PRIVILEGES |
                                                                      TOKEN_ADJUST_GROUPS |
                                                                      TOKEN_ADJUST_DEFAULT,
                                                                      "TOKEN_ALL_ACCESS_P");

            // #if ((defined(_WIN32_WINNT) && (_WIN32_WINNT > 0x0400)) || (!defined(_WIN32_WINNT)))
            public static TOKEN_ACCESS_RIGHT TOKEN_ALL_ACCESS = new(TOKEN_ALL_ACCESS_P | TOKEN_ADJUST_SESSIONID, "TOKEN_ALL_ACCESS");
            // #else
            // #define TOKEN_ALL_ACCESS TOKEN_ALL_ACCESS_P
            // #endif

            public static TOKEN_ACCESS_RIGHT TOKEN_READ = new(STANDARD_RIGHTS_READ | TOKEN_QUERY, "TOKEN_READ");
            public static TOKEN_ACCESS_RIGHT TOKEN_WRITE = new(STANDARD_RIGHTS_WRITE |
                                                               TOKEN_ADJUST_PRIVILEGES |
                                                               TOKEN_ADJUST_GROUPS |
                                                               TOKEN_ADJUST_DEFAULT,
                                                               "TOKEN_WRITE");

            public static TOKEN_ACCESS_RIGHT TOKEN_EXECUTE = new(STANDARD_RIGHTS_EXECUTE, "TOKEN_EXECUTE");
            public static TOKEN_ACCESS_RIGHT TOKEN_TRUST_CONSTRAINT_MASK = new(STANDARD_RIGHTS_READ |
                                                                               TOKEN_QUERY |
                                                                               TOKEN_QUERY_SOURCE,
                                                                               "TOKEN_TRUST_CONSTRAINT_MASK");

            public static TOKEN_ACCESS_RIGHT TOKEN_TRUST_ALLOWED_MASK = new(TOKEN_TRUST_CONSTRAINT_MASK |
                                                                            TOKEN_DUPLICATE |
                                                                            TOKEN_IMPERSONATE,
                                                                            "TOKEN_TRUST_ALLOWED_MASK");

            // #if (NTDDI_VERSION >= NTDDI_WIN8)
            public static TOKEN_ACCESS_RIGHT TOKEN_ACCESS_PSEUDO_HANDLE_WIN8 = new(TOKEN_QUERY.Id | TOKEN_QUERY_SOURCE.Id, "TOKEN_ACCESS_PSEUDO_HANDLE_WIN8");
            public static TOKEN_ACCESS_RIGHT TOKEN_ACCESS_PSEUDO_HANDLE = new(TOKEN_ACCESS_PSEUDO_HANDLE_WIN8.Id, "TOKEN_ACCESS_PSEUDO_HANDLE");
            // #endif

            public static implicit operator TOKEN_ACCESS_RIGHT(uint id) => GetAll<TOKEN_ACCESS_RIGHT>().Where(s => s.Id == id).FirstOrDefault();
            private TOKEN_ACCESS_RIGHT(uint id, string name) : base (id, name) { }
        }

        /// <summary>
        /// Privilege attributes.
        /// 
        /// Minimum supported client:
        /// Minimum supported server:
        /// Header: Winnt.h (include Windows.h)
        /// 
        /// Documentation:
        /// </summary>
        public sealed class PRIVILEGE_ATTRIBUTE : Enumeration
        {
            public static PRIVILEGE_ATTRIBUTE SE_PRIVILEGE_ENABLED_BY_DEFAULT = new(0x00000001, "SE_PRIVILEGE_ENABLED_BY_DEFAULT");
            public static PRIVILEGE_ATTRIBUTE SE_PRIVILEGE_ENABLED = new(0x00000002, "SE_PRIVILEGE_ENABLED");
            public static PRIVILEGE_ATTRIBUTE SE_PRIVILEGE_REMOVED = new(0X00000004, "SE_PRIVILEGE_REMOVED");
            public static PRIVILEGE_ATTRIBUTE SE_PRIVILEGE_USED_FOR_ACCESS = new(0x80000000, "SE_PRIVILEGE_USED_FOR_ACCESS");
            public static PRIVILEGE_ATTRIBUTE SE_PRIVILEGE_VALID_ATTRIBUTES = new(SE_PRIVILEGE_ENABLED_BY_DEFAULT |
                                                                                  SE_PRIVILEGE_ENABLED |
                                                                                  SE_PRIVILEGE_REMOVED |
                                                                                  SE_PRIVILEGE_USED_FOR_ACCESS,
                                                                                  "SE_PRIVILEGE_VALID_ATTRIBUTES");

            public static implicit operator PRIVILEGE_ATTRIBUTE(uint id) => GetAll<PRIVILEGE_ATTRIBUTE>().Where(s => s.Id == id).FirstOrDefault();
            private PRIVILEGE_ATTRIBUTE(uint id, string name) : base(id, name) { }
        }
        #endregion

        #region Structures

        /// <summary>
        /// The SID_IDENTIFIER_AUTHORITY structure represents the top-level authority of a security identifier (SID).
        /// 
        /// Minimum supported client: Windows XP [desktop apps only]
        /// Minimum supported server: Windows Server 2003 [desktop apps only]
        /// Header: Winnt.h (include Windows.h)
        /// 
        /// Documentation: https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-sid_identifier_authority
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        internal struct SID_IDENTIFIER_AUTHORITY
        {
            internal byte[] Value;
            internal SID_IDENTIFIER_AUTHORITY(byte[] value)
            {
                Value = value;
            }
        }

        /// <summary>
        /// The security identifier (SID) structure is a variable-length structure used to uniquely identify users or groups.
        /// 
        /// Minimum supported client: Windows XP [desktop apps only]
        /// Minimum supported server: Windows Server 2003 [desktop apps only]
        /// Header: Winnt.h (include Windows.h)
        /// 
        /// Documentation: https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-sid
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        internal struct SID
        {
            internal byte Revision;
            internal byte SubAuthorityCount;
            internal uint[] SubAuthority;
        }

        /// <summary>
        /// The ACL structure is the header of an access control list (ACL).
        /// A complete ACL consists of an ACL structure followed by an ordered list of zero or more access control entries (ACEs).
        /// 
        /// Minimum supported client: Windows XP [desktop apps only]
        /// Minimum supported server: Windows Server 2003 [desktop apps only]
        /// Header: Winnt.h (include Windows.h)
        /// 
        /// Documentation: https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-acl
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        internal struct ACL
        {
            internal byte AclRevision;
            internal byte Sbz1;
            internal ushort AclSize;
            internal ushort AceCount;
            internal ushort Sbz2;
        }

        /// <summary>
        /// The SECURITY_DESCRIPTOR structure contains the security information associated with an object.
        /// Applications use this structure to set and query an object's security status.
        /// 
        /// 
        /// Minimum supported client: Windows XP [desktop apps | UWP apps]
        /// Minimum supported server: Windows Server 2003 [desktop apps | UWP apps]
        /// Header: Winnt.h (include Windows.h)
        /// 
        /// Documentation: https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-security_descriptor
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        internal struct SECURITY_DESCRIPTOR
        {
            internal byte Revision;
            internal byte Sbz1;
            internal SECURITY_DESCRIPTOR_CONTROL Control;
            internal IntPtr Owner;
            internal IntPtr Group;
            internal IntPtr Sacl;
            internal IntPtr Dacl;
        }

        /// <summary>
        /// The OBJECTS_AND_SID structure contains a security identifier (SID) that identifies a trustee
        /// and GUIDs that identify the object types of an object-specific access control entry (ACE).
        /// 
        /// Minimum supported client: Windows XP [desktop apps only]
        /// Minimum supported server: Windows Server 2003 [desktop apps only]
        /// Header: accctrl.h
        /// 
        /// Documentation: https://learn.microsoft.com/windows/win32/api/accctrl/ns-accctrl-objects_and_sid
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        internal struct OBJECTS_AND_SID
        {
            internal OBJECTS_PRESENT ObjectsPresent;
            internal Guid ObjectTypeGuid;
            internal Guid InheritedObjectTypeGuid;
            internal SID pSid;
        }

        /// <summary>
        /// The OBJECTS_AND_NAME structure contains a string that identifies a trustee by name
        /// and additional strings that identify the object types of an object-specific access control entry (ACE).
        /// 
        /// Minimum supported client: Windows XP [desktop apps only]
        /// Minimum supported server: Windows Server 2003 [desktop apps only]
        /// Header: accctrl.h
        /// 
        /// Documentation: https://learn.microsoft.com/windows/win32/api/accctrl/ns-accctrl-objects_and_name_w
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        internal struct OBJECTS_AND_NAME_W
        {
            internal OBJECTS_PRESENT ObjectsPresent;
            internal SE_OBJECT_TYPE ObjectType;
            internal string ObjectTypeName;
            internal string InheritedObjectTypeName;
            internal string ptstrName;
        }

        /// <summary>
        /// The TRUSTEE structure identifies the user account, group account, or logon session to which an access control entry (ACE) applies.
        /// The structure can use a name or a security identifier (SID) to identify the trustee.
        /// 
        /// Access control functions, such as SetEntriesInAcl and GetExplicitEntriesFromAcl,
        /// use this structure to identify the logon account associated with the access control
        /// or audit control information in an EXPLICIT_ACCESS structure.
        /// 
        /// Minimum supported client: Windows XP [desktop apps only]
        /// Minimum supported server: Windows Server 2003 [desktop apps only]
        /// Header: accctrl.h
        /// 
        /// Documentation: https://learn.microsoft.com/windows/win32/api/accctrl/ns-accctrl-trustee_w
        /// </summary>
        [StructLayout(LayoutKind.Explicit)]
        internal struct TRUSTEE_W
        {
            // This member is not currently supported and must be NULL.
            [FieldOffset(0)] internal IntPtr pMultipleTrustee;
            [FieldOffset(1)] internal MULTIPLE_TRUSTEE_OPERATION MultipleTrusteeOperation;
            [FieldOffset(2)] internal TRUSTEE_FORM TrusteeForm;
            [FieldOffset(3)] internal TRUSTEE_TYPE TrusteeType;

            // Union.
            [FieldOffset(4)] internal string u_ptstrName;
            [FieldOffset(4)] internal SID pSid;
            [FieldOffset(4)] internal OBJECTS_AND_SID pObjectsAndSid;
            [FieldOffset(4)] internal OBJECTS_AND_NAME_W pObjectsAndName;

            [FieldOffset(5)] internal string ptstrName;
        }

        /// <summary>
        /// The EXPLICIT_ACCESS structure defines access control information for a specified trustee.
        /// Access control functions, such as SetEntriesInAcl and GetExplicitEntriesFromAcl,
        /// use this structure to describe the information in an access control entry(ACE) of an access control list (ACL).
        /// 
        /// Minimum supported client: Windows XP [desktop apps only]
        /// Minimum supported server: Windows Server 2003 [desktop apps only]
        /// Header: accctrl.h
        /// 
        /// Documentation: https://learn.microsoft.com/windows/win32/api/accctrl/ns-accctrl-explicit_access_w
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        internal struct EXPLICIT_ACCESS_W
        {
            internal uint grfAccessPermissions;
            internal ACCESS_MODE grfAccessMode;
            internal uint grfInheritance;
            internal TRUSTEE_W Trustee;
        }

        /// <summary>
        /// Describes a local identifier for an adapter.
        /// 
        /// Minimum supported client:
        /// Minimum supported server:
        /// Header: winnt.h (include Windows.h)
        /// 
        /// Documentation: https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-luid
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        internal struct LUID
        {
            internal uint LowPart;
            internal long HighPart;
        }

        /// <summary>
        /// The LUID_AND_ATTRIBUTES structure represents a locally unique identifier (LUID) and its attributes.
        /// 
        /// Minimum supported client: Windows XP [desktop apps only]
        /// Minimum supported server: Windows Server 2003 [desktop apps only]
        /// Header: winnt.h (include Windows.h)
        /// 
        /// Documentation: https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-luid_and_attributes
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        internal struct LUID_AND_ATTRIBUTES
        {
            internal LUID Luid;
            internal PRIVILEGE_ATTRIBUTE Attributes;
        }

        /// <summary>
        /// The TOKEN_PRIVILEGES structure contains information about a set of privileges for an access token.
        /// 
        /// Minimum supported client: Windows XP [desktop apps only]
        /// Minimum supported server: Windows Server 2003 [desktop apps only]
        /// Header: winnt.h (include Windows.h)
        /// 
        /// Documentation: https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-token_privileges
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        internal struct TOKEN_PRIVILEGES
        {
            internal uint PrivilegeCount;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            internal LUID_AND_ATTRIBUTES[] Privileges;
        }
        #endregion
    
        public AccessControl() { }

        public void Dispose() => AccessControlManager.Dispose(disposing: true);

        /// <summary>
        /// This method adjusts the current process token privileges.
        /// </summary>
        /// <param name="privilege_list"></param>
        public static void AdjustTokenPrivileges(string[] privilege_list)
        {
            TOKEN_PRIVILEGES token_privileges = new() { Privileges = new LUID_AND_ATTRIBUTES[1] };
            SystemSafeHandle h_token = AccessControlManager.GetProcessTokenSafeHandle(TOKEN_ACCESS_RIGHT.TOKEN_ADJUST_PRIVILEGES);
            
            foreach (string privilege in privilege_list)
            {
                if (!NativeFunctions.LookupPrivilegeValue(string.Empty, NativeFunctions.SE_DEBUG_NAME, ref token_privileges.Privileges[0].Luid))
                    throw new SystemException(Base.GetSystemErrorText(Marshal.GetLastWin32Error()));

                token_privileges.Privileges[0].Attributes = PRIVILEGE_ATTRIBUTE.SE_PRIVILEGE_ENABLED | PRIVILEGE_ATTRIBUTE.SE_PRIVILEGE_USED_FOR_ACCESS;
                token_privileges.PrivilegeCount = 1;

                if (!NativeFunctions.AdjustTokenPrivileges(h_token, false, ref token_privileges, 0, IntPtr.Zero, IntPtr.Zero))
                    throw new SystemException(Base.GetSystemErrorText(Marshal.GetLastWin32Error()));
            }
        }
    }
}
