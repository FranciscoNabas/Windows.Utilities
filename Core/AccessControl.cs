using System;
using System.Linq;
using System.Diagnostics;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Net;
using System.Security.Principal;
using System.Text;

namespace Windows.Utilities
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
    internal enum SECURITY_DESCRIPTOR_CONTROL : uint
    {
        SE_OWNER_DEFAULTED = 0x0001,
        SE_GROUP_DEFAULTED = 0x0002,
        SE_DACL_PRESENT = 0x0004,
        SE_DACL_DEFAULTED = 0x0008,
        SE_SACL_PRESENT = 0x0010,
        SE_DACL_AUTO_INHERIT_REQ = 0x0100,
        SE_SACL_AUTO_INHERIT_REQ = 0x0200,
        SE_DACL_AUTO_INHERITED = 0x0400,
        SE_SACL_AUTO_INHERITED = 0x0800,
        SE_DACL_PROTECTED = 0x1000,
        SE_SACL_PROTECTED = 0x2000,
        SE_RM_CONTROL_VALID = 0x4000,
        SE_SELF_RELATIVE = 0x8000
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
    internal enum SECURITY_INFORMATION : uint
    {
        OWNER_SECURITY_INFORMATION = 0x00000001,
        GROUP_SECURITY_INFORMATION = 0x00000002,
        DACL_SECURITY_INFORMATION = 0x00000004,
        SACL_SECURITY_INFORMATION = 0x00000008,
        LABEL_SECURITY_INFORMATION = 0x00000010,
        ATTRIBUTE_SECURITY_INFORMATION = 0x00000020,
        SCOPE_SECURITY_INFORMATION = 0x00000040,
        PROCESS_TRUST_LABEL_SECURITY_INFORMATION = 0x00000080,
        ACCESS_FILTER_SECURITY_INFORMATION = 0x00000100,
        BACKUP_SECURITY_INFORMATION = 0x00010000,
        PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000,
        PROTECTED_SACL_SECURITY_INFORMATION = 0x40000000,
        UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000,
        UNPROTECTED_SACL_SECURITY_INFORMATION = 0x10000000
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
    internal enum ACCESS_MODE : uint
    {
        NOT_USED_ACCESS,
        GRANT_ACCESS,
        SET_ACCESS,
        DENY_ACCESS,
        REVOKE_ACCESS,
        SET_AUDIT_SUCCESS,
        SET_AUDIT_FAILURE
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
    internal enum ACE_FLAGS : uint
    {
        OBJECT_INHERIT_ACE = 0x1,
        CONTAINER_INHERIT_ACE = 0x2,
        NO_PROPAGATE_INHERIT_ACE = 0x4,
        INHERIT_ONLY_ACE = 0x8,
        INHERITED_ACE = 0x10,
        VALID_INHERIT_FLAGS = 0x1F,
        SUCCESSFUL_ACCESS_ACE_FLAG = 0x20,
        CRITICAL_ACE_FLAG = 0x40,
        TRUST_PROTECTED_FILTER_ACE_FLAG = 0x40,
        FAILED_ACCESS_ACE_FLAG = 0x80
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
    internal enum MULTIPLE_TRUSTEE_OPERATION : uint
    {
        NO_MULTIPLE_TRUSTEE,
        TRUSTEE_IS_IMPERSONATE
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
    internal enum TRUSTEE_FORM : uint
    {
        TRUSTEE_IS_SID,
        TRUSTEE_IS_NAME,
        TRUSTEE_BAD_FORM,
        TRUSTEE_IS_OBJECTS_AND_SID,
        TRUSTEE_IS_OBJECTS_AND_NAME
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
    internal enum TRUSTEE_TYPE : uint
    {
        TRUSTEE_IS_UNKNOWN,
        TRUSTEE_IS_USER,
        TRUSTEE_IS_GROUP,
        TRUSTEE_IS_DOMAIN,
        TRUSTEE_IS_ALIAS,
        TRUSTEE_IS_WELL_KNOWN_GROUP,
        TRUSTEE_IS_DELETED,
        TRUSTEE_IS_INVALID,
        TRUSTEE_IS_COMPUTER
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
    internal enum OBJECTS_PRESENT : uint
    {
        ACE_OBJECT_TYPE_PRESENT = 0x1,
        ACE_INHERITED_OBJECT_TYPE_PRESENT = 0x2,
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
    internal enum SE_OBJECT_TYPE : uint
    {
        SE_UNKNOWN_OBJECT_TYPE,
        SE_FILE_OBJECT,
        SE_SERVICE,
        SE_PRINTER,
        SE_REGISTRY_KEY,
        SE_LMSHARE,
        SE_KERNEL_OBJECT,
        SE_WINDOW_OBJECT,
        SE_DS_OBJECT,
        SE_DS_OBJECT_ALL,
        SE_PROVIDER_DEFINED_OBJECT,
        SE_WMIGUID_OBJECT,
        SE_REGISTRY_WOW64_32KEY,
        SE_REGISTRY_WOW64_64KEY
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
    internal enum ACCESS_TYPE : uint
    {
        // The following are masks for the predefined standard access types.
        DELETE = 0x00010000,
        READ_CONTROL = 0x00020000,
        WRITE_DAC = 0x00040000,
        WRITE_OWNER = 0x00080000,
        SYNCHRONIZE = 0x00100000,
        STANDARD_RIGHTS_REQUIRED = 0x000F0000,
        STANDARD_RIGHTS_READ = READ_CONTROL,
        STANDARD_RIGHTS_WRITE = READ_CONTROL,
        STANDARD_RIGHTS_EXECUTE = READ_CONTROL,
        STANDARD_RIGHTS_ALL = 0x001F0000,
        SPECIFIC_RIGHTS_ALL = 0x0000FFFF,

        // AccessSystemAcl access type
        ACCESS_SYSTEM_SECURITY = 0x01000000,

        // MaximumAllowed access type
        MAXIMUM_ALLOWED = 0x02000000,

        //  These are the generic rights.
        GENERIC_READ = 0x80000000,
        GENERIC_WRITE = 0x40000000,
        GENERIC_EXECUTE = 0x20000000,
        GENERIC_ALL = 0x10000000
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
    internal enum TOKEN_ACCESS_RIGHT : uint
    {
        TOKEN_ASSIGN_PRIMARY = 0x0001,
        TOKEN_DUPLICATE = 0x0002,
        TOKEN_IMPERSONATE = 0x0004,
        TOKEN_QUERY = 0x0008,
        TOKEN_QUERY_SOURCE = 0x0010,
        TOKEN_ADJUST_PRIVILEGES = 0x0020,
        TOKEN_ADJUST_GROUPS = 0x0040,
        TOKEN_ADJUST_DEFAULT = 0x0080,
        TOKEN_ADJUST_SESSIONID = 0x0100,
        TOKEN_ALL_ACCESS_P = ACCESS_TYPE.STANDARD_RIGHTS_REQUIRED |
                             TOKEN_ASSIGN_PRIMARY |
                             TOKEN_DUPLICATE |
                             TOKEN_IMPERSONATE |
                             TOKEN_QUERY |
                             TOKEN_QUERY_SOURCE |
                             TOKEN_ADJUST_PRIVILEGES |
                             TOKEN_ADJUST_GROUPS |
                             TOKEN_ADJUST_DEFAULT,

        // #if ((defined(_WIN32_WINNT) && (_WIN32_WINNT > 0x0400)) || (!defined(_WIN32_WINNT)))
        TOKEN_ALL_ACCESS = TOKEN_ALL_ACCESS_P | TOKEN_ADJUST_SESSIONID,
        // #else
        // #define TOKEN_ALL_ACCESS TOKEN_ALL_ACCESS_P
        // #endif
        TOKEN_READ = ACCESS_TYPE.STANDARD_RIGHTS_READ | TOKEN_QUERY,
        TOKEN_WRITE = ACCESS_TYPE.STANDARD_RIGHTS_WRITE |
                      TOKEN_ADJUST_PRIVILEGES |
                      TOKEN_ADJUST_GROUPS |
                      TOKEN_ADJUST_DEFAULT,

        TOKEN_EXECUTE = ACCESS_TYPE.STANDARD_RIGHTS_EXECUTE,
        TOKEN_TRUST_CONSTRAINT_MASK = ACCESS_TYPE.STANDARD_RIGHTS_READ |
                                      TOKEN_QUERY |
                                      TOKEN_QUERY_SOURCE,

        TOKEN_TRUST_ALLOWED_MASK = TOKEN_TRUST_CONSTRAINT_MASK |
                                   TOKEN_DUPLICATE |
                                   TOKEN_IMPERSONATE,

        // #if (NTDDI_VERSION >= NTDDI_WIN8)
        TOKEN_ACCESS_PSEUDO_HANDLE_WIN8 = TOKEN_QUERY | TOKEN_QUERY_SOURCE,
        TOKEN_ACCESS_PSEUDO_HANDLE = TOKEN_ACCESS_PSEUDO_HANDLE_WIN8
        // #endif
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
    internal enum PRIVILEGE_ATTRIBUTE : uint
    {
        SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001,
        SE_PRIVILEGE_ENABLED = 0x00000002,
        SE_PRIVILEGE_REMOVED = 0X00000004,
        SE_PRIVILEGE_USED_FOR_ACCESS = 0x80000000,
        SE_PRIVILEGE_VALID_ATTRIBUTES = SE_PRIVILEGE_ENABLED_BY_DEFAULT |
                                        SE_PRIVILEGE_ENABLED |
                                        SE_PRIVILEGE_REMOVED |
                                        SE_PRIVILEGE_USED_FOR_ACCESS
    }

    /// <summary>
    /// The type of logon.
    /// 
    /// Minimum supported client:
    /// Minimum supported server:
    /// Header: Winbase.h (include Windows.h)
    /// 
    /// Documentation: https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-logonuserw
    /// </summary>
    internal enum LOGON_TYPE : uint
    {
        LOGON32_LOGON_INTERACTIVE = 2,
        LOGON32_LOGON_NETWORK = 3,
        LOGON32_LOGON_BATCH = 4,
        LOGON32_LOGON_SERVICE = 5,
        LOGON32_LOGON_UNLOCK = 7,
        LOGON32_LOGON_NETWORK_CLEARTEXT = 8,
        LOGON32_LOGON_NEW_CREDENTIALS = 9
    }

    /// <summary>
    /// Specifies the logon provider.
    /// 
    /// Minimum supported client:
    /// Minimum supported server:
    /// Header: Winbase.h (include Windows.h)
    /// 
    /// Documentation: https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-logonuserw
    /// </summary>
    internal enum LOGON_PROVIDER : uint
    {
        LOGON32_PROVIDER_DEFAULT,
        LOGON32_PROVIDER_WINNT35,
        LOGON32_PROVIDER_WINNT40,
        LOGON32_PROVIDER_WINNT50,
        LOGON32_PROVIDER_VIRTUAL
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
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct TRUSTEE_W
    {
        internal IntPtr pMultipleTrustee;
        internal MULTIPLE_TRUSTEE_OPERATION MultipleTrusteeOperation;
        internal TRUSTEE_FORM TrusteeForm;
        internal TRUSTEE_TYPE TrusteeType;
        internal string u_ptstrName;
        internal string ptstrName;
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

    internal partial class NativeFunctions
    {
        // winnt.h
        internal static readonly uint SECURITY_DESCRIPTOR_REVISION = 1;

        // winnt.h
        // TODO: Turn into a 'text enumeration'.
        internal static readonly string SE_SECURITY_NAME = "SeSecurityPrivilege";
        internal static readonly string SE_DEBUG_NAME = "SeDebugPrivilege";

        // sddl.h
        internal static readonly uint SDDL_REVISION_1 = 1;

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
            TOKEN_ACCESS_RIGHT DesiredAccess,
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
        internal static extern bool LookupPrivilegeValue(
            string lpSystemName,
            string lpName,
            ref LUID lpLuid
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
        internal static extern bool AdjustTokenPrivileges(
            SystemSafeHandle TokenHandle,
            [MarshalAs(UnmanagedType.Bool)] bool DisableAllPrivileges,
            ref TOKEN_PRIVILEGES NewState,
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
        internal static extern void BuildExplicitAccessWithName(
            ref EXPLICIT_ACCESS_W pExplicitAccess,
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
        internal static extern uint SetEntriesInAcl(
            uint cCountOfExplicitEntries,
            ref EXPLICIT_ACCESS_W pListOfExplicitEntries,
            ACL OldAcl,
            out ACL NewAcl
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
        internal static extern bool SetSecurityDescriptorDacl(
            ref SECURITY_DESCRIPTOR pSecurityDescriptor,
            bool bDaclPresent,
            ACL pDacl,
            bool bDaclDefaulted
        );

        [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "LogonUserW")]
        internal static extern bool LogonUser(
            string lpszUsername,
            string lpszDomain,
            string lpszPassword,
            LOGON_TYPE dwLogonType,
            LOGON_PROVIDER dwLogonProvider,
            out SystemSafeHandle phToken
        );

        [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "ConvertStringSecurityDescriptorToSecurityDescriptorW")]
        internal static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
            string StringSecurityDescriptor,
            uint StringSDRevision,
            ref IntPtr SecurityDescriptor,
            out uint SecurityDescriptorSize
        );

        [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "ConvertSecurityDescriptorToStringSecurityDescriptorW")]
        internal static extern bool ConvertSecurityDescriptorToStringSecurityDescriptor(
            IntPtr pSecurityDescriptor,
            uint RequestedStringSDRevision,
            SECURITY_INFORMATION SecurityInformation,
            out StringBuilder StringSecurityDescriptor,
            out uint StringSecurityDescriptorLen
        );

        [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "SetNamedSecurityInfoW")]
        internal static extern uint SetNamedSecurityInfo(
            string SetNamedSecurityInfoA,
            SE_OBJECT_TYPE ObjectType,
            SECURITY_INFORMATION SecurityInformation,
            SID psidOwner,
            SID psidGroup,
            ACL pDacl,
            ACL pSacl
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
        internal static extern bool InitializeSecurityDescriptor(out SECURITY_DESCRIPTOR pSecurityDescriptor, uint dwRevision);
    }

    /// <summary>
    /// This class is the main API for access control utilities.
    /// </summary>
    public class AccessControl
    {
        
    
        public AccessControl() { }

        /// <summary>
        /// This method adjusts the current process token privileges.
        /// </summary>
        /// <param name="privilege_list"></param>
        public void AdjustTokenPrivileges(string[] privilege_list)
        {
            TOKEN_PRIVILEGES token_privileges = new() { Privileges = new LUID_AND_ATTRIBUTES[1] };
            using SystemSafeHandle h_token = OpenCurrentProcessTokenHandle(TOKEN_ACCESS_RIGHT.TOKEN_ADJUST_PRIVILEGES);
            
            foreach (string privilege in privilege_list)
            {
                if (!NativeFunctions.LookupPrivilegeValue(string.Empty, NativeFunctions.SE_DEBUG_NAME, ref token_privileges.Privileges[0].Luid))
                    NativeException.ThrowNativeException(Marshal.GetLastWin32Error(), Environment.StackTrace);

                token_privileges.Privileges[0].Attributes = PRIVILEGE_ATTRIBUTE.SE_PRIVILEGE_ENABLED | PRIVILEGE_ATTRIBUTE.SE_PRIVILEGE_USED_FOR_ACCESS;
                token_privileges.PrivilegeCount = 1;

                if (!NativeFunctions.AdjustTokenPrivileges(h_token, false, ref token_privileges, 0, IntPtr.Zero, IntPtr.Zero))
                    NativeException.ThrowNativeException(Marshal.GetLastWin32Error(), Environment.StackTrace);
            }
        }


        public static void Impersonate(NetworkCredential credential, Action action_to_impersonate)
        {
            if (!NativeFunctions.LogonUser(
                credential.UserName,
                credential.Domain,
                credential.Password,
                LOGON_TYPE.LOGON32_LOGON_INTERACTIVE,
                LOGON_PROVIDER.LOGON32_PROVIDER_DEFAULT,
                out SystemSafeHandle h_token
            ))
                NativeException.ThrowNativeException(Marshal.GetLastWin32Error(), Environment.StackTrace);

            using (h_token)
            {
                using WindowsIdentity id = new(h_token.DangerousGetHandle());
                action_to_impersonate();
            }

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
        private SystemSafeHandle OpenCurrentProcessTokenHandle(TOKEN_ACCESS_RIGHT desired_access)
        {
            SystemSafeHandle current_process_handle = NativeFunctions.GetCurrentProcess();
            if (!NativeFunctions.OpenProcessToken(current_process_handle, desired_access, out SystemSafeHandle token_handle))
                NativeException.ThrowNativeException(Marshal.GetLastWin32Error(), Environment.StackTrace);

            if (token_handle.IsInvalid)
                NativeException.ThrowNativeException(Marshal.GetLastWin32Error(), Environment.StackTrace);

            return token_handle;
        }
    }
}
