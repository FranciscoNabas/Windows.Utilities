using System;
using System.Net;
using System.Runtime.InteropServices;

namespace Windows.Utilities
{
    #region Enumerations
    /// <summary>
    /// Indicates the scope of the resource.
    /// 
    /// Minimum supported client:
    /// Minimum supported server:
    /// Header: winnetwk.h
    /// 
    /// Documentation: https://learn.microsoft.com/windows/win32/api/winnetwk/ns-winnetwk-netresourcew
    /// </summary>
    internal enum NETWORK_RESOURCE_SCOPE : uint
    {
        RESOURCE_CONNECTED = 0x00000001,
        RESOURCE_GLOBALNET = 0x00000002,
        RESOURCE_REMEMBERED = 0x00000003,
        RESOURCE_RECENT = 0x00000004,
        RESOURCE_CONTEXT = 0x00000005,
    }

    /// <summary>
    /// Indicates the resource type.
    /// 
    /// Minimum supported client:
    /// Minimum supported server:
    /// Header: winnetwk.h
    /// 
    /// Documentation: https://learn.microsoft.com/windows/win32/api/winnetwk/ns-winnetwk-netresourcew
    /// </summary>
    internal enum NETWORK_RESOURCE_TYPE : uint
    {
        RESOURCETYPE_ANY = 0x00000000,
        RESOURCETYPE_DISK = 0x00000001,
        RESOURCETYPE_PRINT = 0x00000002,
        RESOURCETYPE_RESERVED = 0x00000008,
        RESOURCETYPE_UNKNOWN = 0xFFFFFFFF
    }

    /// <summary>
    /// A bitmask that indicates how you can enumerate information about the resource.
    /// 
    /// Minimum supported client:
    /// Minimum supported server:
    /// Header: winnetwk.h
    /// 
    /// Documentation: https://learn.microsoft.com/windows/win32/api/winnetwk/ns-winnetwk-netresourcew
    /// </summary>
    [Flags]
    internal enum NETWORK_RESOURCE_USAGE : uint
    {
        RESOURCEUSAGE_CONNECTABLE = 0x00000001,
        RESOURCEUSAGE_CONTAINER = 0x00000002,
        RESOURCEUSAGE_NOLOCALDEVICE = 0x00000004,
        RESOURCEUSAGE_SIBLING = 0x00000008,
        RESOURCEUSAGE_ATTACHED = 0x00000010,
        RESOURCEUSAGE_ALL = RESOURCEUSAGE_CONNECTABLE | RESOURCEUSAGE_CONTAINER | RESOURCEUSAGE_ATTACHED,
        RESOURCEUSAGE_RESERVED = 0x80000000
    }

    /// <summary>
    /// Set by the provider to indicate what display type a user interface should use to represent this resource.
    /// 
    /// Minimum supported client:
    /// Minimum supported server:
    /// Header: winnetwk.h
    /// 
    /// Documentation: https://learn.microsoft.com/windows/win32/api/winnetwk/ns-winnetwk-netresourcew
    /// </summary>
    internal enum NETWORK_RESOURCE_DISPLAY_TYPE : uint
    {
        RESOURCEDISPLAYTYPE_GENERIC = 0x00000000,
        RESOURCEDISPLAYTYPE_DOMAIN = 0x00000001,
        RESOURCEDISPLAYTYPE_SERVER = 0x00000002,
        RESOURCEDISPLAYTYPE_SHARE = 0x00000003,
        RESOURCEDISPLAYTYPE_FILE = 0x00000004,
        RESOURCEDISPLAYTYPE_GROUP = 0x00000005,
        RESOURCEDISPLAYTYPE_NETWORK = 0x00000006,
        RESOURCEDISPLAYTYPE_ROOT = 0x00000007,
        RESOURCEDISPLAYTYPE_SHAREADMIN = 0x00000008,
        RESOURCEDISPLAYTYPE_DIRECTORY = 0x00000009,
        RESOURCEDISPLAYTYPE_TREE = 0x0000000A,
        RESOURCEDISPLAYTYPE_NDSCONTAINER = 0x0000000B
    }

    [Flags]
    internal enum CONNECT_OPTION : uint
    {
        CONNECT_OPTION_NONE = 0x00000000,
        CONNECT_UPDATE_PROFILE = 0x00000001,
        CONNECT_UPDATE_RECENT = 0x00000002,
        CONNECT_TEMPORARY = 0x00000004,
        CONNECT_INTERACTIVE = 0x00000008,
        CONNECT_PROMPT = 0x00000010,
        CONNECT_NEED_DRIVE = 0x00000020,
        CONNECT_REFCOUNT = 0x00000040,
        CONNECT_REDIRECT = 0x00000080,
        CONNECT_LOCALDRIVE = 0x00000100,
        CONNECT_CURRENT_MEDIA = 0x00000200,
        CONNECT_DEFERRED = 0x00000400,
        CONNECT_RESERVED = 0xFF000000,
        CONNECT_COMMANDLINE = 0x00000800,
        CONNECT_CMD_SAVECRED = 0x00001000,
        CONNECT_CRED_RESET = 0x00002000,
        CONNECT_REQUIRE_INTEGRITY = 0x00004000,
        CONNECT_REQUIRE_PRIVACY = 0x00008000,
        CONNECT_WRITE_THROUGH_SEMANTICS = 0x00010000,
        CONNECT_GLOBAL_MAPPING = 0x00040000
    }
    #endregion

    #region Structures
    /// <summary>
    /// The following structure contains information about a network resource.
    /// It is used by several of the network provider functions, including NPOpenEnum and NPAddConnection.
    /// 
    /// Minimum supported client: Windows XP [desktop apps only]
    /// Minimum supported server: Windows Server 2003 [desktop apps only]
    /// Header: winnetwk.h
    /// 
    /// P/Invoke: http://pinvoke.net/default.aspx/Structures/NETRESOURCE.html
    /// Documentation: https://learn.microsoft.com/windows/win32/api/winnetwk/ns-winnetwk-netresourcew
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct NETRESOURCE
    {
        internal NETWORK_RESOURCE_SCOPE dwScope;
        internal NETWORK_RESOURCE_TYPE dwType;
        internal NETWORK_RESOURCE_DISPLAY_TYPE dwDisplayType;
        internal NETWORK_RESOURCE_USAGE dwUsage;
        internal string lpLocalName;
        internal string lpRemoteName;
        internal string lpComment;
        internal string lpProvider;
    }
    #endregion

    internal partial class NativeFunctions
    {
        /// <summary>
        /// The WNetAddConnection2 function makes a connection to a network resource and can redirect a local device to the network resource.
        /// 
        /// Minimum supported client:
        /// Minimum supported server:
        /// Header: winnetwk.h
        /// 
        /// P/Invoke: http://pinvoke.net/default.aspx/mpr.WNetAddConnection2
        /// Documentation: https://learn.microsoft.com/windows/win32/api/winnetwk/nf-winnetwk-wnetaddconnection2w
        /// </summary>
        [DllImport("Mpr.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "WNetAddConnection2W")]
        internal static extern uint WNetAddConnection2(
            NETRESOURCE lpNetResource,
            string lpPassword,
            string lpUserName,
            CONNECT_OPTION dwFlags
        );
        [DllImport("Mpr.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "WNetAddConnection2W")]
        internal static extern uint WNetAddConnection2(
            NETRESOURCE lpNetResource,
            IntPtr lpPassword,
            IntPtr lpUserName,
            CONNECT_OPTION dwFlags
        );

        /// <summary>
        /// The WNetAddConnection2 function makes a connection to a network resource and can redirect a local device to the network resource.
        /// 
        /// Minimum supported client:
        /// Minimum supported server:
        /// Header: winnetwk.h
        /// 
        /// P/Invoke: https://www.pinvoke.net/default.aspx/mpr.wnetcancelconnection2
        /// Documentation: https://learn.microsoft.com/windows/win32/api/winnetwk/nf-winnetwk-wnetcancelconnection2w
        /// </summary>
        [DllImport("Mpr.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "WNetCancelConnection2W")]
        internal static extern uint WNetCancelConnection2(
            string lpName,
            CONNECT_OPTION dwFlags,
            bool fForce
        );
    }

    public class Network
    {
        
    }

    internal class NetworkConnection : IDisposable
    {
        private readonly string _network_name;
        private readonly NetworkCredential? _credential;
        private readonly CONNECT_OPTION _option = CONNECT_OPTION.CONNECT_OPTION_NONE;

        internal NetworkConnection(string network_name) => _network_name = network_name;
        internal NetworkConnection(string network_name, NetworkCredential credential) => 
            (_network_name, _credential) = (network_name, credential);

        internal NetworkConnection(string network_name, NetworkCredential credential, CONNECT_OPTION option) =>
            (_network_name, _credential, _option) = (network_name, credential, option);

        ~NetworkConnection() => Dispose();

        public void Dispose()
        {
            NativeFunctions.WNetCancelConnection2(_network_name, CONNECT_OPTION.CONNECT_OPTION_NONE, true);
            GC.SuppressFinalize(this);
        }

        internal void Connect(NETRESOURCE resource_information)
        {
            if (_credential is not null)
            {
                string user_fqdn = string.IsNullOrEmpty(_credential.Domain) ?
                _credential.UserName : string.Format(@"{0}\{1}", _credential.Domain, _credential.UserName);

                uint result = NativeFunctions.WNetAddConnection2(resource_information, _credential.Password, user_fqdn, _option);
                if (result != 0)
                    NativeException.ThrowNativeException((int)result, Environment.StackTrace);
            }
            else
            {
                uint result = NativeFunctions.WNetAddConnection2(resource_information, IntPtr.Zero, IntPtr.Zero, _option);
                if (result != 0)
                    NativeException.ThrowNativeException((int)result, Environment.StackTrace);
            }
        }
    }
}
