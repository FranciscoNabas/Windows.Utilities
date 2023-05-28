using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace Windows.Utilities
{
    internal partial class NativeFunctions
    {
        // TODO: Map Win32 errors as resources?
        public static readonly int ERROR_INSUFFICIENT_BUFFER = 122;

        /// <summary>
        /// Formats a message string. The function requires a message definition as input.
        /// 
        /// Minimum supported client: Windows XP [desktop apps | UWP apps]
        /// Minimum supported server: Windows Server 2003 [desktop apps | UWP apps]
        /// Header: winbase.h (include Windows.h)
        /// 
        /// P/Invoke: https://www.pinvoke.net/default.aspx/kernel32.formatmessage
        /// Documentation: https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-formatmessage
        /// </summary>
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern int FormatMessage(
            uint dwFlags,
            IntPtr lpSource,
            int dwMessageId,
            uint dwLanguageId,
            out StringBuilder msgOut,
            int nSize,
            IntPtr Arguments
        );

        /// <summary>
        /// Closes an open object handle.
        /// 
        /// Minimum supported client: Windows XP [desktop apps | UWP apps]
        /// Minimum supported server: Windows Server 2003 [desktop apps | UWP apps]
        /// Header: handleapi.h (include Windows.h)
        /// 
        /// P/Invoke: https://www.pinvoke.net/default.aspx/kernel32.closehandle
        /// Documentation: https://learn.microsoft.com/windows/win32/api/handleapi/nf-handleapi-closehandle
        /// </summary>
        [DllImport("Kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CloseHandle(IntPtr hObject);
    }

    public class Base
    {
        #region Enumerations

        /// <summary>
        /// Formats a message string. The function requires a message definition as input.
        /// 
        /// Minimum supported client: Windows XP [desktop apps | UWP apps]
        /// Minimum supported server: Windows Server 2003 [desktop apps | UWP apps]
        /// Header: winbase.h (include Windows.h)
        /// 
        /// Documentation: https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-formatmessage
        /// </summary>
        
        public sealed class FORMAT_MESSAGE_FLAGS : Enumeration
        {
            public static FORMAT_MESSAGE_FLAGS FORMAT_MESSAGE_ALLOCATE_BUFFER = new(0x00000100, "FORMAT_MESSAGE_ALLOCATE_BUFFER");
            public static FORMAT_MESSAGE_FLAGS FORMAT_MESSAGE_IGNORE_INSERTS = new(0x00000200, "FORMAT_MESSAGE_IGNORE_INSERTS");
            public static FORMAT_MESSAGE_FLAGS FORMAT_MESSAGE_FROM_STRING = new(0x00000400, "FORMAT_MESSAGE_FROM_STRING");
            public static FORMAT_MESSAGE_FLAGS FORMAT_MESSAGE_FROM_HMODULE = new(0x00000800, "FORMAT_MESSAGE_FROM_HMODULE");
            public static FORMAT_MESSAGE_FLAGS FORMAT_MESSAGE_FROM_SYSTEM = new(0x00001000, "FORMAT_MESSAGE_FROM_SYSTEM");
            public static FORMAT_MESSAGE_FLAGS FORMAT_MESSAGE_ARGUMENT_ARRAY = new(0x00002000, "FORMAT_MESSAGE_ARGUMENT_ARRAY");
            public static FORMAT_MESSAGE_FLAGS FORMAT_MESSAGE_MAX_WIDTH_MASK = new(0x000000FF, "FORMAT_MESSAGE_MAX_WIDTH_MASK");

            public static implicit operator FORMAT_MESSAGE_FLAGS(uint id) => GetAll<FORMAT_MESSAGE_FLAGS>().Where(s => s.Id == id).FirstOrDefault();
            private FORMAT_MESSAGE_FLAGS(uint id, string name) : base(id, name) { }
        }
        #endregion

        #region Methods
        public static string GetSystemErrorText(int error_code)
        {
            StringBuilder buffer = new(1024);
            int result = NativeFunctions.FormatMessage(
                FORMAT_MESSAGE_FLAGS.FORMAT_MESSAGE_ALLOCATE_BUFFER |
                FORMAT_MESSAGE_FLAGS.FORMAT_MESSAGE_FROM_SYSTEM |
                FORMAT_MESSAGE_FLAGS.FORMAT_MESSAGE_IGNORE_INSERTS,
                IntPtr.Zero,
                error_code,
                0,
                out buffer,
                buffer.Capacity,
                IntPtr.Zero
            );
            if (result == 0)
                throw new SystemException($"Error formating message. {Marshal.GetLastWin32Error()}");

            return buffer.ToString();
        }
        #endregion
    }
}
