using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace Windows.Utilities
{
    internal partial class NativeFunctions
    {
        // TODO: Map Win32 errors as resources?
        public static readonly int ERROR_INSUFFICIENT_BUFFER = 122;
        public static readonly int ERROR_MORE_DATA = 234;

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
            Base.FORMAT_MESSAGE_FLAGS dwFlags,
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

        [DllImport("Kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern IntPtr LocalFree(IntPtr hMem);

        internal static string[] GetStringArrayFromDoubleNullTermninatedCStyleArray(IntPtr ptr)
        {
            List<string> strings = new();
            while (true)
            {
                string current = Marshal.PtrToStringUni(ptr);
                strings.Add(current);

                // Length + '\0' * 2 (wide char = 2 bytes).
                int string_bytes = (current.Length + 1) * 2;

                // Checking if it's the end of the array.
                byte[] bytes = new byte[4];
                IntPtr no_null_offset = (IntPtr)((long)ptr + (current.Length * 2));
                bytes[0] = Marshal.ReadByte(no_null_offset, 0);
                bytes[1] = Marshal.ReadByte(no_null_offset, 1);
                bytes[2] = Marshal.ReadByte(no_null_offset, 2);
                bytes[3] = Marshal.ReadByte(no_null_offset, 3);

                if (Encoding.Unicode.GetString(bytes) == "\0\0")
                    break;

                ptr = (IntPtr)((long)ptr + string_bytes);
            }

            return strings.ToArray();
        }
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

        public enum FORMAT_MESSAGE_FLAGS : uint
        {
            FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x00000100,
            FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200,
            FORMAT_MESSAGE_FROM_STRING = 0x00000400,
            FORMAT_MESSAGE_FROM_HMODULE = 0x00000800,
            FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000,
            FORMAT_MESSAGE_ARGUMENT_ARRAY = 0x00002000,
            FORMAT_MESSAGE_MAX_WIDTH_MASK = 0x000000FF
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
