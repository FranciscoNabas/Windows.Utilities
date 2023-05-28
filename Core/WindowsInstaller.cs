using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Windows.Utilities
{
    internal partial class NativeFunctions
    {
        /// <summary>
        /// InstallHinfSection is an entry-point function exported by Setupapi.dll that you can use to execute a section of an .inf file.
        /// InstallHinfSection can be invoked by calling the Rundll32.exe utility.
        /// 
        /// Minimum supported client: Windows XP [desktop apps only]
        /// Minimum supported server: Windows Server 2003 [desktop apps only]
        /// Header: setupapi.h
        /// 
        /// P/Invoke:
        /// Documentation: https://learn.microsoft.com/windows/win32/api/setupapi/nf-setupapi-installhinfsectionw
        /// </summary>
        [DllImport("Setupapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern void InstallHinfSectionW(
            IntPtr Window, // The parent window handle. Typically hwnd is Null.
            IntPtr ModuleHandle, // Reserved and should be Null.
            string CommandLine,
            int ShowCommand // Reserved and should be zero.
        );
    }

    internal class WindowsInstaller
    {
        public static void InstallInfSection(string command_line) => NativeFunctions.InstallHinfSectionW(IntPtr.Zero, IntPtr.Zero, command_line, 0);
    }
}
