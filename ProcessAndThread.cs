using System;
using System.Runtime.InteropServices;

namespace Windows.Utilities
{
    internal partial class NativeFunctions
    {
        /// <summary>
        /// Opens an existing local process object.
        /// 
        /// Minimum supported client: Windows XP [desktop apps | UWP apps]
        /// Minimum supported server: Windows Server 2003 [desktop apps | UWP apps]
        /// Header: processthreadsapi.h (include Windows.h on Windows Server 2003, Windows Vista, Windows 7, Windows Server 2008 Windows Server 2008 R2)
        /// 
        /// P/Invoke: https://www.pinvoke.net/default.aspx/kernel32.openprocess
        /// Documentation: https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
        /// </summary>
        [DllImport("Kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr OpenProcess(
            uint dwDesiredAccess,
            bool bInheritHandle,
            uint dwProcessId
        );

        /// <summary>
        /// Terminates the specified process and all of its threads.
        /// 
        /// Minimum supported client: Windows XP [desktop apps | UWP apps]
        /// Minimum supported server: Windows Server 2003 [desktop apps | UWP apps]
        /// Header: processthreadsapi.h (include Windows.h on Windows Server 2003, Windows Vista, Windows 7, Windows Server 2008 Windows Server 2008 R2)
        /// 
        /// P/Invoke: https://www.pinvoke.net/default.aspx/kernel32.terminateprocess
        /// Documentation: https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess
        /// </summary>
        [DllImport("Kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool TerminateProcess(
            IntPtr hProcess,
            uint uExistCode
        );

        /// <summary>
        /// Retrieves a pseudo handle for the current process.
        /// 
        /// Minimum supported client: Windows XP [desktop apps | UWP apps]
        /// Minimum supported server: Windows Server 2003 [desktop apps | UWP apps]
        /// Header: processthreadsapi.h (include Windows.h on Windows Server 2003, Windows Vista, Windows 7, Windows Server 2008 Windows Server 2008 R2)
        /// 
        /// P/Invoke: https://www.pinvoke.net/default.aspx/kernel32/GetCurrentProcess.html
        /// Documentation: https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocess
        /// </summary>
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr GetCurrentProcess();
    }
    
    internal class ProcessAndThread
    {

    }
}
