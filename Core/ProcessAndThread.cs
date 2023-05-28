﻿using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
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
        internal static extern SystemSafeHandle OpenProcess(
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
        internal static extern bool TerminateProcess(
            SystemSafeHandle hProcess,
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
        internal static extern SystemSafeHandle GetCurrentProcess();
    }

    internal sealed class ProcessAndThreadManager : IDisposable
    {
        private readonly Dictionary<uint, SystemSafeHandle> _process_list;
        private static ProcessAndThreadManager? _instance;

        private ProcessAndThreadManager() => _process_list = new();

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
                    foreach (KeyValuePair<uint, SystemSafeHandle> safe_handle in _instance._process_list)
                    {
                        if (!safe_handle.Value.IsInvalid && !safe_handle.Value.IsClosed)
                            safe_handle.Value.Dispose();
                    }
            }
        }

        /// <summary>
        /// Returns a process safe handle.
        /// </summary>
        /// <param name="process_id"></param>
        /// <param name="desired_access"></param>
        /// <returns></returns>
        internal static SystemSafeHandle GetProcessTokenSafeHandle(uint process_id, ProcessAndThread.PROCESS_SECURITY desired_access)
        {
            _instance ??= new();
            if (!_instance._process_list.TryGetValue(process_id, out SystemSafeHandle process_handle))
            {
                process_handle = _instance.OpenHandleWithCheck(process_id, desired_access);

                _instance._process_list.Add(process_id, process_handle);
            }
            else
            {
                if (process_handle.IsClosed || process_handle.IsInvalid)
                    process_handle = _instance.OpenHandleWithCheck(process_id, desired_access);
            }

            return process_handle;
        }

        /// <summary>
        /// Used internally to open a safe handle to a process with error handling.
        /// </summary>
        /// <param name="process_id"></param>
        /// <param name="desired_access"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="SystemException"></exception>
        private SystemSafeHandle OpenHandleWithCheck(uint process_id, ProcessAndThread.PROCESS_SECURITY desired_access)
        {
            if (_instance is null)
                throw new ArgumentNullException();

            SystemSafeHandle process_handle = NativeFunctions.OpenProcess(desired_access, false, process_id);
            if (process_handle.IsInvalid)
                throw new SystemException(Base.GetSystemErrorText(Marshal.GetLastWin32Error()));

            return process_handle;
        }
    }


    public class ProcessAndThread : IDisposable
    {
        #region Enumerations

        /// <summary>
        /// Retrieves a pseudo handle for the current process.
        /// 
        /// Minimum supported client:
        /// Minimum supported server:
        /// Header: winnt.h (include Windows.h)
        /// 
        /// Documentation: https://learn.microsoft.com/windows/win32/procthread/process-security-and-access-rights
        /// </summary>
        public sealed class PROCESS_SECURITY : AccessControl.ACCESS_TYPE
        {
            public static PROCESS_SECURITY PROCESS_TERMINATE = new(0x0001, "PROCESS_TERMINATE");
            public static PROCESS_SECURITY PROCESS_CREATE_THREAD = new(0x0002, "PROCESS_CREATE_THREAD");
            public static PROCESS_SECURITY PROCESS_SET_SESSIONID = new(0x0004, "PROCESS_SET_SESSIONID");
            public static PROCESS_SECURITY PROCESS_VM_OPERATION = new(0x0008, "PROCESS_VM_OPERATION");
            public static PROCESS_SECURITY PROCESS_VM_READ = new(0x0010, "PROCESS_VM_READ");
            public static PROCESS_SECURITY PROCESS_VM_WRITE = new(0x0020, "PROCESS_VM_WRITE");
            public static PROCESS_SECURITY PROCESS_DUP_HANDLE = new(0x0040, "PROCESS_DUP_HANDLE");
            public static PROCESS_SECURITY PROCESS_CREATE_PROCESS = new(0x0080, "PROCESS_CREATE_PROCESS");
            public static PROCESS_SECURITY PROCESS_SET_QUOTA = new(0x0100, "PROCESS_SET_QUOTA");
            public static PROCESS_SECURITY PROCESS_SET_INFORMATION = new(0x0200, "PROCESS_SET_INFORMATION");
            public static PROCESS_SECURITY PROCESS_QUERY_INFORMATION = new(0x0400, "PROCESS_QUERY_INFORMATION");
            public static PROCESS_SECURITY PROCESS_SUSPEND_RESUME = new(0x0800, "PROCESS_SUSPEND_RESUME");
            public static PROCESS_SECURITY PROCESS_QUERY_LIMITED_INFORMATION = new(0x1000, "PROCESS_QUERY_LIMITED_INFORMATION");
            public static PROCESS_SECURITY PROCESS_SET_LIMITED_INFORMATION = new(0x2000, "PROCESS_SET_LIMITED_INFORMATION");

            // #if (NTDDI_VERSION >= NTDDI_VISTA)
            public static PROCESS_SECURITY PROCESS_ALL_ACCESS = new(STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF, "PROCESS_ALL_ACCESS");
            // #else
            // #define PROCESS_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFF)
            // #endif

            private PROCESS_SECURITY(uint id, string name) : base(id, name) { }
        }

        /// <summary>
        /// Retrieves a pseudo handle for the current process.
        /// 
        /// Minimum supported client:
        /// Minimum supported server:
        /// Header: winnt.h (include Windows.h)
        /// 
        /// Documentation: https://learn.microsoft.com/windows/win32/procthread/thread-security-and-access-rights
        /// </summary>
        public sealed class THREAD_SECURITY : AccessControl.ACCESS_TYPE
        {
            public static THREAD_SECURITY THREAD_TERMINATE = new(0x0001, "THREAD_TERMINATE");
            public static THREAD_SECURITY THREAD_SUSPEND_RESUME = new(0x0002, "THREAD_SUSPEND_RESUME");
            public static THREAD_SECURITY THREAD_GET_CONTEXT = new(0x0008, "THREAD_GET_CONTEXT");
            public static THREAD_SECURITY THREAD_SET_CONTEXT = new(0x0010, "THREAD_SET_CONTEXT");
            public static THREAD_SECURITY THREAD_QUERY_INFORMATION = new(0x0040, "THREAD_QUERY_INFORMATION");
            public static THREAD_SECURITY THREAD_SET_INFORMATION = new(0x0020, "THREAD_SET_INFORMATION");
            public static THREAD_SECURITY THREAD_SET_THREAD_TOKEN = new(0x0080, "THREAD_SET_THREAD_TOKEN");
            public static THREAD_SECURITY THREAD_IMPERSONATE = new(0x0100, "THREAD_IMPERSONATE");
            public static THREAD_SECURITY THREAD_DIRECT_IMPERSONATION = new(0x0200, "THREAD_DIRECT_IMPERSONATION");
            public static THREAD_SECURITY THREAD_SET_LIMITED_INFORMATION = new(0x0400, "THREAD_SET_LIMITED_INFORMATION");
            public static THREAD_SECURITY THREAD_QUERY_LIMITED_INFORMATION = new(0x0800, "THREAD_QUERY_LIMITED_INFORMATION");
            public static THREAD_SECURITY THREAD_RESUME = new(0x1000, "THREAD_RESUME");

            // #if (NTDDI_VERSION >= NTDDI_VISTA)
            public static THREAD_SECURITY THREAD_ALL_ACCESS = new(STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF, "THREAD_ALL_ACCESS");
            // #else
            // #define THREAD_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x3FF)
            // #endif

            private THREAD_SECURITY(uint id, string name) : base(id, name) { }
        }

        /// <summary>
        /// Retrieves a pseudo handle for the current process.
        /// 
        /// Minimum supported client:
        /// Minimum supported server:
        /// Header: winnt.h (include Windows.h)
        /// 
        /// Documentation: https://learn.microsoft.com/windows/win32/procthread/job-object-security-and-access-rights
        /// </summary>
        public sealed class JOB_OBJECT_SECURITY : AccessControl.ACCESS_TYPE
        {
            public static JOB_OBJECT_SECURITY JOB_OBJECT_ASSIGN_PROCESS = new(0x0001, "JOB_OBJECT_ASSIGN_PROCESS");
            public static JOB_OBJECT_SECURITY JOB_OBJECT_SET_ATTRIBUTES = new(0x0002, "JOB_OBJECT_SET_ATTRIBUTES");
            public static JOB_OBJECT_SECURITY JOB_OBJECT_QUERY = new(0x0004, "JOB_OBJECT_QUERY");
            public static JOB_OBJECT_SECURITY JOB_OBJECT_TERMINATE = new(0x0008, "JOB_OBJECT_TERMINATE");
            public static JOB_OBJECT_SECURITY JOB_OBJECT_SET_SECURITY_ATTRIBUTES = new(0x0010, "JOB_OBJECT_SET_SECURITY_ATTRIBUTES");
            public static JOB_OBJECT_SECURITY JOB_OBJECT_IMPERSONATE = new(0x0020, "JOB_OBJECT_IMPERSONATE");
            public static JOB_OBJECT_SECURITY JOB_OBJECT_ALL_ACCESS = new(STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x3F, "JOB_OBJECT_ALL_ACCESS");

            private JOB_OBJECT_SECURITY(uint id, string name) : base (id, name) { }
        }
        #endregion

        private static readonly Dictionary<uint, string[]> _process_added_privilege_list = new();
        
        public ProcessAndThread() { }

        public void Dispose() => ProcessAndThreadManager.Dispose(disposing: true);

        public void TerminateProcess(uint process_id, uint exit_code = 1)
        {
            SystemSafeHandle h_process = ProcessAndThreadManager.GetProcessTokenSafeHandle(process_id, PROCESS_SECURITY.PROCESS_TERMINATE);

            if (!NativeFunctions.TerminateProcess(h_process, exit_code))
                throw new SystemException(Base.GetSystemErrorText(Marshal.GetLastWin32Error()));
        }

        public void TerminateProcess(uint process_id, string[] added_privileges, uint exit_code = 1)
        {
            using Process current_process = Process.GetCurrentProcess();
            if (_process_added_privilege_list.TryGetValue((uint)current_process.Id, out string[] existing_privileges))
            {
                string[] unique_privileges = (string[])(from string privilege in added_privileges
                                             where !existing_privileges.Contains(privilege)
                                             select privilege);
                
                if (unique_privileges.Length > 0)
                {
                    AccessControl.AdjustTokenPrivileges(unique_privileges);
                    List<string> all_privilege = new(existing_privileges);
                    all_privilege.AddRange(unique_privileges);
                    _process_added_privilege_list[(uint)current_process.Id] = all_privilege.ToArray();
                }
            }
            else
            {
                AccessControl.AdjustTokenPrivileges(added_privileges);
                _process_added_privilege_list.Add((uint)current_process.Id, added_privileges);
            }

            SystemSafeHandle h_process = ProcessAndThreadManager.GetProcessTokenSafeHandle(process_id, PROCESS_SECURITY.PROCESS_TERMINATE);

            if (!NativeFunctions.TerminateProcess(h_process, exit_code))
                throw new SystemException(Base.GetSystemErrorText(Marshal.GetLastWin32Error()));
        }
    }
}