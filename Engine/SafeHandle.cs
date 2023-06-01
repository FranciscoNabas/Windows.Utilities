using System;
using System.Runtime.ConstrainedExecution;
using Microsoft.Win32.SafeHandles;

namespace Windows.Utilities
{
    internal enum HandleType
    {
        General,
        Service
    }
    internal class SystemSafeHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private SystemSafeHandle() : base(true) { }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
        protected override bool ReleaseHandle()
        {
            return NativeFunctions.CloseHandle(handle);
        }
    }

    internal class ServiceSafeHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private ServiceSafeHandle() : base(true) { }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
        protected override bool ReleaseHandle()
        {
            return NativeFunctions.CloseServiceHandle(handle);
        }
    }
}