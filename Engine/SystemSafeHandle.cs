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
        private HandleType handle_type = HandleType.General;
        private SystemSafeHandle() : base(true) { }

        internal void Dispose(HandleType type)
        {
            handle_type = type;
            ReleaseHandle();
        }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
        protected override bool ReleaseHandle()
        {
            if (!IsInvalid && !IsClosed)
                return handle_type switch
                {
                    HandleType.Service => NativeFunctions.CloseServiceHandle(handle),
                    _ => NativeFunctions.CloseHandle(handle),
                };

            return true;
        }
    }
}