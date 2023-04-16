using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;


namespace IUL
{
    public class Win32
    {
        [StructLayout(LayoutKind.Explicit, Size = 8)]
        public struct LARGE_INTEGER
        {
            [FieldOffset(0)] public long QuadPart;

            [FieldOffset(0)] public uint LowPart;
            [FieldOffset(4)] public int HighPart;

            [FieldOffset(0)] public int LowPartAsInt;
            [FieldOffset(0)] public uint LowPartAsUInt;

            [FieldOffset(4)] public int HighPartAsInt;
            [FieldOffset(4)] public uint HighPartAsUInt;

            public long ToInt64()
            {
                return ((long)this.HighPart << 32) | (uint)this.LowPartAsInt;
            }

            public static LARGE_INTEGER FromInt64(long value)
            {
                return new LARGE_INTEGER
                {
                    LowPartAsInt = (int)(value),
                    HighPartAsInt = (int)((value >> 32))
                };
            }
        }

        public struct ClientId
        {
            public IntPtr processHandle;
            public IntPtr threadHandle;
        }

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern int NtAllocateVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress,
            uint zeroBits, ref uint regionSize, uint allocationType, uint protect);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern int NtWaitForSingleObject(IntPtr threadHandle, bool alertable, uint timeout);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern int RtlCreateUserThread(IntPtr processHandle, IntPtr securityDescriptor,
            bool createSuspended, uint zeroBits, IntPtr zeroReserve, IntPtr zeroCommit, IntPtr startAddress,
            IntPtr startParameter, ref IntPtr threadHandle, ref ClientId clientid);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern int NtProtectVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress,
            ref uint numberOfBytes, uint newProtect, ref uint oldProtect);
        
        [DllImport("ntdll.dll")]
        public static extern int NtClose(IntPtr handle);
    }
}
