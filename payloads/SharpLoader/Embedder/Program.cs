using dnlib.DotNet;
using System;
using System.IO.Compression;
using System.IO;
using System.Security.Cryptography;


namespace Embedder
{
    internal class Program
    {
        public static void Main(string[] args)
        {
            try
            {
                if (args.Length < 3)
                {
                    Console.WriteLine("[!] Error: not enough arguments");
                    Environment.Exit(1);
                }
                DES des = DES.Create();
                des.Padding = PaddingMode.ISO10126;
                string resourceName = Convert.ToBase64String(des.Key) + "_" + Convert.ToBase64String(des.IV);
                var resource = File.ReadAllBytes(args[0]);
                byte[] encrypted;
                using (MemoryStream ms = new MemoryStream())
                {
                    CryptoStream cStream = new CryptoStream(ms, des.CreateEncryptor(des.Key, des.IV), CryptoStreamMode.Write);
                    cStream.Write(resource, 0, resource.Length);
                    cStream.FlushFinalBlock();
                    encrypted = ms.ToArray();
                }

                using (MemoryStream ms = new MemoryStream())
                {
                    using (DeflateStream ds = new DeflateStream(ms, CompressionMode.Compress))
                    {
                        ds.Write(encrypted, 0, encrypted.Length);
                    }
                    encrypted = ms.ToArray();
                }

                var input = ModuleDefMD.Load(args[1]);
                input.Resources.Add(new EmbeddedResource(resourceName, encrypted));
                input.Write(args[2]);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Error: {0}", ex.Message);
            }
        }
    }
}
