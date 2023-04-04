using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading.Tasks;
using NetTools;

namespace Pinger
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("[!] Not enough arguments");
                return;
            }

            var list = args[0].Split(',');
            var addresses = new List<IPAddress>();
            foreach (var item in list)
            {
                IPAddressRange range;
                var result = IPAddressRange.TryParse(args[0], out range);
                if (!result)
                {
                    Console.WriteLine("[!] Cannot parse IP address range.");
                    return;
                }
                foreach (var ip in range)
                {
                    addresses.Add(ip);
                }
            }

            var tasks = new List<Task<PingReply>>();
            foreach (var addr in addresses)
            {
                tasks.Add(PingAsync(addr));
            }

            Task.WaitAll(tasks.ToArray());

            foreach (var task in tasks)
            {
                if (task.Result.Status == IPStatus.Success)
                {
                    Console.WriteLine($"[+] {task.Result.Address}");
                }
            }
        }

        static Task<PingReply> PingAsync(IPAddress address)
        {
            var tcs = new TaskCompletionSource<PingReply>();
            Ping ping = new Ping();
            
            ping.PingCompleted += (obj, sender) =>
            {
                tcs.SetResult(sender.Reply);
            };
            ping.SendAsync(address, 5000, new object());
            return tcs.Task;
        }
    }
}
