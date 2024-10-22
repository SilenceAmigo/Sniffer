using System.Net;

namespace Netzwerkscanner
{
    public static class NetworkscannerFunctions // Eine Klasse hinzufügen
    {
        public static readonly HttpClient client = new HttpClient(); // Reuse HttpClient instance

        public static int CalcSubnetSize(int[] subnetMask)
        {
            int subnetzSize = 0;
            foreach (int octet in subnetMask)
            {
                string binaryOctet = Convert.ToString(octet, 2);
                foreach (char c in binaryOctet)
                {
                    if (c == '1')
                    {
                        subnetzSize++;
                    }
                }
            }
            return subnetzSize;
        }

        public static string GetSubnet(string localIP)
        {
            var ipParts = localIP.Split('.');
            return $"{ipParts[0]}.{ipParts[1]}.{ipParts[2]}.";
        }

        public static int[] GetSubnetArray(string localIP)
        {
            return localIP.Split('.').Select(int.Parse).ToArray();
        }

        public static int CalcNumOfIps(int subnetzSize)
        {
            return (int)Math.Pow(2, 32 - subnetzSize);
        }

        public static int[] NextIp(int[] subnetArray)
        {
            int[] newArray = (int[])subnetArray.Clone();
            if (newArray[2] < 255)
            {
                newArray[2]++;
            }
            else
            {
                newArray[2] = 0;
                if (newArray[1] < 255)
                {
                    newArray[1]++;
                }
                else
                {
                    newArray[1] = 0;
                    if (newArray[0] < 255)
                    {
                        newArray[0]++;
                    }
                }
            }
            return newArray;
        }

        public static string FormatMacAddress(byte[] macAddr)
        {
            return string.Join(":", macAddr.Take(6).Select(b => b.ToString("X2")));
        }

        public static void AddDeviceIfNew(string ip, string macAddress, double latency, Dictionary<string, (string MacAddress, string Manufacturer, double Latency)> foundDevices)
        {
            lock (foundDevices)
            {
                Interlocked.Increment(ref Network_Scanner.count); // Atomically increment count

                if (!foundDevices.ContainsKey(ip))
                {
                    string manufacturer = "Unknown";
                    manufacturer = Task.Run(async () => await GetManufacturerFromMac(macAddress)).Result;
                    foundDevices.Add(ip, (macAddress, manufacturer, latency));
                }
            }
        }

        public static async Task<string> GetManufacturerFromMac(string macAddress)
        {
            try
            {
                // Überprüfe, ob die MAC-Adresse nur aus Nullen besteht
                if (macAddress.All(c => c == '0' || c == ':'))
                {
                    return "Unknown";
                }

                // Bereite das MAC-Präfix vor und ersetze ":" durch "-"
                string macPrefix = macAddress.Substring(0, 8).Replace(":", "-");

                // Sende die Anfrage an die API
                HttpResponseMessage response = await client.GetAsync($"https://api.macvendors.com/{macPrefix}");
                response.EnsureSuccessStatusCode();

                // Lies die Antwort
                return await response.Content.ReadAsStringAsync();
            }
            catch (Exception)
            {
                return "Unknown";
            }
        }


        public static (string localIP, int[] subnetMask, string gateway) GetLocalIPAddressAndSubnetMask()
        {
            string localIP = null;
            string gateway = null;
            int[] subnetMask = new int[4];
            var host = Dns.GetHostEntry(Dns.GetHostName());
            foreach (var ip in host.AddressList)
            {
                if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    localIP = ip.ToString();
                }
            }
            foreach (System.Net.NetworkInformation.NetworkInterface ni in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
            {
                foreach (System.Net.NetworkInformation.UnicastIPAddressInformation ip in ni.GetIPProperties().UnicastAddresses)
                {
                    if (ip.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        if (ip.Address.ToString() == localIP)
                        {
                            subnetMask = ip.IPv4Mask.ToString().Split('.').Select(int.Parse).ToArray();
                        }
                    }
                }
                foreach (System.Net.NetworkInformation.GatewayIPAddressInformation gw in ni.GetIPProperties().GatewayAddresses)
                {
                    if (gw.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        gateway = gw.Address.ToString();
                    }
                }
            }
            return (localIP, subnetMask, gateway);
        }

        public static string GetHostName(string ipAddress)
        {
            try
            {
                return Dns.GetHostEntry(ipAddress).HostName;
            }
            catch
            {
                return "Unknown";
            }
        }

    }
}
