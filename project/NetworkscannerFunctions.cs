using System.Net;
using Microsoft.VisualBasic;
using Netzwerkscanner.dataModels;
using Newtonsoft.Json;

namespace Netzwerkscanner
{
    public static class NetworkscannerFunctions // Eine Klasse hinzufügen
    {
        public static readonly HttpClient client = new HttpClient(); // Reuse HttpClient instance

        private static Dictionary<string, List<string>> ieeeMacDatabase;

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



        // public static async Task<string> GetManufacturerFromMacApi(string mac)
        // {
        //     string apiUrl = $"https://api.macvendors.com/{mac}";

        //     using (HttpClient client = new HttpClient())
        //     {
        //         try
        //         {
        //             // Sende eine GET-Anfrage an die API
        //             HttpResponseMessage response = await client.GetAsync(apiUrl);
        //             await Task.Delay(1700); // 1 Sekunde warten zwischen den Anfragen


        //             if (response.IsSuccessStatusCode)
        //             {
        //                 // Lese die Antwort als String
        //                 string responseData = await response.Content.ReadAsStringAsync();
        //                 return responseData;
        //             }
        //             else
        //             {
        //                 return "Unknown";
        //             }
        //         }
        //         catch (Exception ex)
        //         {
        //             return "";
        //         }
        //     }
        // }

        public static async Task<string> GetManufacturerFromMacIEEEList(string macAddr, Dictionary<string, List<string>> macDatabase)
        {
            string macPrefix = macAddr.Substring(0, 8).Replace(":", "");

            // Variable für den Hersteller initialisieren
            string manufacturer = "unknown";

            // Schleife durch das Dictionary, um den Hersteller zu finden, der den Präfix enthält
            if (macDatabase != null)
            {
                foreach (var entry in macDatabase)
                {

                    if (entry.Value.Contains(macPrefix))
                    {
                        manufacturer = entry.Key;
                        return manufacturer;
                    }
                }
            }
            return manufacturer;

        }

        public static async Task GetManufacturerFromMacIEEEList(List<InactiveDevices> inactiveDevicesList)
        {
            // JSON-Datenbank laden
            string ieeeMacDatabase = LoadJson.LoadIeeeMacDatabase();

            // JSON in Dictionary deserialisieren
            var macDatabase = JsonConvert.DeserializeObject<Dictionary<string, List<string>>>(ieeeMacDatabase);

            // Schleife durch die Liste der inaktiven Geräte
            foreach (var device in inactiveDevicesList)
            {
                // Die ersten 6 Zeichen der MAC-Adresse erhalten und in Großbuchstaben umwandeln
                string macPrefix = device.MacAddress.Substring(0, 6).ToUpper();

                // Variable für den Hersteller initialisieren
                string manufacturer = "unknown";

                // Schleife durch das Dictionary, um den Hersteller zu finden, der den Präfix enthält
                if (macDatabase != null)
                {
                    foreach (var entry in macDatabase)
                    {
                        if (entry.Value.Contains(macPrefix))
                        {
                            manufacturer = entry.Key;
                            break;
                        }
                    }
                }
                device.Manufacturer = manufacturer;
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
