using System.Net;
using System.Net.NetworkInformation;
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



        public static (string localIP, int[] subnetMask, string gateway) SelectNetworkInterface()
        {
            var interfaces = new List<(string Name, string IPAddress, int[] SubnetMask, string Gateway)>();

            // Alle Netzwerkschnittstellen durchlaufen
            foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                foreach (UnicastIPAddressInformation ip in ni.GetIPProperties().UnicastAddresses)
                {
                    if (ip.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        var subnetMask = ip.IPv4Mask.ToString().Split('.').Select(int.Parse).ToArray();
                        string gateway = ni.GetIPProperties().GatewayAddresses
                            .FirstOrDefault(gw => gw.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)?.Address.ToString();
                        string macAddress = ni.GetPhysicalAddress().ToString();

                        if (!string.IsNullOrEmpty(ip.Address.ToString()) && !string.IsNullOrEmpty(gateway) && !string.IsNullOrEmpty(macAddress))
                        {
                            interfaces.Add((ni.Name, ip.Address.ToString(), subnetMask, gateway));
                        }
                    }
                }
            }

            if (interfaces.Count == 0)
            {
                Console.WriteLine("No valid network interfaces found.");
                return (null, null, null);
            }

            // Alle gefundenen Schnittstellen anzeigen
            Console.WriteLine("Available Network Interfaces:");
            for (int i = 0; i < interfaces.Count; i++)
            {
                Console.WriteLine($"{i + 1}. Adapter: {interfaces[i].Name}");
                Console.WriteLine($"   IP Address: {interfaces[i].IPAddress}");
                Console.WriteLine($"   Subnet Mask: {string.Join(".", interfaces[i].SubnetMask)}");
                Console.WriteLine($"   Gateway: {interfaces[i].Gateway}");
                Console.WriteLine("\n");
            }

            // Benutzer zur Auswahl auffordern
            Console.Write("Select an adapter by number: ");
            if (int.TryParse(Console.ReadLine(), out int selection) && selection > 0 && selection <= interfaces.Count)
            {
                var selectedInterface = interfaces[selection - 1];
                return (selectedInterface.IPAddress, selectedInterface.SubnetMask, selectedInterface.Gateway);
            }

            Console.WriteLine("Invalid selection.");
            return (null, null, null);
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
