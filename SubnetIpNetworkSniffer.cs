using System.Net;
using System.Runtime.InteropServices;
using System.Linq;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Net.Http;

class SubnetIpNetworkSniffer
{
    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern int SendARP(int destIp, int srcIp, byte[] macAddr, ref int physicalAddrLen);
    private static int count;
    private static readonly HttpClient client = new HttpClient(); // Reuse HttpClient instance

    public static async Task Main(string[] args)
    {
        // Benutzerabfrage auslagern
        bool showAllInfo = GetUserInput();

        // Netzwerkinformationen abrufen
        var (localIP, subnetMask, gateway) = GetLocalIPAddressAndSubnetMask();
        if (localIP == null || subnetMask == null)
        {
            Console.WriteLine("Keine lokale IP-Adresse oder Subnetzmaske gefunden.");
            return;
        }

        // Berechnung der Anzahl der IP-Adressen
        int subnetzSize = CalcSubnetSize(subnetMask);
        int numOfIps = CalcNumOfIps(subnetzSize);

        string subnet = GetSubnet(localIP);
        int[] subnetArray = GetSubnetArray(localIP);

        // Ausgabe der Netzwerkinformationen
        PrintNetworkInfo(localIP, subnet, subnetzSize, gateway);

        // ARP-Sweep durchführen und Zeit messen
        var (foundDevices, elapsedSeconds) = await PerformArpSweepAndMeasureTime(numOfIps, subnetArray, showAllInfo);

        // Ausgabe der gefundenen Geräte
        PrintFoundDevices(foundDevices, showAllInfo);

        // Ausgabe der Zeit und Anzahl der gefundenen Hosts
        PrintSummary(elapsedSeconds);
    }

    static async Task<SortedDictionary<string, (string MacAddress, string Manufacturer)>> ARPSweep(int numOfIps, int[] subnetArray, bool showAllInfo)
    {
        var foundDevices = new SortedDictionary<string, (string MacAddress, string Manufacturer)>();
        int j = 0;
        int k = 0;

        if (numOfIps == 0)
        {
            return foundDevices;
        }

        Parallel.For(1, 255, i =>
        {
            string ip = CreateIpAddress(subnetArray, i);
            IPAddress ipAddress;
            Console.WriteLine(ip);
            if (i == 254)  // "255 -> Broadcast" "1-254 -> 254 pro Oktette"
            {
                k++;
            }

            try
            {
                ipAddress = IPAddress.Parse(ip);
            }
            catch (FormatException)
            {
                return;
            }
            // Verarbeiten des ARP-Requests
            ProcessArpRequest(ipAddress, foundDevices, ref j);
        });

        if (k > 0)
        {
            subnetArray = NextIp(subnetArray);
            var foundDevicesRek = await ARPSweep(numOfIps - 256, subnetArray, showAllInfo);
            lock (foundDevices)
            {
                foreach (var device in foundDevicesRek)
                {
                    if (!foundDevices.ContainsKey(device.Key))
                    {
                        foundDevices.Add(device.Key, device.Value);
                    }
                }
            }
            k = 0;
        }
        return foundDevices;
    }

    // Methode zum Erstellen der IP-Adresse
    static string CreateIpAddress(int[] subnetArray, int i)
    {
        string subnet = string.Join(".", subnetArray.Take(subnetArray.Length - 1));
        return $"{subnet}.{i}";
    }

    // Methode zum Verarbeiten des ARP-Requests
    static void ProcessArpRequest(IPAddress ipAddress, SortedDictionary<string, (string MacAddress, string Manufacturer)> foundDevices, ref int count)
    {
        byte[] macAddr = new byte[6];
        int len = macAddr.Length;

        try
        {
            int result = SendARP(BitConverter.ToInt32(ipAddress.GetAddressBytes(), 0), 0, macAddr, ref len);

            if (result == 0)
            {
                var macAddress = FormatMacAddress(macAddr);
                AddDeviceIfNew(ipAddress.ToString(), macAddress, foundDevices, ref count);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Fehler beim Senden von ARP-Request für {ipAddress}: {ex.Message}");
        }
    }

    // Methode zum Hinzufügen eines neuen Geräts
    static void AddDeviceIfNew(string ip, string macAddress, SortedDictionary<string, (string MacAddress, string Manufacturer)> foundDevices, ref int count)
    {
        lock (foundDevices)
        {
            count++;
            Console.WriteLine($"{count}: Host gefunden");
            if (!foundDevices.ContainsKey(ip))
            {
                string manufacturer = "Unbekannt";
                manufacturer = Task.Run(async () => await GetManufacturerFromMac(macAddress)).Result;
                foundDevices.Add(ip, (macAddress, manufacturer));
            }
        }
    }


    // ARP-Sweep durchführen und Zeit messen
    static async Task<(SortedDictionary<string, (string MacAddress, string Manufacturer)>, double)> PerformArpSweepAndMeasureTime(int numOfIps, int[] subnetArray, bool showAllInfo)
    {
        Stopwatch stopwatch = new Stopwatch();
        stopwatch.Start();

        var foundDevices = await ARPSweep(numOfIps, subnetArray, showAllInfo);

        stopwatch.Stop();

        return (foundDevices, stopwatch.Elapsed.TotalSeconds);
    }

    // Benutzerabfrage
    static bool GetUserInput()
    {
        Console.WriteLine("Möchten Sie alle Informationen (IP-Adresse, MAC-Adresse, Hostname und Hersteller) sehen? (y/n):");
        string input = Console.ReadLine().Trim().ToLower();
        return input == "y";
    }

    // Netzwerkinformationen ausgeben
    static void PrintNetworkInfo(string localIP, string subnet, int subnetzSize, string gateway)
    {
        Console.WriteLine($"IP-Adresse: {localIP} -> Subnetz: {subnet}0/{subnetzSize}");
        Console.WriteLine($"Gateway: {gateway}");
    }

    // Gefundene Geräte ausgeben
    static void PrintFoundDevices(SortedDictionary<string, (string MacAddress, string Manufacturer)> foundDevices, bool showAllInfo)
    {
        Console.WriteLine("\nGefundene Geräte sortiert nach IP-Adresse:");
        foreach (var device in foundDevices)
        {
            string hostname = GetHostName(device.Key);
            if (showAllInfo)
            {
                Console.WriteLine($"Gerät gefunden: {device.Key}\nMAC-Adresse: {device.Value.MacAddress}\nHostname: {hostname}\nHersteller: {device.Value.Manufacturer}\n\n");
            }
            else
            {
                Console.WriteLine($"Gerät gefunden: {device.Key}\nMAC-Adresse: {device.Value.MacAddress}\nHostname: {hostname}\nHersteller: {device.Value.Manufacturer}\n\n");
            }
        }
        Console.WriteLine($"\n{count} Hosts gefunden");
    }

    // Zeit und Anzahl der gefundenen Hosts ausgeben
    static void PrintSummary(double elapsedSeconds)
    {
        Console.WriteLine($"Zeit für den ARP-Sweep: {elapsedSeconds:F2} s");
    }

    // Subnetzgröße berechnen
    static int CalcSubnetSize(int[] subnetMask)
    {
        int subnetzSize = 0;
        foreach (int octet in subnetMask)
        {
            string binaryOctet = Convert.ToString(octet, 2).PadLeft(8, '0');
            foreach (char bit in binaryOctet)
            {
                if (bit == '1')
                {
                    subnetzSize++;
                }
                else
                {
                    break;
                }
            }
        }
        return subnetzSize;
    }

    // Anzahl der IP-Adressen berechnen
    static int CalcNumOfIps(int subnetzSize)
    {
        int maxOctetSize = 32;
        int maxSubnetzSize = maxOctetSize - subnetzSize;
        return (int)Math.Pow(2, maxSubnetzSize);
    }



    static (string, int[], string) GetLocalIPAddressAndSubnetMask()
    {
        foreach (var ni in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
        {
            if (ni.OperationalStatus == System.Net.NetworkInformation.OperationalStatus.Up)
            {
                foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                {
                    if (ua.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        string ipAddress = ua.Address.ToString();
                        string subnetMask = ua.IPv4Mask.ToString();
                        string gateway = ni.GetIPProperties().GatewayAddresses.FirstOrDefault()?.Address.ToString();
                        int[] subnetMaskArray = subnetMask.Split('.').Select(int.Parse).ToArray();
                        return (ipAddress, subnetMaskArray, gateway);
                    }
                }
            }
        }
        return (null, null, null);
    }

    static string GetSubnet(string ipAddress)
    {
        var segments = ipAddress.Split('.');
        if (segments.Length == 4)
        {
            return $"{segments[0]}.{segments[1]}.{segments[2]}.";
        }
        else
        {
            throw new FormatException("Invalid IP address format.");
        }
    }

    static int[] GetSubnetArray(string ipAddress)
    {
        var segments = ipAddress.Split('.');
        if (segments.Length == 4)
        {
            return segments.Select(s => int.Parse(s)).ToArray();
        }
        else
        {
            throw new FormatException("Invalid IP address format.");
        }
    }

    static string FormatMacAddress(byte[] macAddr)
    {
        return string.Join(":", macAddr.Select(b => b.ToString("X2").PadLeft(2, '0')));
    }

    static string GetHostName(string ipAddress)
    {
        try
        {
            IPHostEntry entry = Dns.GetHostEntry(ipAddress);
            return entry.HostName;
        }
        catch (Exception)
        {
            return "Unbekannt";
        }
    }

    static string ExtractOUI(string macAddress)
    {
        return string.Join(":", macAddress.Split(':').Take(3));
    }

    static async Task<string> GetManufacturerFromMac(string macAddress)
    {
        string oui = ExtractOUI(macAddress);
        string apiUrl = $"https://api.macvendors.com/{oui.Replace(":", "")}";

        try
        {
            HttpResponseMessage response = await client.GetAsync(apiUrl);
            if (response.IsSuccessStatusCode)
            {
                return await response.Content.ReadAsStringAsync();
            }
            else
            {
                return "Unbekannt";
            }
        }
        catch
        {
            return "Unbekannt";
        }
    }

    static int[] NextIp(int[] subnetArray)
    {
        subnetArray[2] = subnetArray[2] + 1;
        if (subnetArray[2] < 0)
        {
            subnetArray[1] = subnetArray[1] + 1;
            subnetArray[2] = 255;
            if (subnetArray[1] < 0)
            {
                subnetArray[0] = subnetArray[0] + 1;
                subnetArray[1] = 255;
                if (subnetArray[0] < 0)
                {
                    return subnetArray;
                }
            }
        }
        return subnetArray;
    }
}
