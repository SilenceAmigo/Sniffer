using System;
using System.Net;
using System.Runtime.InteropServices;
using System.Linq;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Net.Http;
using System.Threading;

class SubnetIpNetworkSniffer
{
    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern int SendARP(int destIp, int srcIp, byte[] macAddr, ref int physicalAddrLen);

    private static int count;  // Class-level field for tracking found hosts
    private static readonly HttpClient client = new HttpClient(); // Reuse HttpClient instance
    private static int totalTestedIps = 0;  // Shared progress counter
    private static int originalNumOfIps = 0;  // Store the original number of IPs

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
        originalNumOfIps = CalcNumOfIps(subnetzSize); // Use a shared class-level variable to store original number of IPs

        string subnet = GetSubnet(localIP);
        int[] subnetArray = GetSubnetArray(localIP);

        // Ausgabe der Netzwerkinformationen
        PrintNetworkInfo(localIP, subnet, subnetzSize, gateway);

        // ARP-Sweep durchführen und Zeit messen
        var (foundDevices, elapsedSeconds) = await PerformArpSweepAndMeasureTime(originalNumOfIps, subnetArray, showAllInfo);

        // Ausgabe der gefundenen Geräte
        PrintFoundDevices(foundDevices, showAllInfo);

        // Ausgabe der Zeit und Anzahl der gefundenen Hosts
        PrintSummary(elapsedSeconds);
    }

    static async Task<SortedDictionary<string, (string MacAddress, string Manufacturer, double Latency)>> ARPSweep(int numOfIps, int[] subnetArray, bool showAllInfo)
    {
        var foundDevices = new SortedDictionary<string, (string MacAddress, string Manufacturer, double Latency)>();
        int totalIps = originalNumOfIps;  // Use the shared original number of IPs
        int testedIps = 0;

        if (numOfIps == 0)
        {
            return foundDevices;
        }

        // Die Anzahl der Schritte für den Fortschrittsbalken
        const int progressBarLength = 50;

        // Erstelle einen Mutex für die Konsolenausgabe
        object consoleLock = new object();

        Parallel.For(1, 255, i =>
        {
            string ip = CreateIpAddress(subnetArray, i);
            IPAddress ipAddress;
            try
            {
                ipAddress = IPAddress.Parse(ip);
            }
            catch (FormatException)
            {
                return;
            }

            // Verarbeiten des ARP-Requests
            ProcessArpRequest(ipAddress, foundDevices);

            Interlocked.Increment(ref testedIps);
            Interlocked.Increment(ref totalTestedIps); // Update the shared progress counter

            if (totalIps > 0)
            {
                double progressPercentage = Math.Min((totalTestedIps / (double)totalIps), 1.0);
                int progressBarFilled = (int)(progressBarLength * progressPercentage);

                // Fortschrittsbalken erstellen
                int progress = Math.Max(progressBarLength - progressBarFilled - 1, 0);

                string progressBar = new string('#', progressBarFilled) + new string('-', progress);

                lock (consoleLock)
                {
                    // Lösche die aktuelle Zeile und schreibe den Fortschrittsbalken
                    Console.SetCursorPosition(0, Console.CursorTop);
                    if (progressBarLength == progressBarFilled + 1)
                    {
                        Console.Write($"[{progressBar}] (100%)");
                    }
                    else
                    {
                        Console.Write($"[{progressBar}] ({progressPercentage:P0})");
                    }
                }
            }
        });

        // Recursive Call
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

        return foundDevices;
    }

    // Methode zum Erstellen der IP-Adresse
    static string CreateIpAddress(int[] subnetArray, int i)
    {
        string subnet = string.Join(".", subnetArray.Take(subnetArray.Length - 1));
        return $"{subnet}.{i}";
    }

    // Methode zum Verarbeiten des ARP-Requests
    static void ProcessArpRequest(IPAddress ipAddress, SortedDictionary<string, (string MacAddress, string Manufacturer, double Latency)> foundDevices)
    {
        byte[] macAddr = new byte[6];
        int len = macAddr.Length;

        try
        {
            Stopwatch stopwatch = new Stopwatch();
            stopwatch.Start();
            int result = SendARP(BitConverter.ToInt32(ipAddress.GetAddressBytes(), 0), 0, macAddr, ref len);
            stopwatch.Stop();
            double latency = stopwatch.Elapsed.TotalSeconds; // Latenz in Sekunden

            if (result == 0)
            {
                var macAddress = FormatMacAddress(macAddr);
                AddDeviceIfNew(ipAddress.ToString(), macAddress, latency, foundDevices);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Fehler beim Senden von ARP-Request für {ipAddress}: {ex.Message}");
        }
    }

    // Methode zum Hinzufügen eines neuen Geräts
    static void AddDeviceIfNew(string ip, string macAddress, double latency, SortedDictionary<string, (string MacAddress, string Manufacturer, double Latency)> foundDevices)
    {
        lock (foundDevices)
        {
            Interlocked.Increment(ref count); // Atomically increment count

            if (!foundDevices.ContainsKey(ip))
            {
                string manufacturer = "Unbekannt";
                manufacturer = Task.Run(async () => await GetManufacturerFromMac(macAddress)).Result;
                foundDevices.Add(ip, (macAddress, manufacturer, latency));
            }
        }
    }

    // ARP-Sweep durchführen und Zeit messen
    static async Task<(SortedDictionary<string, (string MacAddress, string Manufacturer, double Latency)>, double)> PerformArpSweepAndMeasureTime(int numOfIps, int[] subnetArray, bool showAllInfo)
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
        Console.WriteLine("Möchten Sie alle Informationen (IP-Adresse, MAC-Adresse, Hostname, Hersteller und Latenz) sehen? (y/n):");
        string input = Console.ReadLine().Trim().ToLower();
        Console.Clear();
        return input == "y";
    
    }

    // Netzwerkinformationen ausgeben
    static void PrintNetworkInfo(string localIP, string subnet, int subnetzSize, string gateway)
    {
        Console.WriteLine($"IP-Adresse: {localIP} -> Subnetz: {subnet}0/{subnetzSize}");
        Console.WriteLine($"Gateway: {gateway}");
    }

    // Gefundene Geräte ausgeben
    static void PrintFoundDevices(SortedDictionary<string, (string MacAddress, string Manufacturer, double Latency)> foundDevices, bool showAllInfo)
    {
        Console.WriteLine("\n\nGefundene Geräte sortiert nach IP-Adresse:\n\n");
        foreach (var device in foundDevices)
        {
            string hostname = GetHostName(device.Key);
            if (showAllInfo)
            {
                Console.WriteLine($"Ip-Adresse: {device.Key}\nMAC-Adresse: {device.Value.MacAddress}\nHostname: {hostname}\nHersteller: {device.Value.Manufacturer}\nLatenz: {device.Value.Latency} s\n\n");
            }
            else
            {
                Console.WriteLine($"Ip-Adresse: {device.Key}\nMAC-Adresse: {device.Value.MacAddress}\nHostname: {hostname}\nHersteller: {device.Value.Manufacturer}\nLatenz: {device.Value.Latency} s\n\n");
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

    // Anzahl der IP-Adressen im Subnetz berechnen
    static int CalcNumOfIps(int subnetzSize)
    {
        return (int)Math.Pow(2, 32 - subnetzSize);
    }

    // Subnetz aus lokaler IP-Adresse ableiten
    static string GetSubnet(string localIP)
    {
        var ipParts = localIP.Split('.');
        return $"{ipParts[0]}.{ipParts[1]}.{ipParts[2]}.";
    }

    // Lokale IP-Adresse und Subnetzmaske abrufen
    static (string localIP, int[] subnetMask, string gateway) GetLocalIPAddressAndSubnetMask()
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

    // Subnetz-Array aus lokaler IP-Adresse erstellen
    static int[] GetSubnetArray(string localIP)
    {
        return localIP.Split('.').Select(int.Parse).ToArray();
    }

    // MAC-Adresse formatieren
    static string FormatMacAddress(byte[] macAddr)
    {
        return string.Join(":", macAddr.Take(6).Select(b => b.ToString("X2")));
    }

    // Nächste IP-Adresse im Subnetz berechnen
    static int[] NextIp(int[] subnetArray)
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

    // Hostname abrufen
    static string GetHostName(string ipAddress)
    {
        try
        {
            return Dns.GetHostEntry(ipAddress).HostName;
        }
        catch
        {
            return "Unbekannt";
        }
    }

    // Hersteller von MAC-Adresse abrufen
    static async Task<string> GetManufacturerFromMac(string macAddress)
    {
        try
        {
            string macPrefix = macAddress.Substring(0, 8).Replace(":", "-");
            HttpResponseMessage response = await client.GetAsync($"https://api.macvendors.com/{macPrefix}");
            response.EnsureSuccessStatusCode();
            return await response.Content.ReadAsStringAsync();
        }
        catch (Exception)
        {
            return "Unbekannt";
        }
    }
}