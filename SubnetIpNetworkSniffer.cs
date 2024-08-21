using System.Net;
using System.Runtime.InteropServices;
using System.Linq;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Diagnostics;

class SubnetIpNetworkSniffer
{
    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern int SendARP(int destIp, int srcIp, byte[] macAddr, ref int physicalAddrLen);
    private static int count;

    public static void Main(string[] args)
    {
        var (localIP, subnetMask, gateway) = GetLocalIPAddressAndSubnetMask();
        if (localIP == null || subnetMask == null)
        {
            Console.WriteLine("Keine lokale IP-Adresse oder Subnetzmaske gefunden.");
            return;
        }
        
            
        string binMask = ConvertToBinarySubnetMask(subnetMask);
        int subnetzSize = 0;
        binMask = binMask.Replace(".", "");
        foreach (char bit in binMask)
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

        string subnet = GetSubnet(localIP);
    
        Console.WriteLine($"IP-Adresse: {localIP} -> Subnetz: {subnet}0/{subnetzSize}");
        Console.WriteLine($"Gateway: {gateway}");

        int maxOctetSize = 32;
        int maxSubnetzSize = maxOctetSize - subnetzSize;
        int numOfIps = (int)Math.Pow(2, maxSubnetzSize) - 1;

        Stopwatch stopwatch = new Stopwatch();
        stopwatch.Start();

        var foundDevices = ARPSweep(subnet, numOfIps);

        stopwatch.Stop();

        Console.WriteLine("\nGefundene Geräte sortiert nach IP-Adresse:");
        foreach (var device in foundDevices)
        {
            string hostname = GetHostName(device.Key);
            Console.WriteLine($"Gerät gefunden: {device.Key}, MAC-Adresse: {device.Value}, Hostname: {hostname}");
        }

        Console.WriteLine($"\n{count} Hosts gefunden");
        Console.WriteLine($"Zeit für den ARP-Sweep: {stopwatch.Elapsed.TotalSeconds:F2} s");
        Console.WriteLine($"Gateway: {gateway}");
        
    }
    public static void GetARPTable()
    {
        Process process = new Process();
        process.StartInfo.FileName = "arp";
        process.StartInfo.Arguments = "-a";
        process.StartInfo.RedirectStandardOutput = true;
        process.StartInfo.UseShellExecute = false;
        process.StartInfo.CreateNoWindow = true;
        process.Start();

        string output = process.StandardOutput.ReadToEnd();
        process.WaitForExit();

        Console.WriteLine(output);
    }

    static string ConvertToBinarySubnetMask(string subnetMask)
    {
        var binaryMask = subnetMask
            .Split('.')
            .Select(octet => Convert.ToString(int.Parse(octet), 2).PadLeft(8, '0'))
            .Aggregate((a, b) => a + "." + b);

        return binaryMask;
    }

    static SortedDictionary<string, string> ARPSweep(string subnet, int numOfIps)
    {
        var foundDevices = new SortedDictionary<string, string>();
        int j = 0;
        int k = 1;
        Parallel.For(1, numOfIps - 1, i =>
        {               
            string ip = $"{subnet}{i}";
            IPAddress ipAddress;

        
            
            try
            {
                ipAddress = IPAddress.Parse(ip);
            }
            catch (FormatException)
            {
                return;
            }

            byte[] macAddr = new byte[6];
            int len = macAddr.Length;

            try
            {
                int result = SendARP(BitConverter.ToInt32(ipAddress.GetAddressBytes(), 0), 0, macAddr, ref len);

                if (result == 0)
                {
                    var macAddress = FormatMacAddress(macAddr);

                    lock (foundDevices)
                    {
                        j++;
                        Console.WriteLine($"{j}: Host gefunden");
                        if (!foundDevices.ContainsKey(ip))
                        {
                            foundDevices[ip] = macAddress;
                            count++;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Fehler beim Senden von ARP-Request für {ip}: {ex.Message}");
            }
        });

        return foundDevices;
    }

    static (string, string, string) GetLocalIPAddressAndSubnetMask()
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
                        string? gateway = ni.GetIPProperties().GatewayAddresses.FirstOrDefault()?.Address.ToString();
                        return (ipAddress, subnetMask, gateway);
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

    static string FormatMacAddress(byte[] macAddr)
    {
        return string.Join(":", macAddr.Select(b => b.ToString("X2")));
    }

    // Methode zum Abrufen des Hostnamens einer IP-Adresse
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
}
