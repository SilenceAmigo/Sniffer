using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;

namespace Netzwerkscanner
{
    public static class ARPFunktions
    {
        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        public static extern int SendARP(int destIp, int srcIp, byte[] macAddr, ref int physicalAddrLen);
        public static async Task<(SortedDictionary<string, (string MacAddress, string Manufacturer, double Latency)>, double)> PerformArpSweepAndMeasureTime(int numOfIps, int[] subnetArray, bool showAllInfo)

        {
            Stopwatch stopwatch = new Stopwatch();
            stopwatch.Start();

            var foundDevices = await ARPSweep(numOfIps, subnetArray);

            stopwatch.Stop();

            return (foundDevices, stopwatch.Elapsed.TotalSeconds);
        }

        public static async Task<SortedDictionary<string, (string MacAddress, string Manufacturer, double Latency)>> ARPSweep(int numOfIps, int[] subnetArray)
        {
            var foundDevices = new SortedDictionary<string, (string MacAddress, string Manufacturer, double Latency)>();
            int totalIps = Network_Scanner.originalNumOfIps;  // Use the shared original number of IPs
            int testedIps = 0;

            if (numOfIps <= 0)
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
                //Console.WriteLine(ip);
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
                Interlocked.Increment(ref Network_Scanner.totalTestedIps); // Update the shared progress counter

                InAndOutput.UpdateProgressBar(Network_Scanner.totalTestedIps, totalIps, progressBarLength, consoleLock);

            });

            // Recursive Call
            subnetArray = NetworkscannerFunctions.NextIp(subnetArray);
            var foundDevicesRek = await ARPSweep(numOfIps - 256, subnetArray);
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
        static string CreateIpAddress(int[] subnetArray, int i)
        {
            string subnet = string.Join(".", subnetArray.Take(subnetArray.Length - 1));
            return $"{subnet}.{i}";
        }

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
                    var macAddress = NetworkscannerFunctions.FormatMacAddress(macAddr);

                    NetworkscannerFunctions.AddDeviceIfNew(ipAddress.ToString(), macAddress, latency, foundDevices);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Fehler beim Senden von ARP-Request für {ipAddress}: {ex.Message}");
            }
        }
    }
}
