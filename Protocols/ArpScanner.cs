using System.Collections.Generic;
using System.Threading.Tasks;
using Netzwerkscanner.dataModels;

namespace Netzwerkscanner.Protocols
{
    public class ArpScanner : IProtocolScanner
    {
        public string ProtocolName => "ARP"; // Implementiere die Property

        public async Task<(List<DeviceInfo> foundDevices, double elapsedSeconds)> ScanAsync(string target, int originalNumOfIps, int[] subnetArray)
        {
            var (foundDevices, elapsedSeconds) = await ARPFunktions.PerformArpSweepAndMeasureTime(originalNumOfIps, subnetArray);

            return (foundDevices, elapsedSeconds); // Tuple zurückgeben
        }

        public void Configure(Dictionary<string, string> settings)
        {
            // Optionale Konfiguration für den ARP-Scanner
        }
    }
}
