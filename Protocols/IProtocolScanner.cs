using System.Collections.Generic;
using System.Threading.Tasks;
using Netzwerkscanner.dataModels;

namespace Netzwerkscanner.Protocols
{
    public interface IProtocolScanner
    {
        string ProtocolName { get; }  // Name des Protokolls

        Task<(List<DeviceInfo> foundDevices, double elapsedSeconds)> ScanAsync(string target, int originalNumOfIps, int[] subnetArray);  // Scan-Methode

        void Configure(Dictionary<string, string> settings);  // Optionale Konfiguration
    }
}
