// Pfad: /Netzwerkscanner/Program.cs
using System.Net;
using System.Diagnostics;
using Newtonsoft.Json;
using System.Security;
using System.Runtime.InteropServices;
using SnmpSharpNet;
using Newtonsoft.Json.Schema;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json;
using System.IO;
using Netzwerkscanner.dataModels;
using Netzwerkscanner.project;
using Netzwerkscanner.Protocols;
using System.Net.NetworkInformation;

namespace Netzwerkscanner
{
    class Network_Scanner
    {
        public static int count;  // Class-level field for tracking found hosts
        public static int totalTestedIps = 0;  // Shared progress counter
        public static int originalNumOfIps = 0;  // Store the original number of IPs

        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        public static extern int SendARP(int destIp, int srcIp, byte[] macAddr, ref int physicalAddrLen);

        public static async Task Main(string[] args)
        {

            // Netzwerkinformationen abrufen
            var (localIP, subnetMask, gateway) = NetworkscannerFunctions.GetLocalIPAddressAndSubnetMask();
            if (localIP == null || subnetMask == null)
            {
                Console.WriteLine("No local IP address or subnet mask found.");
                return;
            }
            // Berechnung der Anzahl der IP-Adressen
            int subnetzSize = NetworkscannerFunctions.CalcSubnetSize(subnetMask);
            originalNumOfIps = NetworkscannerFunctions.CalcNumOfIps(subnetzSize); // Store original number of IPs in shared class-level variable

            string subnet = NetworkscannerFunctions.GetSubnet(localIP);
            int[] subnetArray = NetworkscannerFunctions.GetSubnetArray(localIP);

            // Ausgabe der Netzwerkinformationen
            InAndOutput.PrintNetworkInfo(localIP, subnet, subnetzSize, gateway);
            NetzwerkInfo netzwerkInfo = new NetzwerkInfo
            {
                LokaleIP = localIP,
                Subnetz = subnet,
                NetworkSize = $"/{subnetzSize}",
                Gateway = gateway
            };

            // Protocol Manager initialisieren
            ProtocolManager protocolManager = new ProtocolManager();

            bool scanSubnet = InAndOutput.GetUserInput("Would you like to scan the network you are in?");
            if (scanSubnet)
            {
                // Wählen Sie ein Protokoll aus der Liste verfügbarer Protokolle
                var availableProtocols = protocolManager.GetAvailableProtocols();
                foreach (var protocol in availableProtocols)
                {
                    Console.WriteLine($"- {protocol}");
                }

                string selectedProtocol = InAndOutput.GetUserInputAndReturnString("Select a protocol for scanning:");
                InAndOutput.PrintNetworkInfo(localIP, subnet, subnetzSize, gateway);
                Console.WriteLine($"The selected protocol is {selectedProtocol}\n");
                var (foundDevices, elapsedSeconds) = await protocolManager.ScanNetwork(selectedProtocol, subnet, originalNumOfIps, subnetArray);

                // Ausgabe der gefundenen Geräte
                InAndOutput.PrintFoundDevices(foundDevices, elapsedSeconds);
            }

            Data data = new Data
            {
                Netzwerk = netzwerkInfo,
                Hosts = InAndOutput.results,
                SwitchInfos = InAndOutput.switchInfos,
            };

            // Switch scannen
            bool scanSwitch = InAndOutput.GetUserInput("Would you like to scan a switch?");
            if (scanSwitch)
            {
                string switchIp = InAndOutput.GetValidIpAddress();

                bool reachable = false; // Flag to track reachability

                while (!reachable)
                {
                    Ping ping = new Ping();
                    PingReply reply = ping.Send(switchIp);

                    if (reply.Status == IPStatus.Success)
                    {
                        Console.WriteLine($"Device reachable {switchIp}");
                        reachable = true;
                    }
                    else
                    {
                        Console.WriteLine($"Device {switchIp} not reachable.");
                        bool tryAgain = InAndOutput.GetUserInput("Would you like to try again?");
                        if (!tryAgain)
                        {
                            Console.WriteLine("Program is terminated.");
                            return;
                        }
                    }
                }

                bool scanSwitchWithPw = InAndOutput.GetUserInputAndClear("Do you have admin rights on the switch?");
                if (scanSwitchWithPw)
                {
                    InAndOutput.RequestAdminCredentialsAndLogin(switchIp);
                }
            }

            // JSON-Schema Validierung und Speichern
            string schemaPath = "C:\\Users\\Dominik\\Documents\\Netzwerkscanner\\jsonSpec.json";
            string schemaJson = File.ReadAllText(schemaPath);

            // JSON-Schema laden
            JSchema schema = JSchema.Parse(schemaJson);

            // Konvertiere die Daten in JSON
            string json = JsonConvert.SerializeObject(data, Formatting.Indented);

            // Validierung der JSON-Daten gegen das Schema
            bool isValid = LoadJson.JsonValidierung(json, schema);

            if (isValid)
            {
                // Wenn gültig, speichere die JSON-Datei
                string dataPath = "C:\\Users\\Dominik\\Documents\\Netzwerkscanner\\result.json";
                File.WriteAllText(dataPath, json);
                Console.WriteLine("The JSON data is valid and has been saved.");
            }
            else
            {
                Console.WriteLine("The JSON data is invalid. Please check the schema and the data.");
            }
        }
    }
}
