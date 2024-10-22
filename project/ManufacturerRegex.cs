using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using Newtonsoft.Json;

public class ArpEntry
{
    public string ip { get; set; }
    public string mac { get; set; }
    public string type { get; set; }
    public string port { get; set; }

}

namespace Netzwerkscanner
{
    public static class ManufacturerRegex
    {
        public static void ArubaRegex(string result, string manufacturer)
        {
            // Allgemeinerer Regex für Aruba-Geräte, um Hersteller, Modell und Gerätetyp zu erfassen
            string systemNamePattern = @"^(?<Hersteller>Aruba)-(?<Modell>\w+)-(?<Geraetetyp>[\w\-]+)";

            // Extrahiere den System Name aus dem Ergebnis
            string systemNamePatternExtract = @"System Name\s+:\s+(.*)";
            string systemName = RegexMatch(result, systemNamePatternExtract);

            // Wende den allgemeinen Regex auf den System Name an
            var match = Regex.Match(systemName, systemNamePattern);

            // Falls der Regex erfolgreich ist, die Gruppen extrahieren
            if (match.Success)
            {
                string model = match.Groups["Modell"].Value;
                string deviceType = match.Groups["Geraetetyp"].Value;

                // Extrahiere Firmware-Version
                string firmwarePattern = @"Software revision\s+:\s+([^\s]+)";
                string firmwareVersion = RegexMatch(result, firmwarePattern);

                // Ausgabe der Switch infos
                InAndOutput.PrintSwitchInfos(manufacturer, model, deviceType, firmwareVersion, result);

                if (InAndOutput.GetUserInputAnDClearMessage("Möchten Sie Erweiterte Informationen zu dem Switch erhalten?"))
                {

                    Console.Clear();
                    string arpTablePattern = @"IP ARP table\s+([\s\S]*?)(?=\n\s*\n|\z)";

                    string arpTable = RegexMatch(result, arpTablePattern);

                    string detailedPattern = @"(\d+\.\d+\.\d+\.\d+)\s+([a-fA-F0-9-]+)\s+(\w+)\s+(\d+)";

                    // Liste für die ARP-Einträge
                    // Liste für die ARP-Einträge
                    List<ArpEntry> arpEntries = new List<ArpEntry>();


                    // Suche nach allen Übereinstimmungen
                    MatchCollection matches = Regex.Matches(arpTable, detailedPattern);
                    foreach (Match matchEntry in matches)
                    {
                        // Extrahiere die IP, MAC, Typ und Port
                        string ip = matchEntry.Groups[1].Value;
                        string mac = matchEntry.Groups[2].Value;
                        string type = matchEntry.Groups[3].Value;
                        string port = matchEntry.Groups[4].Value;

                        // Füge den Eintrag zur Liste hinzu
                        arpEntries.Add(new ArpEntry
                        {
                            ip = ip,
                            mac = mac,
                            type = type,
                            port = port
                        });
                    }

                    var patterns = new Dictionary<string, string>
                        {
                            { "baseMacAddr", @"(Base MAC Addr\s*:\s*[\w-]+)" },
                            { "romVersion", @"(ROM Version\s+:\s+[^\s]+)" },
                            { "serialNumber", @"(Serial Number\s+:\s+[^\s]+)" },
                            { "upTime", @"(Up Time\s*:\s*.+?)" },
                            { "memoryTotal", @"(Memory\s*-\s*Total\s*:\s*[0-9,]+)" },
                            { "freeMemory", @"(Free\s*:\s*[0-9,]+)" },
                            { "cpuUtil", @"(CPU Util \(\%\)\s*:\s*[0-9]+)" }
                        };

                    var systemInformation = new List<string>();

                    // Iteriere über die Patterns und extrahiere die Werte
                    foreach (var pattern in patterns)
                    {
                        string matchValue = RegexMatch(result, pattern.Value);
                        systemInformation.Add(matchValue);
                    }

                    string ipRoutPattern = @"(?<ipRouting>IP Routing\s*:\s*.+?)\n\s*(?<defaultGateway>Default Gateway\s*:\s*.+?)\n\s*(?<defaultTTL>Default TTL\s*:\s*.+?)\n\s*(?<arpAge>Arp Age\s*:\s*.+?)\n\s*(?<domainSuffix>Domain Suffix\s*:\s*.+?)\n\s*(?<dnsServer>DNS server\s*:\s*.+)";



                    Match routingRegex = Regex.Match(result, ipRoutPattern, RegexOptions.Multiline);


                    string runningConfigPattern = @"Running configuration:\s*((?:[^\n]+\n?)+?)(?=\n\s*\n|\Z)";

                    string runningConfig = RegexMatch(result, runningConfigPattern);


                    InAndOutput.PrintSwitchInfos(manufacturer, model, deviceType, firmwareVersion, result);
                    InAndOutput.PrintAdvancedSwitchInfos(result, routingRegex, systemInformation, arpEntries, runningConfig);

                }
            }
            else
            {
                Console.WriteLine("Could not parse the system name.");
            }


        }

        public static void CheckRegex(string manufacturer, string result)
        {
            switch (manufacturer)  // Einstiegspunkt für die Hersteller 
            {
                case "Aruba":
                    ArubaRegex(result, manufacturer);
                    break;
                default:
                    Console.WriteLine($"No special handling for the manufacturer: {manufacturer}");
                    break;
            }
        }

        public static Dictionary<string, string> GetPacketDetails(string result)
        {
            var packetDetails = new Dictionary<string, string>();

            // Regex-Pattern, um die Paketdetails (Total, Buffers, Lowest, Missed) zu erfassen
            string detailPattern = @"(?<Type>Packet\s+-\s+Total|Buffers\s+Free|Lowest|Missed)\s*:\s*(?<Value>\d+)";

            var matches = Regex.Matches(result, detailPattern);
            foreach (Match match in matches)
            {
                // Verwenden einer detaillierteren Beschreibung für die Felder
                string type = match.Groups["Type"].Value.Trim();
                string value = match.Groups["Value"].Value.Trim();

                // Anhand des Typs eine detaillierte Beschreibung festlegen
                string description = type switch
                {
                    "Packet   - Total" => "Total number of parcels",
                    "Buffers    Free" => "Available buffers for incoming packets",
                    "Lowest" => "Lowest number of available buffers",
                    "Missed" => "Missed packages due to missing buffers",
                    _ => type // Standardfall: Originalbezeichnung
                };

                packetDetails.Add(description, value);
            }

            return packetDetails;
        }

        // Hilfsfunktion zur Extraktion der Paketanzahl
        public static Dictionary<string, string> GetPacketCounts(string result)
        {
            var packetCounts = new Dictionary<string, string>();

            // Regex-Muster für empfangene und gesendete Pakete
            string packetPattern = @"(?:Pkts (?:Rx|Tx))\s*:\s*(?<Count>\d[\d,]*)";

            var matches = Regex.Matches(result, packetPattern);
            foreach (Match match in matches)
            {
                // Ersetzen von 'Pkts Rx' und 'Pkts Tx' durch 'Eingehende Pakete' und 'Ausgehende Pakete'
                string type = match.Groups[0].Value.Contains("Rx") ? "Eingehende Pakete" : "Ausgehende Pakete";
                string count = match.Groups["Count"].Value;

                packetCounts.Add(type, count);
            }

            return packetCounts;
        }


        // Hilfsfunktion, um eine Regex auf den result-String anzuwenden
        private static string RegexMatch(string input, string pattern)
        {
            var match = Regex.Match(input, pattern);
            return match.Success ? match.Groups[1].Value.Trim() : "Nicht gefunden";
        }

        public static List<(string VlanName, string Ip, string SubnetMask)> GetVlans(string result)
        {
            // Liste zur Speicherung der VLAN-Daten (Name, erste IP-Adresse, zweite IP-Adresse)
            var vlans = new List<(string VlanName, string Ip, string SubnetMask)>();

            // Regex-Pattern für DEFAULT_VLAN und die regulären VLANs
            string vlanDefaultPattern = @".*DEFAULT_VLAN.*";
            string vlanPattern = @"^\s*([^\|]+)\s*\|\s*(\w+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(.*)";

            // Muster für IP-Adresse (extrahiert aus den gegebenen Patterns)
            string ipPattern = @"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b";

            // Suche nach DEFAULT_VLAN in der Ausgabe
            var vlanDefault = Regex.Match(result, vlanDefaultPattern, RegexOptions.Multiline);
            if (vlanDefault.Success)
            {
                // Erster Treffer (der Name des VLANs)
                string vlanName = Regex.Match(vlanDefault.Value, @"^\s*([^\|]+)").Groups[1].Value;

                // Suche nach IP-Adressen innerhalb von DEFAULT_VLAN
                var ipMatches = Regex.Matches(vlanDefault.Value, ipPattern);
                string ip = ipMatches.Count > 0 ? ipMatches[0].Value : "No IP";
                string subnetMask = ipMatches.Count > 1 ? ipMatches[1].Value : "No IP";

                // Hinzufügen zu den VLANs
                vlans.Add((vlanName.Trim(), ip, subnetMask));
            }

            // Suche nach regulären VLAN-Matches
            var matches = Regex.Matches(result, vlanPattern, RegexOptions.Multiline);
            foreach (Match match in matches)
            {
                // VLAN-Name (Gruppe 1 im Pattern)
                string vlanName = match.Groups[1].Value.Trim();

                // Erste und zweite IP-Adresse (Gruppe 3 und 4 im Pattern)
                string ip = match.Groups[3].Value;
                string subnetMask = match.Groups[4].Value;

                // Hinzufügen zu den VLANs
                vlans.Add((vlanName, ip, subnetMask));
            }

            return vlans;
        }


        // Funktion zum Extrahieren der offenen Ports
        public static List<string> GetOpenPorts(string result)
        {
            List<string> openPorts = new List<string>();

            // Regex für offene Ports (Status "Up")
            string pattern = @"^\s*(\d+)\s+Up";  // Hier wird die Portnummer in der ersten Gruppe erfasst
            Regex regex = new Regex(pattern, RegexOptions.Multiline);

            // Durchlaufe alle Übereinstimmungen im Ergebnistext
            foreach (Match match in regex.Matches(result))
            {
                // Extrahiere die Portnummer (Gruppe 1 im Regex)
                openPorts.Add(match.Groups[1].Value);
            }

            return openPorts;
        }
    }
}

