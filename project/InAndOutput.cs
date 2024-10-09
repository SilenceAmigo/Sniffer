using System.Security;
using System.Text.RegularExpressions;
using Microsoft.VisualBasic;
using Newtonsoft.Json;
using Renci.SshNet;

namespace Netzwerkscanner
{
    public static class InAndOutput
    {
        // Fragt den Benutzer nach einer Ja/Nein-Eingabe und wiederholt die Eingabe bei ungültigen Werten.
        public static bool GetUserInput(string question)
        {
            string input;
            do
            {
                Console.WriteLine(question + " (y/n):");
                input = Console.ReadLine()?.Trim().ToLower();

                if (input != "y" && input != "n")
                {
                    Console.WriteLine("Ungültige Eingabe. Bitte 'y' für Ja oder 'n' für Nein eingeben.\n");

                }
            } while (input != "y" && input != "n");

            return input == "y";
        }

        public static bool GetUserInputAnDClearMessage(string message)
        {
            string input;
            do
            {
                Console.WriteLine(message + " (y/n):");
                input = Console.ReadLine()?.Trim().ToLower();

                if (input != "y" && input != "n")
                {
                    Console.WriteLine("Ungültige Eingabe. Bitte 'y' für Ja oder 'n' für Nein eingeben.\n");

                }
            } while (input != "y" && input != "n");

            return input == "y";
        }

        // Fragt nach einer Ja/Nein-Eingabe, löscht das Display und überprüft die Eingabe.
        public static bool GetUserInputAndClear(string message)
        {
            string input;
            do
            {
                Console.WriteLine(message + " (y/n):");
                input = Console.ReadLine()?.Trim().ToLower();
                Console.Clear();

                if (input != "y" && input != "n")
                {
                    Console.WriteLine("Ungültige Eingabe. Bitte 'y' für Ja oder 'n' für Nein eingeben.");
                }
            } while (input != "y" && input != "n");

            return input == "y";
        }

        // Zeigt eine Nachricht an, fordert eine Eingabe an und gibt die Eingabe zurück. Prüft, ob die Eingabe leer ist.
        public static string PrintAndClearGetInput(string message)
        {
            string input;
            do
            {
                Console.WriteLine(message);
                input = Console.ReadLine()?.Trim();

                if (string.IsNullOrEmpty(input))
                {
                    Console.WriteLine("Ungültige Eingabe. Bitte geben Sie einen Wert ein.");
                }
            } while (string.IsNullOrEmpty(input));

            Console.Clear();
            return input;
        }

        public static string GetValidIpAddress()
        {
            string ipAddress = string.Empty;
            bool isValid = false;

            // Solange die Eingabe keine gültige IP-Adresse ist, wird die Eingabe wiederholt
            while (!isValid)
            {
                Console.WriteLine("Bitte geben Sie eine gültige IP-Adresse ein:");
                ipAddress = Console.ReadLine();

                // Überprüfen, ob die eingegebene IP-Adresse im gültigen Format ist
                if (IsValidIpAddress(ipAddress))
                {
                    isValid = true;
                }
                else
                {
                    Console.WriteLine("Ungültige IP-Adresse! Bitte eine korrekte IP-Adresse eingeben. \n");
                }
            }

            return ipAddress;
        }

        // Überprüfen, ob eine gegebene IP-Adresse gültig ist
        private static bool IsValidIpAddress(string ipAddress)
        {
            // Muster für eine gültige IPv4-Adresse
            string pattern = @"^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\." +
                             @"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\." +
                             @"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\." +
                             @"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$";

            // Regex zur Validierung der IP-Adresse
            return Regex.IsMatch(ipAddress, pattern);
        }

        public static void PrintAdvancedSwitchInfos(string result, Match routingRegex, List<string> systemInformation, string arpTable, string runningConfig)
        {
            Console.WriteLine("Erweiterte Informationen:");
            Console.WriteLine(new string('─', 60));

            if (routingRegex.Success)
            {
                Console.WriteLine("Routing Informationen:\n");
                for (int i = 1; i < routingRegex.Groups.Count; i++)
                {
                    Console.WriteLine(routingRegex.Groups[i].Value);
                }
            }
            Console.WriteLine(new string('─', 60));

            Console.WriteLine("System Informationen:\n");

            // Verwende einheitliches Format für die Ausgabe
            foreach (var info in systemInformation)
            {
                // Hier wird angenommen, dass jede Zeile ein Format wie "Bezeichnung : Wert" hat
                var parts = info.Split(new[] { ':' }, 2); // Teile den String in zwei Teile

                if (parts.Length == 2) // Stelle sicher, dass es zwei Teile gibt
                {
                    string label = parts[0].Trim(); // Bezeichnung
                    string value = parts[1].Trim(); // Wert

                    // Formatiere die Ausgabe mit einem festen Abstand
                    Console.WriteLine($"{label,-20} : {value}");
                }
                else
                {
                    Console.WriteLine(info); // Falls es nicht das erwartete Format hat, gib es einfach so aus
                }
            }
            Console.WriteLine(new string('─', 60));
            Console.WriteLine("Arp-Table:\n");
            Console.WriteLine(arpTable);
            Console.WriteLine(new string('─', 60));

            Console.WriteLine("Running configuration:\n");
            Console.WriteLine(runningConfig);
            Console.WriteLine(new string('─', 60));


        }


        // Zeigt eine Nachricht an und wartet für 1 Sekunde, bevor das Display gelöscht wird.
        public static void PrintAndClear(string message)
        {
            Console.WriteLine(message);
            Thread.Sleep(1000);
            Console.Clear();
        }

        // Zeigt die gefundenen Geräte an.
        public static void PrintFoundDevices(SortedDictionary<string, (string MacAddress, string Manufacturer, double Latency)> foundDevices, bool showAllInfo)
        {
            Console.WriteLine("\n\nGefundene Geräte sortiert nach IP-Adresse:\n\n");
            int i = 0;
            foreach (var device in foundDevices)
            {
                i++;
                string hostname = NetworkscannerFunctions.GetHostName(device.Key);
                Console.WriteLine($"Host Nr {i}\nIp-Adresse: {device.Key}\nMAC-Adresse: {device.Value.MacAddress}\nHostname: {hostname}\nHersteller: {device.Value.Manufacturer}\nLatenz: {device.Value.Latency} s\n\n");
            }
            Console.WriteLine($"\n{Network_Scanner.count} Hosts gefunden");
        }

        // Gibt Netzwerkinformationen aus.
        public static void PrintNetworkInfo(string localIP, string subnet, int subnetzSize, string gateway)
        {
            Console.Clear();
            Console.WriteLine("Netzwerkinformationen:");
            Console.WriteLine($"- Lokale IP-Adresse: {localIP}");
            Console.WriteLine($"- Subnetz: {subnet}");
            Console.WriteLine($"- Netzgröße: /{subnetzSize}");
            Console.WriteLine($"- Gateway: {gateway}");
            Console.WriteLine();
        }

        // Gibt eine Zusammenfassung der Scans aus.
        public static void PrintSummary(double elapsedSeconds)
        {
            Console.WriteLine($"Dauer des ARP-Sweeps: {elapsedSeconds:F2} Sekunden");
            Console.WriteLine($"Anzahl der gefundenen Hosts: {Network_Scanner.count}");
            Console.WriteLine();
        }

        // Fragt nach Administrator-Zugangsdaten und versucht, sich per SSH anzumelden.
        public static void RequestAdminCredentialsAndLogin(string switchIp, string manufacturer, string macAddress)
        {
            Console.WriteLine($"Scanne Gerät von: {manufacturer} ({switchIp}) mit der MAC-Adresse {macAddress}");

            Console.WriteLine("Bitte geben Sie den Benutzernamen des Admins ein:");
            string adminName = Console.ReadLine();

            Console.WriteLine("Bitte geben Sie das Passwort des Admins ein:");
            SecureString password = Authorization.ReadPassword(); // Hier wird das Passwort ohne Sichtbarkeit eingegeben

            Authorization.CheckSwitchLoginWithShell(switchIp, adminName, password);
        }

        // Fortschrittsanzeige für Scans in der Konsole.
        public static void UpdateProgressBar(int current, int total, int progressBarLength, object consoleLock)
        {
            if (total > 0)
            {
                double progressPercentage = Math.Min((current / (double)total), 1.0);
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
        }

        // Start-Informationen anzeigen und Benutzerabfragen.
        public static string OutputStartInfo(ShellStream shellStream)
        {
            string manufacturer = "";
            shellStream.WriteLine("");
            string result = Authorization.ReadStream(shellStream, "");

            if (!string.IsNullOrEmpty(result))
            {
                if (result.Contains("Aruba"))
                {
                    manufacturer = "Aruba";
                }
                shellStream.WriteLine("A");
                Authorization.ReadStream(shellStream, "A");
            }
            return manufacturer;
        }

        // Führt einen SSH-Befehl aus, liest die Ausgabe und zeigt sie an.
        public static string ExecuteSshCommand(string command, ShellStream shellStream)
        {
            shellStream.WriteLine(command);
            Authorization.ReadStream(shellStream, "");
            shellStream.WriteLine("A");
            string result = Authorization.ReadStream(shellStream, "");
            shellStream.Flush();

            return result;
        }

        public static void PrintSwitchInfos(string manufacturer, string model, string deviceType, string firmwareVersion, string result)
        {
            Console.WriteLine(new string('─', 60));
            Console.WriteLine($"-Hersteller        : {manufacturer}");
            Console.WriteLine($"-Modell            : {model}");
            Console.WriteLine($"-Gerätetyp         : {deviceType}");
            Console.WriteLine($"-Firmware-Version  : {firmwareVersion}");
            Console.WriteLine(new string('─', 60));

            string json = LoadJson.LoadEmbeddedJson();
            // Deserialisiere den JSON-String in ein PortsList-Objekt
            var portsDictionary = JsonConvert.DeserializeObject<Dictionary<string, List<PortInfo>>>(json);


            // Jetzt die offenen Ports extrahieren und ausgeben
            List<string> openPorts = ManufacturerRegex.GetOpenPorts(result);
            Console.WriteLine("Offene Ports:\n");
            if (openPorts.Count > 0)
            {
                foreach (var port in openPorts)
                {
                    string portTrimmed = port.Trim(); // Entferne mögliche Leerzeichen

                    if (portsDictionary.TryGetValue(portTrimmed, out var portInfoList))
                    {
                        foreach (var portInfo in portInfoList)
                        {
                            Console.WriteLine($"-{portTrimmed}\t{portInfo.Description}");
                        }
                    }
                }
            }
            else
            {
                Console.WriteLine("Keine offenen Ports gefunden.");
            }
            Console.WriteLine(new string('─', 60));

            // VLAN-Informationen anzeigen
            var vlans = ManufacturerRegex.GetVlans(result);
            if (vlans.Count > 0)
            {
                // Kopfzeile für die Tabelle
                Console.WriteLine($"{"VLAN",-20} {"IP Address",-20} {"Subnet Mask",-20}");
                Console.WriteLine(new string('-', 60)); // Längere Trennlinie

                // Ausgabe jeder Zeile in der Tabelle
                foreach (var vlan in vlans)
                {
                    Console.WriteLine($"{vlan.VlanName,-20} {vlan.Ip,-20} {vlan.SubnetMask,-20}");
                }
            }
            Console.WriteLine(new string('─', 60));

            // Eingehende und ausgehende Pakete anzeigen
            var packetCounts = ManufacturerRegex.GetPacketCounts(result);
            if (packetCounts.Count > 0)
            {
                Console.WriteLine("Empfangene und gesendete Pakete:\n");
                foreach (var packet in packetCounts)
                {
                    Console.WriteLine($"{packet.Key} : {packet.Value}");
                }
            }
            else
            {
                Console.WriteLine("Keine Paketinformationen gefunden.");
            }

            var packetDetails = ManufacturerRegex.GetPacketDetails(result);
            if (packetDetails.Count > 0)
            {
                Console.WriteLine("\nPaketdetails:\n");
                foreach (var detail in packetDetails)
                {
                    Console.WriteLine($"{detail.Key} : {detail.Value}");
                }
            }
            else
            {
                Console.WriteLine("Keine weiteren Paketdetails gefunden.");
            }
            Console.WriteLine(new string('─', 60));
        }
    }
}
