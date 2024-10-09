using System.Text.RegularExpressions;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using Renci.SshNet;
namespace Netzwerkscanner
{
    public static class Authorization
    {
        public static int i = 0;
        public static bool CheckSwitchLoginWithShell(string switchIp, string username, SecureString password)
        {
            IntPtr ptr = IntPtr.Zero;  // Initialisiere den Pointer

            try
            {
                // Passwort als Plaintext abrufen
                ptr = Marshal.SecureStringToGlobalAllocUnicode(password);
                string plainPassword = Marshal.PtrToStringUni(ptr);

                using (var sshClient = new SshClient(switchIp, username, "WLC7yjR*#NdXp#"))
                {
                    // Versuch, eine Verbindung zum Switch herzustellen
                    sshClient.Connect();

                    if (sshClient.IsConnected)
                    {
                        InAndOutput.PrintAndClear("Erfolgreich eingeloggt!");

                        // Starte eine interaktive Shell-Sitzung
                        var shellStream = sshClient.CreateShellStream("dummy", 0, 0, 0, 0, 1000);

                        // inhalt der ssh nachricht 
                        string sshResult = "";

                        // Allgemeine Systeminformationen des Switches
                        var manufacturer = InAndOutput.OutputStartInfo(shellStream);


                        // Switch system informationen 
                        sshResult += InAndOutput.ExecuteSshCommand("show system", shellStream);

                        // Netzwerkinformationen und Routing-Tabellen
                        sshResult += InAndOutput.ExecuteSshCommand("show arp", shellStream);
                        sshResult += InAndOutput.ExecuteSshCommand("show ip", shellStream);
                        sshResult += InAndOutput.ExecuteSshCommand("show interface status", shellStream);
                        sshResult += InAndOutput.ExecuteSshCommand("show running-config", shellStream);
                        sshResult += InAndOutput.ExecuteSshCommand("", shellStream);




                        ManufacturerRegex.CheckRegex(manufacturer, sshResult);



                        sshClient.Disconnect();
                        return true; // Erfolgreiche Login und Befehlsausführung
                    }
                    else
                    {
                        Console.WriteLine("Login fehlgeschlagen.");
                        return false;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Fehler beim Verbinden oder Ausführen des Befehls: {ex.Message}");
                return false;
            }
            finally
            {
                // Stelle sicher, dass der Speicher für das Passwort freigegeben wird
                if (ptr != IntPtr.Zero)
                {
                    Marshal.ZeroFreeGlobalAllocUnicode(ptr);
                }
            }
        }

        public static string ReadStream(ShellStream shellStream, string befehl)
        {
            StringBuilder output = new StringBuilder();
            string line;

            while (true)
            {

                // Warten, bis Daten verfügbar sind
                while (!shellStream.DataAvailable)
                {
                    Thread.Sleep(500);
                }

                // Lese die Zeile
                line = shellStream.ReadLine();

                if (line.Contains("-- MORE --"))
                {
                    shellStream.WriteLine("-");
                    if (i > 0)
                    {
                        shellStream.ReadLine();
                    }
                    i++;
                    continue;
                }



                // Überprüfe auf Endesignale
                if (line.Contains(">") || line.Contains("#") || line.Contains("$") || line.Contains("Press any key to continue"))
                {
                    break;
                }

                // Füge die Zeile zum Output hinzu
                output.AppendLine(line);

            }
            return output.ToString();
        }


        public static SecureString ReadPassword()
        {
            SecureString password = new SecureString();
            ConsoleKeyInfo key;

            do
            {
                key = Console.ReadKey(true); // true sorgt dafür, dass die Eingabe nicht angezeigt wird

                if (key.Key != ConsoleKey.Enter && key.Key != ConsoleKey.Backspace)
                {
                    password.AppendChar(key.KeyChar); // Passwort-Zeichen hinzufügen
                    Console.Write("*"); // Sternchen anzeigen
                }
                else if (key.Key == ConsoleKey.Backspace && password.Length > 0)
                {
                    // Entferne das letzte Zeichen aus dem SecureString
                    password.RemoveAt(password.Length - 1);
                    Console.Write("\b \b"); // Backspace-Effekt in der Konsole
                }
            }
            while (key.Key != ConsoleKey.Enter); // Ende der Eingabe bei Enter

            Console.WriteLine(); // Um zur nächsten Zeile zu springen, nachdem Enter gedrückt wurde

            password.MakeReadOnly(); // Macht das Passwort unveränderlich
            return password;
        }
    }
}
