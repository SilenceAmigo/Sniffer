using System.Reflection;

namespace Netzwerkscanner
{
    public static class LoadJson
    {
        public static string LoadEmbeddedJson()
        {
            var assembly = Assembly.GetExecutingAssembly();
            var resourceName = "Netzwerkscanner.ports.lists.json";

            using (Stream stream = assembly.GetManifestResourceStream(resourceName))
            using (StreamReader reader = new StreamReader(stream))
            {
                return reader.ReadToEnd();
            }
        }
    }
    public class PortInfo
    {
        public string Description { get; set; }
        public bool Udp { get; set; }
        public string Status { get; set; }
        public string Port { get; set; }
        public bool Tcp { get; set; }
    }
}