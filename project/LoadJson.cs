using System.Reflection;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json.Schema;

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
        public static bool JsonValidierung(string json, JSchema schema)
        {
            // Konvertiere den JSON-String in ein JToken
            JToken jsonToken = JToken.Parse(json);

            // Überprüfe, ob das JToken dem Schema entspricht
            bool isValid = jsonToken.IsValid(schema, out IList<string> validationErrors);

            // Ausgabe der Fehler, falls vorhanden
            if (!isValid)
            {
                foreach (string error in validationErrors)
                {
                    Console.WriteLine($"Error: {error}");
                }
            }

            return isValid;
        }

        public static string LoadIeeeMacDatabase()
        {
            string resourceName = "Netzwerkscanner.IEEEMacAdress.json";

            // Die Assembly der laufenden Anwendung abrufen
            var assembly = Assembly.GetExecutingAssembly();

            // Eingebettete Ressource als Stream lesen
            using (Stream stream = assembly.GetManifestResourceStream(resourceName))
            {
                using (StreamReader reader = new StreamReader(stream))
                {
                    string jsonContent = reader.ReadToEnd();
                    return jsonContent;
                }
            }
        }
    }

}