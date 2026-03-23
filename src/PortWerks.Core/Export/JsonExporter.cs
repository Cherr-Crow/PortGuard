using System.Threading.Tasks;
using Newtonsoft.Json;
using PortWerks.Core.Models;

namespace PortWerks.Core.Export
{
    public class JsonExporter : IExporter
    {
        public string FileExtension => ".json";

        public Task<string> ExportAsync(ScanResult result)
        {
            var json = JsonConvert.SerializeObject(result, Formatting.Indented, new JsonSerializerSettings
            {
                NullValueHandling = NullValueHandling.Ignore,
                DateFormatString = "yyyy-MM-dd HH:mm:ss"
            });

            return Task.FromResult(json);
        }
    }
}
