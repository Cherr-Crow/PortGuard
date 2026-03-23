using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Serialization;
using PortWerks.Core.Models;

namespace PortWerks.Core.Export
{
    public class XmlExporter : IExporter
    {
        public string FileExtension => ".xml";

        public Task<string> ExportAsync(ScanResult result)
        {
            var serializer = new XmlSerializer(typeof(ScanResult));
            using var stringWriter = new StringWriter();
            serializer.Serialize(stringWriter, result);
            return Task.FromResult(stringWriter.ToString());
        }
    }
}
