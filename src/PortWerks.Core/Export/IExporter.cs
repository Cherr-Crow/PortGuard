using System.Threading.Tasks;
using PortWerks.Core.Models;

namespace PortWerks.Core.Export
{
    public interface IExporter
    {
        Task<string> ExportAsync(ScanResult result);
        string FileExtension { get; }
    }
}
