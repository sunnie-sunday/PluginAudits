using System.IO.Compression;
using System.Security.Cryptography;

namespace PluginAudits.Cli;

/// <summary>
/// One line of plugins/SHA256SUMS: <c>&lt;sha256&gt;  &lt;plugin&gt;/&lt;version&gt;/&lt;file&gt;</c>.
/// </summary>
internal sealed record ChecksumEntry(string Expected, string Relative)
{
	public string FileName => Relative[(Relative.LastIndexOf('/') + 1)..];
	public bool IsZip => Relative.EndsWith(".zip", StringComparison.OrdinalIgnoreCase);
}

/// <summary>
/// A build folder (<c>plugins/&lt;plugin&gt;/&lt;version&gt;/</c>) as listed in SHA256SUMS: its release zip and the
/// plugin's own DLLs. The auditor supplies either the zip as-is or the unzipped files; both are read without
/// extracting anything.
/// </summary>
internal sealed class Build : IDisposable
{
	private readonly ZipArchive? _zip;

	private Build(string key, string folder, List<ChecksumEntry> entries)
	{
		Key = key;
		Folder = folder;
		Entries = entries;
		Zip = entries.FirstOrDefault(e => e.IsZip);
		if (Zip is not null && File.Exists(PathOf(Zip)))
			_zip = ZipFile.OpenRead(PathOf(Zip));
	}

	public string Key { get; }
	public string Folder { get; }
	public List<ChecksumEntry> Entries { get; }
	public ChecksumEntry? Zip { get; }
	public IEnumerable<ChecksumEntry> PluginDlls => Entries.Where(e => !e.IsZip);
	public bool Supplied => Entries.Any(e => File.Exists(PathOf(e)));

	public static List<Build> Load(string plugins) =>
		File.ReadLines(Path.Combine(plugins, "SHA256SUMS"))
			.Select(line => line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries))
			.Where(f => f.Length >= 2 && !f[0].StartsWith('#'))
			.Select(f => new ChecksumEntry(f[0].ToLowerInvariant(), f[1]))
			.GroupBy(e => e.Relative.Contains('/') ? e.Relative[..e.Relative.LastIndexOf('/')] : "")
			.Select(g => new Build(
				g.Key, Path.Combine(plugins, g.Key.Replace('/', Path.DirectorySeparatorChar)), g.ToList()))
			.ToList();

	public string PathOf(ChecksumEntry entry) => Path.Combine(Folder, entry.FileName);

	/// <summary>Opens a listed file from the folder, or from inside the zip when only the zip was supplied.</summary>
	public (Stream Stream, bool InZip)? Open(ChecksumEntry entry)
	{
		if (File.Exists(PathOf(entry)))
			return (File.OpenRead(PathOf(entry)), false);
		if (!entry.IsZip && ZipEntry(entry.FileName) is { } inZip)
			return (inZip.Open(), true);
		return null;
	}

	/// <summary>Every DLL of the package (plugin and third-party), from the zip or the folder, as raw bytes.</summary>
	public IEnumerable<(string Name, byte[] Bytes)> PackageDlls()
	{
		if (_zip is not null)
		{
			foreach (var e in _zip.Entries)
			{
				var name = e.FullName.Replace('\\', '/');
				if (name.Contains('/') || !name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)) continue;
				using var s = e.Open();
				using var ms = new MemoryStream();
				s.CopyTo(ms);
				yield return (name, ms.ToArray());
			}
			yield break;
		}
		foreach (var f in Directory.EnumerateFiles(Folder, "*.dll"))
			yield return (Path.GetFileName(f), File.ReadAllBytes(f));
	}

	private ZipArchiveEntry? ZipEntry(string fileName) =>
		_zip?.Entries.FirstOrDefault(e => e.FullName.Replace('\\', '/') == fileName);

	public void Dispose() => _zip?.Dispose();

	public static async Task<string> Sha256(Stream input)
	{
		await using var stream = input;
		return Convert.ToHexString(await SHA256.HashDataAsync(stream)).ToLowerInvariant();
	}
}
