using System.Text.Json;

namespace PluginAudits.Cli;

/// <summary>
/// Checks a findings file against your own copy of the build and the tool's output: the build must match the listed
/// hashes, and every evidence entry must be found (or, for "absent", not found) in the output. A finding is reported as
/// reproduced only when all its evidence holds, so no description has to be taken on trust.
/// </summary>
internal static class CheckCommand
{
	private sealed record Evidence(string? File, string? Member, string? Contains, string? Files, string? Absent);
	private sealed record Finding(string Id, string Description, List<Evidence> Evidence);
	private sealed record Reproduce(string Command, string Output);
	private sealed record FindingsFile(
		string Plugin, string Version, Dictionary<string, string> Build, Reproduce Reproduce, List<Finding> Findings);

	public static async Task<int> Run(string root, string findingsPath, string? output)
	{
		var doc = JsonSerializer.Deserialize<FindingsFile>(File.ReadAllText(findingsPath),
			new JsonSerializerOptions { PropertyNameCaseInsensitive = true })!;
		Console.WriteLine($"{doc.Plugin} {doc.Version}: {doc.Findings.Count} findings\n");

		// 1. The build must be the one the findings were made from.
		var builds = Build.Load(Path.Combine(root, "plugins"));
		var buildOk = true;
		foreach (var (relative, sha) in doc.Build)
		{
			var key = relative[..relative.LastIndexOf('/')];
			var build = builds.FirstOrDefault(b => b.Key == key);
			var opened = build?.Open(new ChecksumEntry(sha, relative));
			if (opened is null)
			{
				Console.WriteLine($"missing  {relative}  (place the build in plugins/{key}/, see plugins/README.md)");
				buildOk = false;
				continue;
			}
			var actual = await Build.Sha256(opened.Value.Stream);
			Console.WriteLine(actual == sha
				? $"ok       {relative}"
				: $"MISMATCH {relative} (expected {sha}, got {actual})");
			buildOk &= actual == sha;
		}
		builds.ForEach(b => b.Dispose());
		if (!buildOk)
		{
			Console.Error.WriteLine("\nThe build doesn't match the findings; nothing was checked.");
			return 1;
		}

		// 2. Every evidence entry must hold in the tool's output.
		var outDir = Path.GetFullPath(Path.Combine(root, output ?? doc.Reproduce.Output));
		if (!Directory.Exists(outDir))
		{
			Console.Error.WriteLine($"\nNo output in {Path.GetRelativePath(root, outDir)}. Produce it first:\n" +
				$"  {doc.Reproduce.Command}");
			return 2;
		}
		Console.WriteLine($"\noutput: {Path.GetRelativePath(root, outDir)}\n");

		var failed = 0;
		foreach (var finding in doc.Findings)
		{
			var problems = finding.Evidence.Select(e => Check(outDir, e)).OfType<string>().ToList();
			if (problems.Count == 0)
			{
				Console.WriteLine($"reproduced      {finding.Id}  ({finding.Evidence.Count} evidence)");
				continue;
			}
			failed++;
			Console.WriteLine($"NOT reproduced  {finding.Id}");
			foreach (var p in problems) Console.WriteLine($"                - {p}");
		}

		Console.WriteLine($"\n{doc.Findings.Count - failed} of {doc.Findings.Count} findings reproduced");
		return failed == 0 ? 0 : 1;
	}

	/// <summary>Returns why an evidence entry does not hold, or null when it does.</summary>
	private static string? Check(string outDir, Evidence e)
	{
		if (e.Absent is not null && e.Files is not null)
		{
			var files = Expand(outDir, e.Files).ToList();
			if (files.Count == 0) return $"no files match {e.Files}";
			var hit = files.FirstOrDefault(f => File.ReadAllText(f).Contains(e.Absent, StringComparison.Ordinal));
			return hit is null ? null : $"\"{e.Absent}\" found in {Path.GetRelativePath(outDir, hit)}";
		}
		if (e.File is null || e.Contains is null) return "evidence needs file + contains, or files + absent";

		var path = Path.Combine(outDir, e.File.Replace('/', Path.DirectorySeparatorChar));
		if (!File.Exists(path)) return $"{e.File} not found";
		var text = File.ReadAllText(path);
		if (e.Member is not null)
		{
			var name = e.Member[(Math.Max(e.Member.LastIndexOf('.'), e.Member.LastIndexOf(':')) + 1)..];
			if (!text.Contains(name + "(", StringComparison.Ordinal)) return $"member {e.Member} not found in {e.File}";
		}
		return text.Contains(e.Contains, StringComparison.Ordinal) ? null : $"{e.File} doesn't contain: {e.Contains}";
	}

	/// <summary>Expands "dir/file.cs", "dir/*.cs" or "dir/**/*.cs" relative to the output folder.</summary>
	private static IEnumerable<string> Expand(string outDir, string pattern)
	{
		var p = pattern.Replace('\\', '/');
		var recursive = p.Contains("/**/");
		var relativeDir = recursive ? p[..p.IndexOf("/**/")] : Path.GetDirectoryName(p) ?? "";
		var dir = Path.Combine(outDir, relativeDir.Replace('/', Path.DirectorySeparatorChar));
		var name = recursive ? p[(p.IndexOf("/**/") + 4)..] : Path.GetFileName(p);
		return Directory.Exists(dir)
			? Directory.EnumerateFiles(dir, name,
				recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly)
			: [];
	}
}
