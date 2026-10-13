using PluginAudits.Core;

namespace PluginAudits.Cli;

/// <summary>
/// Decompiles a verified build with ICSharpCode.Decompiler (the ILSpy engine) into one C# project per plugin DLL.
/// Static only: assemblies are read as metadata and never loaded or executed; a post-run check enforces that.
/// </summary>
internal static class DecompileCommand
{
	public static async Task<int> Run(string root, string key, string? output, bool all, bool force)
	{
		var plugins = Path.Combine(root, "plugins");
		var builds = Build.Load(plugins);
		key = key.Replace('\\', '/').Trim('/');
		if (key.StartsWith("plugins/", StringComparison.Ordinal)) key = key["plugins/".Length..];
		var build = builds.FirstOrDefault(b => b.Key.Equals(key, StringComparison.OrdinalIgnoreCase));
		if (build is null)
		{
			Console.Error.WriteLine($"'{key}' is not listed in plugins/SHA256SUMS. Known builds:");
			foreach (var b in builds) Console.Error.WriteLine("  " + b.Key);
			builds.ForEach(b => b.Dispose());
			return 2;
		}
		builds.Where(b => b != build).ToList().ForEach(b => b.Dispose());
		using var _ = build;

		if (!build.Supplied)
		{
			Console.Error.WriteLine($"{build.Key} is missing: place the zip or its unzipped files in " +
				Path.GetRelativePath(root, build.Folder));
			return 2;
		}

		// Only the published build is decompiled: every plugin DLL must match SHA256SUMS.
		var bad = 0;
		foreach (var entry in build.PluginDlls)
		{
			if (build.Open(entry) is not { } opened)
			{
				Console.Error.WriteLine($"missing  {entry.Relative}");
				bad++;
				continue;
			}
			var actual = await Build.Sha256(opened.Stream);
			if (actual == entry.Expected) Console.WriteLine($"ok       {entry.Relative}");
			else
			{
				Console.Error.WriteLine($"MISMATCH {entry.Relative} (expected {entry.Expected}, got {actual})");
				bad++;
			}
		}
		if (bad > 0 && !force)
		{
			Console.Error.WriteLine("Refusing to decompile: this is not the build the findings describe " +
				"(use --force to decompile it anyway).");
			return 1;
		}

		// The whole package goes to _package/ so references between the plugin's DLLs and its libraries resolve.
		var buildPath = build.Key.Replace('/', Path.DirectorySeparatorChar);
		var outDir = Path.GetFullPath(output ?? Path.Combine(root, "decompiled", buildPath));
		var package = Path.Combine(outDir, "_package");
		Directory.CreateDirectory(package);
		var written = new List<string>();
		foreach (var (name, bytes) in build.PackageDlls())
		{
			var path = Path.Combine(package, name);
			await File.WriteAllBytesAsync(path, bytes);
			written.Add(Path.GetFullPath(path));
		}

		var targets = all
			? written
			: build.PluginDlls
				.Select(e => Path.GetFullPath(Path.Combine(package, e.FileName)))
				.Where(File.Exists)
				.ToList();
		foreach (var dll in targets)
		{
			var name = Path.GetFileNameWithoutExtension(dll);
			if (ReactorDetection.Describe(dll) is { } why)
				Console.WriteLine($"warning  {name}: {why}; its strings or code are encrypted, " +
					"so the output is incomplete. Use the .NET Reactor tools of this repository on this build.");
			Console.WriteLine($"decompile {name} -> {Path.GetRelativePath(root, Path.Combine(outDir, name))}");
			Decompilation.DecompileProject(dll, Path.Combine(outDir, name),
				[package, .. Decompilation.DalamudReferenceDirectories()]);
		}

		// Post-run check: no file of the package may have been loaded into this process.
		var safety = TargetIsolation.Check(written);
		if (safety != 0)
			return safety;

		Console.WriteLine($"\nDone: {targets.Count} projects in {Path.GetRelativePath(root, outDir)}");
		return 0;
	}
}
