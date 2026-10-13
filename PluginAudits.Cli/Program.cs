// pluginaudits: build verification and decompilation for the audited plugins. Cross-platform, no network access.
//
//   pluginaudits verify [--root <repo>]
//       Checks the plugin builds you placed in plugins/ against plugins/SHA256SUMS, and lists the ones still missing.
//   pluginaudits decompile <plugin>/<version> [-o <dir>] [--all] [--force] [--root <repo>]
//       Decompiles a verified build's own DLLs into C# projects (default: decompiled/<plugin>/<version>/).
//       --all also decompiles its third-party libraries; --force decompiles a build that does not match SHA256SUMS.
//   pluginaudits check <findings.json> [--output <dir>] [--root <repo>]
//       Checks a findings file: the build's hashes, then every evidence entry against the tool's output.
//
// Third-party builds are never downloaded, stored or linked by the repository: each auditor sources their own copy.
using PluginAudits.Cli;

const string Usage = """
    usage:
      pluginaudits verify [--root <repo>]
      pluginaudits decompile <plugin>/<version> [-o <dir>] [--all] [--force] [--root <repo>]
      pluginaudits check <findings.json> [--output <dir>] [--root <repo>]
    """;

var options = args.ToList();
var root = TakeOption(options, "--root") is { } r ? Path.GetFullPath(r) : FindRoot();
if (options.Count == 0 || options[0] is "-h" or "--help")
{
	Console.WriteLine(Usage);
	return 0;
}
if (root is null)
{
	Console.Error.WriteLine("PluginAudits.slnx not found; run from the repository or pass --root <repo>.");
	return 2;
}

switch (options[0])
{
	case "verify":
		return await VerifyCommand.Run(root);
	case "decompile":
		{
			var output = TakeOption(options, "-o") ?? TakeOption(options, "--output");
			var all = options.Remove("--all");
			var force = options.Remove("--force");
			if (options.Count != 2)
			{
				Console.Error.WriteLine(Usage);
				return 2;
			}
			return await DecompileCommand.Run(root, options[1], output, all, force);
		}
	case "check":
		{
			var output = TakeOption(options, "--output");
			if (options.Count != 2)
			{
				Console.Error.WriteLine(Usage);
				return 2;
			}
			return await CheckCommand.Run(root, Path.GetFullPath(options[1]), output);
		}
	default:
		Console.Error.WriteLine($"unknown command '{options[0]}'\n{Usage}");
		return 2;
}

static string? TakeOption(List<string> options, string name)
{
	var i = options.IndexOf(name);
	if (i < 0 || i + 1 >= options.Count) return null;
	var value = options[i + 1];
	options.RemoveRange(i, 2);
	return value;
}

// The repository root is the folder holding PluginAudits.slnx, found from the current directory upwards.
static string? FindRoot()
{
	for (var dir = new DirectoryInfo(Directory.GetCurrentDirectory()); dir is not null; dir = dir.Parent)
		if (File.Exists(Path.Combine(dir.FullName, "PluginAudits.slnx")))
			return dir.FullName;
	return null;
}
