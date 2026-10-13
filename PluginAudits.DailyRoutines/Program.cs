using System.IO.Compression;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using PluginAudits.Core;

namespace PluginAudits.DailyRoutines;

internal static class Program
{
	private const string Usage = """
        drdecrypt — statically decompile DailyRoutines or NyaDraw (both NekoAuth plugins) and decrypt their
        .NET Reactor string tables.

        Usage:
          drdecrypt <input>... [-o <output-dir>] [--all] [--trust-decryptor]

        <input>             A release zip (latest.zip), a directory of DLLs, or individual .dll files.
        -o, --output        Output directory (default: ./decrypted).
        --all               Process every managed DLL, not just DailyRoutines*, OmenTools* and NyaDraw*.
        --trust-decryptor   Run the rebuilt decryptor even if it uses APIs outside the safety allowlist.
        """;

	private static readonly JsonSerializerOptions Json = new()
	{
		WriteIndented = true,
		Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
	};

	private static int Main(string[] args)
	{
		var inputs = new List<string>();
		var output = Path.GetFullPath("decrypted");
		bool all = false, trust = false;

		for (var i = 0; i < args.Length; i++)
		{
			switch (args[i])
			{
				case "-o" or "--output" when i + 1 < args.Length:
					output = Path.GetFullPath(args[++i]);
					break;
				case "--all":
					all = true;
					break;
				case "--trust-decryptor":
					trust = true;
					break;
				case "-h" or "--help":
					Console.WriteLine(Usage);
					return 0;
				default:
					inputs.Add(args[i]);
					break;
			}
		}
		if (inputs.Count == 0)
		{
			Console.Error.WriteLine(Usage);
			return 2;
		}

		Directory.CreateDirectory(output);
		var assemblies = ResolveInputs(inputs, output, all);
		if (assemblies.Count == 0)
		{
			Console.Error.WriteLine("No matching managed assemblies found (use --all to include third-party DLLs).");
			return 1;
		}

		var failures = 0;
		foreach (var assembly in assemblies)
		{
			try
			{
				ProcessAssembly(assembly, output, trust);
			}
			catch (Exception ex)
			{
				failures++;
				Console.Error.WriteLine($"  FAILED: {ex.Message}");
			}
		}

		// Post-run check: the rebuilt decryptor runs in its own collectible context; the plugin itself never may.
		var safety = TargetIsolation.Check(assemblies);
		if (safety != 0)
			return safety;

		Console.WriteLine($"\nDone. Output in {output}");
		return failures == 0 ? 0 : 1;
	}

	private static List<string> ResolveInputs(List<string> inputs, string output, bool all)
	{
		var files = new List<string>();
		foreach (var input in inputs)
		{
			if (File.Exists(input) && input.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
			{
				var extracted = Path.Combine(output, "_package");
				Console.WriteLine($"Extracting {Path.GetFileName(input)} -> {extracted}");
				ZipFile.ExtractToDirectory(input, extracted, overwriteFiles: true);
				files.AddRange(Directory.EnumerateFiles(extracted, "*.dll", SearchOption.TopDirectoryOnly));
			}
			else if (Directory.Exists(input))
			{
				files.AddRange(Directory.EnumerateFiles(input, "*.dll", SearchOption.TopDirectoryOnly));
			}
			else if (File.Exists(input))
			{
				files.Add(input);
				all = true; // explicitly named files are always processed
			}
			else
			{
				Console.Error.WriteLine($"Input not found: {input}");
			}
		}

		return files
			.Select(Path.GetFullPath)
			.Distinct()
			.Where(f => all || IsFirstParty(Path.GetFileName(f)))
			.Where(Decompilation.IsManagedAssembly)
			.OrderBy(f => f, StringComparer.Ordinal)
			.ToList();
	}

	// The plugins' own assemblies; their bundled third-party libraries (ECommons, Newtonsoft.Json...) are skipped.
	private static bool IsFirstParty(string fileName) =>
		fileName.StartsWith("DailyRoutines", StringComparison.OrdinalIgnoreCase)
		|| fileName.StartsWith("OmenTools", StringComparison.OrdinalIgnoreCase)
		|| fileName.StartsWith("NyaDraw", StringComparison.OrdinalIgnoreCase);

	private static void ProcessAssembly(string assemblyPath, string output, bool trust)
	{
		var name = Path.GetFileNameWithoutExtension(assemblyPath);
		var target = Path.Combine(output, name);
		Console.WriteLine($"\n== {name}");

		Console.WriteLine("  decompiling...");
		if (Directory.Exists(target))
			Directory.Delete(target, recursive: true);
		Decompilation.DecompileProject(assemblyPath, target, Path.GetDirectoryName(Path.GetFullPath(assemblyPath))!);

		var parse = CSharpParseOptions.Default.WithLanguageVersion(LanguageVersion.Latest);
		var sources = Directory.EnumerateFiles(target, "*.cs", SearchOption.AllDirectories)
			.Select(path => CSharpSyntaxTree.ParseText(File.ReadAllText(path), parse, path, Encoding.UTF8))
			.ToList();

		var decryptor = DecryptorRebuilder.Locate(sources);
		if (decryptor is null)
		{
			Console.WriteLine("  no .NET Reactor string encryption found; left as plain decompiled source.");
			return;
		}
		Console.WriteLine($"  decryptor: {decryptor.Namespace}.{decryptor.ClassName}.{decryptor.MethodName}()  " +
			$"resource: {decryptor.ResourceName}");

		var resource = Decompilation.ReadManifestResource(assemblyPath, decryptor.ResourceName);
		var table = new StringTable(DecryptorRebuilder.DecryptBlob(decryptor, resource, trust, Console.Out));
		if (!table.TryGet(0, out _))
			throw new InvalidOperationException("Decrypted blob does not look like a string table.");
		Console.WriteLine($"  decrypted string table: {table.Blob.Length:N0} bytes");

		var evaluator = new ConstantEvaluator(ConstantEvaluator.CollectModuleFields(sources));
		var usage = new SortedDictionary<int, (string Text, SortedSet<string> Files)>();
		int resolved = 0, unresolved = 0;

		foreach (var tree in sources)
		{
			var rewriter = new CallSiteRewriter(decryptor.ClassName, decryptor.MethodName, evaluator, table);
			var rewritten = rewriter.Visit(tree.GetRoot());
			if (rewriter.Resolved == 0 && rewriter.Unresolved == 0)
				continue;

			resolved += rewriter.Resolved;
			unresolved += rewriter.Unresolved;
			File.WriteAllText(tree.FilePath, rewritten.ToFullString(), new UTF8Encoding(false));

			var relative = Path.GetRelativePath(target, tree.FilePath).Replace('\\', '/');
			foreach (var index in rewriter.ResolvedIndices)
			{
				table.TryGet(index, out var text);
				if (!usage.TryGetValue(index, out var entry))
					usage[index] = entry = (text, new SortedSet<string>(StringComparer.Ordinal));
				entry.Files.Add(relative);
			}
		}

		File.WriteAllText(Path.Combine(target, "_strings.used.json"), JsonSerializer.Serialize(
			usage.Select(kv => new { offset = kv.Key, text = kv.Value.Text, files = kv.Value.Files }), Json));
		File.WriteAllText(Path.Combine(target, "_strings.all.json"), JsonSerializer.Serialize(
			table.EnumerateSequential().Select(s => new { offset = s.Offset, text = s.Text }), Json));
		File.WriteAllBytes(Path.Combine(target, "_strings.blob.bin"), table.Blob);

		Console.WriteLine($"  call sites rewritten: {resolved:N0}  unresolved: {unresolved:N0}  " +
			$"distinct strings: {usage.Count:N0}");
	}
}
