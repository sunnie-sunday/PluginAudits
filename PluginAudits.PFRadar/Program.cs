using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using PluginAudits.Core;

namespace PluginAudits.PFRadar;

/// <summary>
/// Static removal of PFRadar's .NET Reactor protection (NecroBit method bodies, proxy calls, VM-protected strings),
/// then decompilation. Nothing from the plugin is executed: its loader routines run in an IL emulator, and a
/// post-run check enforces that the plugin was never loaded into the process.
/// </summary>
internal static class Program
{
	private const string Usage = """
        Usage:
          pfrdecrypt <PFRadar.dll | latest.zip | folder> [-o <output-dir>] [--force]
              Full chain for an audited build: decrypts and restores the method bodies, decompiles the restored
              assembly and replaces every encrypted string call with its literal. Refuses builds without a profile
              (see BuildProfile.cs) unless --force is given with --profile <version>.
          pfrdecrypt trace <input.dll> <method> <output-dir> [--start-state <n>] [--location <original.dll>]
              Statically emulates a loader method and dumps the byte arrays and constants it builds.
        """;

	private static int Main(string[] args)
	{
		var rest = args.ToList();
		if (rest.Count == 0 || rest[0] is "-h" or "--help")
		{
			Console.WriteLine(Usage);
			return rest.Count == 0 ? 1 : 0;
		}

		switch (rest[0])
		{
			case "trace":
				{
					rest.RemoveAt(0);
					var start = Take(rest, "--start-state");
					var location = Take(rest, "--location");
					if (rest.Count < 3) return Fail(Usage);
					Trace(Path.GetFullPath(rest[0]), rest[1], Path.GetFullPath(rest[2]),
						start is null ? null : int.Parse(start), location is null ? null : Path.GetFullPath(location));
					return 0;
				}
			default:
				{
					var output = Take(rest, "-o") ?? Take(rest, "--output");
					var profileVersion = Take(rest, "--profile");
					var force = rest.Remove("--force");
					if (rest.Count != 1) return Fail(Usage);
					return RunChain(rest[0], output, force, profileVersion);
				}
		}
	}

	/// <summary>
	/// The whole chain for one build: trace → XOR → restore → trace strings and constants → decompile → rewrite.
	/// </summary>
	private static int RunChain(string input, string? output, bool force, string? profileVersion)
	{
		var outDir = Path.GetFullPath(output ?? "decrypted");
		Directory.CreateDirectory(outDir);
		var original = LocatePluginDll(Path.GetFullPath(input), outDir);
		if (original is null) return Fail($"PFRadar.dll not found in {input}");

		using (var stream = File.OpenRead(original))
		{
			var sha = Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
			var profile = BuildProfile.All.FirstOrDefault(p => p.PluginDllSha256 == sha)
						  ?? (force ? BuildProfile.All.FirstOrDefault(p => p.Version == profileVersion) : null);
			if (profile is null)
				return Fail($"PFRadar.dll ({sha}) is not an audited build; known profiles: " +
							string.Join(", ", BuildProfile.All.Select(p => p.Version)) +
							". Use --force --profile <version> to try one anyway.");
			Console.WriteLine($"PFRadar {profile.Version} (PFRadar.dll {sha[..16]}…)");
			return RunChain(profile, original, outDir);
		}
	}

	private static int RunChain(BuildProfile profile, string original, string outDir)
	{
		var restored = Path.Combine(outDir, "PFRadar.restored.dll");
		string Dir(string name) => Path.Combine(outDir, name);

		Console.WriteLine("\n[1/5] emulating the loader to decrypt the method-body store");
		Trace(original, profile.LoaderMethod, Dir("trace"), profile.LoaderStartState, original);
		var store = File.ReadAllBytes(Path.Combine(Dir("trace"), $"local{profile.MethodStoreLocal}.bin"));
		for (var i = 0; i + 8 <= store.Length; i += 8)
			BinaryPrimitives.WriteUInt64LittleEndian(store.AsSpan(i),
				BinaryPrimitives.ReadUInt64LittleEndian(store.AsSpan(i)) ^ profile.MethodStoreXorKey);
		var storePath = Path.Combine(outDir, "methods.bin");
		File.WriteAllBytes(storePath, store);

		Console.WriteLine("\n[2/5] restoring the method bodies");
		if (MethodRestorer.Restore(original, storePath, restored) != 0) return Fail("method restore failed");
		WriteProxyMap(restored, Path.Combine(outDir, "proxies.json"));

		Console.WriteLine("\n[3/5] emulating the string accessor and the constants initialiser");
		Trace(restored, profile.StringAccessorMethod, Dir("strings"), null, original);
		Trace(restored, profile.ConstantsMethod, Dir("constants"), null, original);

		Console.WriteLine("\n[4/5] decompiling the restored assembly");
		var project = Dir("PFRadar");
		if (Directory.Exists(project)) Directory.Delete(project, recursive: true);
		Decompilation.DecompileProject(restored, project,
			[Path.GetDirectoryName(original)!, .. Decompilation.DalamudReferenceDirectories()]);

		Console.WriteLine("\n[5/5] replacing encrypted string calls with their literals");
		var rc = StringRewriter.Run(project,
			Path.Combine(Dir("strings"), $"static-{profile.StringBlobField}.bin"),
			Path.Combine(Dir("constants"), $"static-{profile.ConstantsField}.json"),
			project, Path.Combine(outDir, "strings.json"));
		if (rc != 0) return rc;

		// Post-run check: neither the plugin nor its restored copy may have entered this process.
		var safety = TargetIsolation.Check([original, restored]);
		if (safety != 0) return safety;

		Console.WriteLine($"\nDone. Decompiled project with literal strings: {project}");
		return 0;
	}

	/// <summary>
	/// Writes the decrypted proxy-call table: each delegate field the obfuscator calls through
	/// (<c>Type.ScanRole(..., Type.Field)</c> in the decompiled code) mapped to the method it really calls.
	/// </summary>
	private static void WriteProxyMap(string assembly, string path)
	{
		var module = dnlib.DotNet.ModuleDefMD.Load(assembly);
		var map = new SortedDictionary<string, string>(StringComparer.Ordinal);
		foreach (var (fieldToken, (methodToken, _)) in ProxyTable.Load(module))
		{
			if (module.ResolveToken(fieldToken) is not dnlib.DotNet.FieldDef field) continue;
			map[$"{field.DeclaringType.Name}.{field.Name}"] = module.ResolveToken(methodToken) is dnlib.DotNet.IMethod m
				? $"{m.DeclaringType.FullName}::{m.Name}" : $"0x{methodToken:X8}";
		}
		File.WriteAllText(path, System.Text.Json.JsonSerializer.Serialize(map,
			new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
		Console.WriteLine($"  proxy-call table: {map.Count} entries -> {Path.GetFileName(path)}");
	}

	/// <summary>
	/// Finds PFRadar.dll: given directly, in a folder, or extracted from a release zip into output/_package.
	/// </summary>
	private static string? LocatePluginDll(string input, string outDir)
	{
		if (File.Exists(input) && input.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
		{
			var package = Path.Combine(outDir, "_package");
			ZipFile.ExtractToDirectory(input, package, overwriteFiles: true);
			input = package;
		}
		if (Directory.Exists(input)) input = Path.Combine(input, "PFRadar.dll");
		return File.Exists(input) ? input : null;
	}

	/// <summary>
	/// Statically emulates a loader method and dumps the byte arrays and integer constants it builds.
	/// </summary>
	private static void Trace(string input, string methodName, string outDir, int? startState, string? location)
	{
		var module = dnlib.DotNet.ModuleDefMD.Load(input);
		ExternalModels.Module = module;
		ExternalModels.LocationPath = location;
		var method = module.GetTypes().SelectMany(t => t.Methods).FirstOrDefault(m => m.Name == methodName && m.HasBody)
					 ?? throw new InvalidOperationException("method not found: " + methodName);
		Console.WriteLine($"Emulating {method.FullName} ({method.Body.Instructions.Count} instructions)");
		var emu = new IlEmulator(module) { StartState = startState, StartMethod = method };
		if (method.DeclaringType.FindStaticConstructor() is { HasBody: true } cctor && cctor != method)
		{
			try { emu.Run(cctor, []); Console.WriteLine("type initializer emulated"); }
			catch (IlEmulator.StopException stop)
			{
				Console.WriteLine($"type initializer stopped: {stop.Message} at {stop.At}");
			}
		}
		try
		{
			// Zero-valued arguments (e.g. offset 0 for a string accessor) are enough to trigger lazy initialisation.
			var callArgs = method.MethodSig.Params.Select(p => (object?)(p.ElementType switch
			{
				dnlib.DotNet.ElementType.I8 or dnlib.DotNet.ElementType.U8 => 0L,
				dnlib.DotNet.ElementType.I4 or dnlib.DotNet.ElementType.U4 or dnlib.DotNet.ElementType.I2
					or dnlib.DotNet.ElementType.U2 or dnlib.DotNet.ElementType.I1 or dnlib.DotNet.ElementType.U1 => 0,
				_ => null,
			})).ToList();
			if (!method.IsStatic) callArgs.Insert(0, null);
			emu.Run(method, callArgs.ToArray());
			Console.WriteLine("completed");
		}
		catch (IlEmulator.StopException stop)
		{
			// Loaders are emulated until the emulator meets something it doesn't model; the arrays are built by then.
			Console.WriteLine($"stopped after {emu.Steps:N0} steps: {stop.Message}\n" +
				$"  in {stop.Method.FullName} at {stop.At}");
		}

		Directory.CreateDirectory(outDir);
		foreach (var (field, value) in emu.StaticFields)
		{
			var safe = string.Concat(field.Split("::").Last().Where(char.IsLetterOrDigit));
			if (value is IlEmulator.ObjectInstance { Fields.Count: > 0 } so)
			{
				var ints = so.Fields.Where(kv => kv.Value is int or long)
					.ToDictionary(kv => kv.Key, kv => Convert.ToInt64(kv.Value));
				if (ints.Count > 0)
				{
					File.WriteAllText(Path.Combine(outDir, $"static-{safe}.json"),
						System.Text.Json.JsonSerializer.Serialize(ints));
					Console.WriteLine($"  static {field}: object with {ints.Count} integer fields");
				}
			}
			if (value is not byte[] sb || sb.Length < 64) continue;
			Console.WriteLine($"  static {field}: byte[{sb.Length}]");
			File.WriteAllBytes(Path.Combine(outDir, $"static-{safe}.bin"), sb);
		}
		if (emu.LastFrames.TryGetValue(method, out var locals))
		{
			for (var i = 0; i < locals.Length; i++)
			{
				if (locals[i] is not byte[] b || b.Length <= 64) continue;
				Console.WriteLine($"  local {i,3}: byte[{b.Length}]");
				File.WriteAllBytes(Path.Combine(outDir, $"local{i}.bin"), b);
			}
		}
	}

	private static string? Take(List<string> args, string name)
	{
		var i = args.IndexOf(name);
		if (i < 0 || i + 1 >= args.Count) return null;
		var value = args[i + 1];
		args.RemoveRange(i, 2);
		return value;
	}

	private static int Fail(string message)
	{
		Console.Error.WriteLine(message);
		return 1;
	}
}
