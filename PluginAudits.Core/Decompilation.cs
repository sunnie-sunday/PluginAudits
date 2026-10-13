using System.Reflection.PortableExecutable;
using ICSharpCode.Decompiler;
using ICSharpCode.Decompiler.CSharp;
using ICSharpCode.Decompiler.CSharp.ProjectDecompiler;
using ICSharpCode.Decompiler.Metadata;

namespace PluginAudits.Core;

/// <summary>
/// Static decompilation via ICSharpCode.Decompiler (the ILSpy engine). Reads metadata only; never loads the assembly.
/// </summary>
public static class Decompilation
{
	public static bool IsManagedAssembly(string path)
	{
		try
		{
			using var stream = File.OpenRead(path);
			using var pe = new PEReader(stream);
			return pe.HasMetadata;
		}
		catch (BadImageFormatException)
		{
			return false;
		}
	}

	/// <summary>
	/// Decompiles <paramref name="assemblyPath"/> into a C# project. References are resolved from
	/// <paramref name="searchDirectories"/>, in order; directories that don't exist are skipped.
	/// </summary>
	public static void DecompileProject(string assemblyPath, string outputDirectory, params string[] searchDirectories)
	{
		var file = new PEFile(assemblyPath, PEStreamOptions.PrefetchEntireImage);
		var resolver = new UniversalAssemblyResolver(assemblyPath, throwOnError: false, file.DetectTargetFrameworkId());
		foreach (var directory in searchDirectories.Where(Directory.Exists))
			resolver.AddSearchDirectory(directory);

		var settings = new DecompilerSettings(LanguageVersion.CSharp12_0) { ThrowOnAssemblyResolveErrors = false };
		Directory.CreateDirectory(outputDirectory);
		new WholeProjectDecompiler(settings, resolver, null, null, null).DecompileProject(file, outputDirectory);
	}

	/// <summary>
	/// Dalamud's reference assemblies, if XIVLauncher is installed (Windows, or XIVLauncher.Core on Linux).
	/// </summary>
	public static IEnumerable<string> DalamudReferenceDirectories() =>
		new[]
		{
			Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
				"XIVLauncher", "addon", "Hooks", "dev"),
			Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
				".xlcore", "dalamud", "Hooks", "dev"),
		}.Where(Directory.Exists);

	public static byte[] ReadManifestResource(string assemblyPath, string resourceName)
	{
		var file = new PEFile(assemblyPath, PEStreamOptions.PrefetchEntireImage);
		var resource = file.Resources.FirstOrDefault(r => r.Name == resourceName)
			?? throw new InvalidOperationException(
				$"Resource '{resourceName}' not found in {Path.GetFileName(assemblyPath)}.");
		using var stream = resource.TryOpenStream()
			?? throw new InvalidOperationException($"Resource '{resourceName}' is not embedded.");
		using var buffer = new MemoryStream();
		stream.CopyTo(buffer);
		return buffer.ToArray();
	}
}
