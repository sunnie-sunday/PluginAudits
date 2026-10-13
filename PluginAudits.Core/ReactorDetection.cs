using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;

namespace PluginAudits.Core;

/// <summary>
/// Recognises .NET Reactor protection from metadata alone, so tools can point to the right deobfuscator.
/// </summary>
public static class ReactorDetection
{
	/// <summary>Describes the protection found, or null for an unprotected assembly.</summary>
	public static string? Describe(string assemblyPath)
	{
		using var pe = new PEReader(File.OpenRead(assemblyPath));
		if (!pe.HasMetadata) return null;
		var md = pe.GetMetadataReader();
		int total = 0, odd = 0;
		foreach (var h in md.TypeDefinitions)
		{
			var name = md.GetString(md.GetTypeDefinition(h).Name);
			if (name.StartsWith("<Module>{", StringComparison.Ordinal))
				return "protected by .NET Reactor (<Module>{GUID} type)";
			total++;
			if (name.Any(c => c > 0x7E || char.IsControl(c))) odd++;
		}
		return total > 10 && odd * 10 > total ? $"obfuscated names ({odd} of {total} types)" : null;
	}
}
