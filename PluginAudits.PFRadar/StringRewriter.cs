using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace PluginAudits.PFRadar;

/// <summary>
/// Replaces PFRadar's encrypted string-accessor calls in decompiled C# with their plaintext literals.
/// Pure text rewrite: the string table comes from the blob dumped by <c>trace</c>, never from running the plugin.
/// </summary>
/// <remarks>
/// Call sites look like <c>ViewerDistributor.FlushSynchronizer(0x1234 ^ &lt;Module&gt;{guid}.m_container.m_field)</c>,
/// where the fields are the obfuscator's integer constants (also dumped by <c>trace</c>). The accessor names are
/// those of PFRadar 1.5.0.7; other builds rename them.
/// </remarks>
internal static partial class StringRewriter
{
	// The module type as written in single-file output (<Module>{guid}) or escaped in project output
	// (_003CModule_003E_007B<guid with _002D for '-'>_007D).
	private const string Module =
		@"(?:<Module>\{[0-9a-f-]+\}|_003CModule_003E_007B[0-9A-Fa-f_]+?_007D)\.m_[0-9a-f]+\.(m_[0-9a-f]+)";
	private const string Number = "(?:-{0,2}(?:0x[0-9A-Fa-f]+|[0-9]+))";
	private const string Expression =
		$@"((?:{Number}\s*\^\s*)*(?:{Number}|{Module})(?:\s*\^\s*(?:{Number}|{Module}))*)";

	[GeneratedRegex($@"ViewerDistributor\.FlushSynchronizer\({Expression}\)")]
	private static partial Regex FlushSynchronizer();

	[GeneratedRegex($@"VerifierTransaction\.ScanRole\({Expression},\s*VerifierTransaction\.[A-Za-z]+\)")]
	private static partial Regex ScanRole();

	[GeneratedRegex($"^{Module}$")]
	private static partial Regex ModuleField();

	[GeneratedRegex(@"\s*\^\s*")]
	private static partial Regex XorSplit();

	/// <summary>
	/// Parses the decrypted string blob: consecutive records of an int32 byte length and UTF-16LE text.
	/// </summary>
	public static Dictionary<int, string> ReadTable(byte[] blob)
	{
		var table = new Dictionary<int, string>();
		var offset = 0;
		while (offset + 4 <= blob.Length)
		{
			var length = BitConverter.ToInt32(blob, offset);
			if (length < 0 || offset + 4 + length > blob.Length) break;
			table[offset] = Encoding.Unicode.GetString(blob, offset + 4, length);
			offset += 4 + length;
		}
		return table;
	}

	public static int Run(
		string sourcePath, string blobPath, string constantsPath, string outputPath, string? dumpTablePath)
	{
		var table = ReadTable(File.ReadAllBytes(blobPath));
		var constants = JsonSerializer.Deserialize<Dictionary<string, long>>(File.ReadAllText(constantsPath))!;
		Console.WriteLine($"{table.Count} strings in the table, {constants.Count} constants");
		if (dumpTablePath is not null)
		{
			var dump = table.ToDictionary(kv => kv.Key.ToString(), kv => kv.Value);
			var options = new JsonSerializerOptions
			{
				WriteIndented = true,
				Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
			};
			File.WriteAllText(dumpTablePath, JsonSerializer.Serialize(dump, options));
		}

		int replaced = 0, missed = 0;
		string Replace(Match m)
		{
			var offset = unchecked((int)(uint)Evaluate(m.Groups[1].Value, constants));
			if (table.TryGetValue(offset, out var text)) { replaced++; return Literal(text); }
			missed++;
			return m.Value;
		}

		var files = Directory.Exists(sourcePath)
			? Directory.EnumerateFiles(sourcePath, "*.cs", SearchOption.AllDirectories)
				.Select(f => (f, Path.Combine(outputPath, Path.GetRelativePath(sourcePath, f))))
			: [(sourcePath, outputPath)];
		foreach (var (input, output) in files)
		{
			var text = File.ReadAllText(input).ReplaceLineEndings("\n");
			text = FlushSynchronizer().Replace(text, Replace);
			text = ScanRole().Replace(text, Replace);
			Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(output))!);
			File.WriteAllText(output, text);
		}
		Console.WriteLine($"replaced {replaced} call sites, {missed} without a table entry");
		return 0;
	}

	/// <summary>
	/// Evaluates an XOR chain of integer literals and obfuscator constants, as the call site computes it.
	/// </summary>
	private static uint Evaluate(string expression, Dictionary<string, long> constants)
	{
		long value = 0;
		foreach (var raw in XorSplit().Split(expression.Trim()))
		{
			if (ModuleField().Match(raw) is { Success: true } field)
			{
				value ^= constants[field.Groups[1].Value];
				continue;
			}
			var part = raw;
			var negative = false;
			while (part.StartsWith('-')) { negative = !negative; part = part[1..]; }
			var number = part.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
				? Convert.ToInt64(part[2..], 16)
				: long.Parse(part);
			value ^= negative ? -number : number;
		}
		return (uint)value;
	}

	private static string Literal(string text) =>
		"\"" + text.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "\\n").Replace("\r", "\\r") + "\"";
}
