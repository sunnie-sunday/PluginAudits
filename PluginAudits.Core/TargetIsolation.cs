namespace PluginAudits.Core;

/// <summary>
/// Checks that none of an audited plugin's files was loaded into the process as an assembly.
/// Every tool calls this after its work, on every file of the target it touched.
/// </summary>
public static class TargetIsolation
{
	/// <summary>
	/// Returns the given files that were loaded into this process as assemblies (empty when the guarantee holds).
	/// </summary>
	public static IReadOnlyList<string> LoadedFrom(IEnumerable<string> targetFiles)
	{
		var targets = targetFiles.Select(Path.GetFullPath).ToHashSet(StringComparer.OrdinalIgnoreCase);
		return AppDomain.CurrentDomain.GetAssemblies()
			.Where(a => !a.IsDynamic && !string.IsNullOrEmpty(a.Location))
			.Select(a => Path.GetFullPath(a.Location))
			.Where(targets.Contains)
			.ToList();
	}

	/// <summary>
	/// Prints a SAFETY error and returns exit code 3 if any target file was loaded; returns 0 otherwise.
	/// </summary>
	public static int Check(IEnumerable<string> targetFiles)
	{
		var loaded = LoadedFrom(targetFiles);
		if (loaded.Count == 0) return 0;
		Console.Error.WriteLine("SAFETY: target assembly was loaded into the process: " + string.Join(", ", loaded));
		return 3;
	}
}
