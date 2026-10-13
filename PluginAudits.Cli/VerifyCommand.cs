namespace PluginAudits.Cli;

/// <summary>
/// Checks the plugin builds placed in plugins/ against plugins/SHA256SUMS and lists the ones still missing.
/// A build can be supplied as its latest.zip or as the unzipped files; the plugin's own DLLs are checked either way
/// (inside the zip when only the zip is there).
/// </summary>
internal static class VerifyCommand
{
	public static async Task<int> Run(string root)
	{
		var plugins = Path.Combine(root, "plugins");
		int verified = 0, missing = 0, mismatched = 0;

		foreach (var build in Build.Load(plugins))
		{
			using var _ = build;
			if (!build.Supplied)
			{
				Console.WriteLine($"missing  {build.Key}/  (place the zip or its unzipped files in " +
					$"{Path.GetRelativePath(root, build.Folder)})");
				missing++;
				continue;
			}

			foreach (var entry in build.Entries)
			{
				// When this is missing, the other form (zip or unzipped files) was supplied.
				if (build.Open(entry) is not { } opened) continue;
				var actual = await Build.Sha256(opened.Stream);
				var where = opened.InZip ? " (in latest.zip)" : "";
				if (actual == entry.Expected)
				{
					Console.WriteLine($"ok       {entry.Relative}{where}");
					verified++;
				}
				else
				{
					Console.Error.WriteLine(
						$"MISMATCH {entry.Relative}{where} (expected {entry.Expected}, got {actual})");
					mismatched++;
				}
			}
		}

		Console.WriteLine($"\n{verified} verified, {missing} builds missing, {mismatched} mismatched");
		if (mismatched > 0)
			Console.Error.WriteLine(
				"A mismatched file is not the build the findings were made from; do not audit it as such.");
		return mismatched > 0 ? 1 : 0;
	}
}
