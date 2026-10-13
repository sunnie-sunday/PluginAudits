namespace PluginAudits.PFRadar;

/// <summary>
/// The build-specific parameters of PFRadar's .NET Reactor protection. Every protected build renames its members and
/// changes its keys, so each audited build gets its own profile; the decryption itself is generic.
/// </summary>
internal sealed record BuildProfile(
	string Version,
	string PluginDllSha256,
	string LoaderMethod,
	int LoaderStartState,
	int MethodStoreLocal,
	ulong MethodStoreXorKey,
	string StringAccessorMethod,
	string StringBlobField,
	string ConstantsMethod,
	string ConstantsField)
{
	/// <summary>
	/// PFRadar 1.5.0.7, as audited.
	/// <list type="bullet">
	/// <item>The loader <c>ViewerDistributor.DisperseGlobalOrder</c> is a flattened state machine; emulation starts at
	/// state 756, after the platform checks, and its local 48 ends up holding the encrypted method-body store.</item>
	/// <item>That store is still XORed per 64-bit word with <c>0x374348be</c> before the NecroBit records can be
	/// read.</item>
	/// <item>On the restored assembly, the string accessor <c>FlushSynchronizer</c> initialises the string blob in
	/// <c>taskSubscriberElements</c>, and the obfuscated method <c>b2eb4caf…</c> fills the integer constants in
	/// <c>m_4ca73a38…</c> that call sites XOR their string offsets with.</item>
	/// </list>
	/// </summary>
	public static readonly BuildProfile Pfradar1507 = new(
		Version: "1.5.0.7",
		PluginDllSha256: "00d97a727adc25a1c5f22905f1b3f955c6486c1054d8dc0e062ef77bbed9dd89",
		LoaderMethod: "DisperseGlobalOrder",
		LoaderStartState: 756,
		MethodStoreLocal: 48,
		MethodStoreXorKey: 0x374348be,
		StringAccessorMethod: "FlushSynchronizer",
		StringBlobField: "taskSubscriberElements",
		ConstantsMethod: "b2eb4caf5f12e405fbcfc144ecd82ba26",
		ConstantsField: "m4ca73a38177641ad9f19d7a394f77d71");

	public static readonly IReadOnlyList<BuildProfile> All = [Pfradar1507];
}
