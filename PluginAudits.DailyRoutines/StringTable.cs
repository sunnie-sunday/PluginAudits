using System.Text;

namespace PluginAudits.DailyRoutines;

/// <summary>
/// The decrypted .NET Reactor string blob: a sequence of <c>[int32 byteLength][UTF-16LE bytes]</c>
/// records, addressed by byte offset.
/// </summary>
internal sealed class StringTable(byte[] blob)
{
	public byte[] Blob { get; } = blob;

	public bool TryGet(int offset, out string text)
	{
		text = "";
		if (offset < 0 || offset > Blob.Length - 4)
			return false;
		var length = BitConverter.ToInt32(Blob, offset);
		if (length < 0 || length > Blob.Length - offset - 4)
			return false;
		text = Encoding.Unicode.GetString(Blob, offset + 4, length);
		return true;
	}

	/// <summary>Walks the blob record by record from offset 0, including strings no call site references.</summary>
	public IEnumerable<(int Offset, string Text)> EnumerateSequential()
	{
		var offset = 0;
		while (TryGet(offset, out var text))
		{
			yield return (offset, text);
			offset += 4 + BitConverter.ToInt32(Blob, offset);
		}
	}
}
