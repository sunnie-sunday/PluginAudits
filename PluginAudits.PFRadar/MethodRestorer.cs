using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;
using dnlib.PE;

namespace PluginAudits.PFRadar;

/// <summary>
/// Restores NecroBit-encrypted method bodies from the decrypted method store (output of <c>trace</c>, with the
/// 64-bit XOR layer removed). Purely static: patches a copy of the file bytes and rebuilds bodies with dnlib.
///
/// Store layout (this .NET Reactor build):
///   int32 decrypterToken, int32 ?, int32 ?, int32 ?, int32 patchCount, int32 mode
///   patchCount x (uint32 rva, uint32 dword)          dword patches into the image (headers, local sig tokens)
///   int32 recordCount
///   recordCount x (uint32 codeRva, uint32 index, int32 size, byte[size] il)   real IL served by the JIT hook
/// </summary>
internal static class MethodRestorer
{
	public static int Restore(string inputDll, string storePath, string outputDll)
	{
		var file = File.ReadAllBytes(inputDll);
		var store = File.ReadAllBytes(storePath);
		var r = new BinaryReader(new MemoryStream(store));

		var decrypterToken = r.ReadUInt32();
		if (decrypterToken >> 24 != 0x06)
			throw new InvalidDataException($"unexpected store header 0x{decrypterToken:X8} (XOR layer not removed?)");
		r.ReadInt32(); r.ReadInt32(); r.ReadInt32();
		var patchCount = r.ReadInt32();
		var mode = r.ReadInt32();
		Console.WriteLine($"store: decrypter 0x{decrypterToken:X8}, {patchCount} dword patches, mode {mode}");

		// 1) dword patches into a copy of the image
		using (var pe = new PEImage(file))
		{
			for (var i = 0; i < patchCount; i++)
			{
				var rva = r.ReadUInt32();
				var value = r.ReadUInt32();
				var offset = (int)pe.ToFileOffset((RVA)rva);
				BitConverter.GetBytes(value).CopyTo(file, offset);
			}
		}

		var recordCount = r.ReadInt32();
		var records = new List<(uint CodeRva, uint Index, byte[] Il)>(recordCount);
		for (var i = 0; i < recordCount && r.BaseStream.Position < store.Length - 12; i++)
		{
			var codeRva = r.ReadUInt32();
			var index = r.ReadUInt32();
			var size = r.ReadInt32();
			records.Add((codeRva, index, r.ReadBytes(size)));
		}
		Console.WriteLine($"store: {records.Count}/{recordCount} method records, " +
			$"{store.Length - r.BaseStream.Position} trailing bytes");

		// 2) map code start RVA -> method, using the patched headers
		var module = ModuleDefMD.Load(file, new ModuleCreationOptions { TryToLoadPdbFromDisk = false });
		var peImage = module.Metadata.PEImage;
		var byCode = new Dictionary<uint, (MethodDef Method, uint HeaderRva)>();
		foreach (var m in module.GetTypes().SelectMany(t => t.Methods))
		{
			if (m.RVA == 0) continue;
			var hdr = (uint)m.RVA;
			var off = (int)peImage.ToFileOffset(m.RVA);
			var b0 = file[off];
			var codeStart = (b0 & 3) == 2 ? hdr + 1 : hdr + 4u * (uint)(file[off + 1] >> 4);
			byCode[codeStart] = (m, hdr);
		}

		// 3) rebuild bodies
		int restored = 0, native = 0, unmatched = 0, failed = 0;
		foreach (var (codeRva, index, il) in records)
		{
			if (!byCode.TryGetValue(codeRva, out var target)) { unmatched++; continue; }
			if (index >= 0x70000000) { native++; continue; } // native stubs: left as-is
			try
			{
				var off = (int)peImage.ToFileOffset((RVA)target.HeaderRva);
				ushort flags, maxStack; uint localSig; byte[]? exceptions = null;
				if ((file[off] & 3) == 2)
				{
					flags = 2; maxStack = 8; localSig = 0;
				}
				else
				{
					flags = BitConverter.ToUInt16(file, off);
					maxStack = BitConverter.ToUInt16(file, off + 2);
					var stubCodeSize = BitConverter.ToUInt32(file, off + 4);
					localSig = BitConverter.ToUInt32(file, off + 8);
					if ((flags & 8) != 0) // MoreSects: exception clauses follow the stub code, 4-byte aligned
					{
						var sect = (off + 4 * (flags >> 12) + (int)stubCodeSize + 3) & ~3;
						exceptions = ReadExtraSections(file, sect);
					}
				}
				var genericContext = new GenericParamContext(target.Method.DeclaringType, target.Method);
				var body = MethodBodyReader.CreateCilBody(module, il, exceptions, target.Method.Parameters,
					flags, maxStack, (uint)il.Length, localSig, genericContext);
				target.Method.Body = body;
				restored++;
			}
			catch (Exception ex)
			{
				failed++;
				if (failed <= 5) Console.WriteLine($"  failed {target.Method.FullName}: {ex.Message}");
			}
		}
		Console.WriteLine($"restored {restored}, native {native}, unmatched {unmatched}, failed {failed}");

		var options = new ModuleWriterOptions(module) { Logger = DummyLogger.NoThrowInstance };
		options.MetadataOptions.Flags |= MetadataFlags.PreserveAll | MetadataFlags.KeepOldMaxStack;
		Directory.CreateDirectory(Path.GetDirectoryName(outputDll)!);
		module.Write(outputDll, options);
		return restored > 0 ? 0 : 4;
	}

	/// <summary>Copies the raw extra data sections (exception clauses) starting at <paramref name="offset"/>.</summary>
	private static byte[] ReadExtraSections(byte[] file, int offset)
	{
		var start = offset;
		while (true)
		{
			var kind = file[offset];
			var fat = (kind & 0x40) != 0;
			var size = fat ? (int)(BitConverter.ToUInt32(file, offset) >> 8) : file[offset + 1];
			offset += size;
			if ((kind & 0x80) == 0) break; // no more sections
			offset = (offset + 3) & ~3;
		}
		return file[start..offset];
	}
}
