using dnlib.DotNet;

namespace PluginAudits.PFRadar;

/// <summary>
/// Decrypts the .NET Reactor proxy-call table (delegate field token -> target method token).
/// The keystream increment is a constant computed from the obfuscator's fixed seeds (no key material).
/// </summary>
internal static class ProxyTable
{
	public const string ResourceName = "SchemaFunction.ReadableVerifier";

	public static Dictionary<uint, (uint MethodToken, bool Flag)> Load(ModuleDefMD module)
	{
		var map = new Dictionary<uint, (uint, bool)>();
		var res = module.Resources.FindEmbeddedResource(ResourceName);
		if (res is null) return map;
		var data = Decrypt(res.CreateReader().ToArray());
		for (var i = 0; i + 8 <= data.Length; i += 8)
		{
			var field = BitConverter.ToUInt32(data, i);
			var value = BitConverter.ToUInt32(data, i + 4);
			map[field] = (value & 0x3FFFFFFF, (value & 0x40000000) != 0);
		}
		return map;
	}

	private static uint StepConstant()
	{
		uint n11 = 244286159u, n13 = 616986719u, n14 = 1807720003u, n15 = 1795290619u;
		ulong n16 = n14 * n14;
		if (n16 == 0) n16--;
		n13 = (uint)(n13 * n13 % n16);
		var n12 = (n14 ^ n14) + n11;
		n12 = 50725 * (n12 & 0xFFFF) - (n12 >> 16);
		n11 = 14014 * (n11 & 0xFFFF) + (n11 >> 16);
		n13 = 61301 * n13 + n14;
		var n17 = n13 / n14 + n14;
		n14 = n13 + n13 + n17 + n13;
		var n18 = ((n15 >> 12) | (n15 << 20)) ^ n13;
		var n19 = n18 & 0xF0F0F0F;
		n18 &= 0xF0F0F0F0u;
		n15 = (n18 >> 4) | (n19 << 4);
		n12 ^= n12 << 5; n12 += n11;
		n12 ^= n12 >> 15; n12 += n14;
		n12 ^= n12 << 17; n12 += n15;
		return ((n12 << 5) + n14 ^ n11) + n12;
	}

	public static byte[] Decrypt(byte[] input)
	{
		var c = StepConstant();
		var output = new byte[input.Length];
		uint acc = 0;
		var rem = input.Length % 4;
		var blocks = input.Length / 4 + (rem > 0 ? 1 : 0);
		for (var i = 0; i < blocks; i++)
		{
			var pos = i * 4;
			acc += c;
			if (i == blocks - 1 && rem > 0)
			{
				uint v = 0;
				for (var j = 0; j < rem; j++) { if (j > 0) v <<= 8; v |= input[input.Length - 1 - j]; }
				var w = acc ^ v; uint mask = 0xFF; var shift = 0;
				for (var k = 0; k < rem; k++)
				{
					if (k > 0) { mask <<= 8; shift += 8; }
					output[pos + k] = (byte)((w & mask) >> shift);
				}
			}
			else
			{
				BitConverter.GetBytes(acc ^ BitConverter.ToUInt32(input, pos)).CopyTo(output, pos);
			}
		}
		return output;
	}
}
