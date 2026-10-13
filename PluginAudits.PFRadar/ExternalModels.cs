using System.Reflection;
using dnlib.DotNet;

namespace PluginAudits.PFRadar;

/// <summary>
/// Whitelisted models for external (BCL) calls made by the emulated loader.
/// Special cases stand in for reflection on the target (types, assembly, resources) using data read statically
/// by dnlib. Generic forwarding is limited to an explicit set of pure BCL types operating on in-memory data.
/// </summary>
internal static class ExternalModels
{
	public static ModuleDefMD? Module { get; set; }
	/// <summary>Path reported as the target's Assembly.Location (the original, unmodified dll).</summary>
	public static string? LocationPath { get; set; }

	// Pure, in-memory BCL types that may be invoked for real on emulator-owned objects.
	private static readonly HashSet<string> ForwardTypes =
	[
		"System.IO.BinaryReader", "System.IO.Stream", "System.IO.MemoryStream",
		"System.Array", "System.BitConverter", "System.String", "System.Math", "System.Int32",
		"System.Text.Encoding", "System.IDisposable",
		"System.Collections.Generic.List`1", "System.Collections.Generic.List`1/Enumerator",
		"System.Collections.Hashtable",
		"System.Security.Cryptography.SymmetricAlgorithm", "System.Security.Cryptography.RijndaelManaged",
		"System.Security.Cryptography.CryptoStream",
		// In-memory asymmetric verification and hashing (no key containers: UseMachineKeyStore is a no-op model).
		"System.Security.Cryptography.RSACryptoServiceProvider", "System.Security.Cryptography.AsymmetricAlgorithm",
		"System.Security.Cryptography.HashAlgorithm", "System.Security.Cryptography.SHA1",
		"System.Security.Cryptography.MD5CryptoServiceProvider", "System.Security.Cryptography.CryptoConfig",
	];

	public static bool TryInvoke(IMethod m, object?[] args, bool isNew, out object? result)
	{
		result = null;
		var type = m.DeclaringType.FullName;
		var name = m.Name.String;

		// --- reflection on the target, answered statically ---
		switch (type, name)
		{
			case ("System.Type", "GetTypeFromHandle"):
			case ("System.Reflection.IntrospectionExtensions", "GetTypeInfo"):
				result = new IlEmulator.Marker("Type"); return true;
			case ("System.Type", "get_Assembly"):
				result = new IlEmulator.Marker("Assembly"); return true;
			case ("System.Type", "get_Module"):
				result = new IlEmulator.Marker("Module"); return true;
			case ("System.Reflection.Assembly", "GetManifestResourceStream")
				when args.Length == 2 && args[1] is string res:
				result = ResourceStream(res); return true;
			// The target's own file: location is the ORIGINAL dll; reads are allowed for that exact path only.
			case ("System.Reflection.Assembly", "get_Location"):
				result = LocationPath ?? throw new InvalidOperationException("no --location given"); return true;
			case ("System.IO.File", "Exists") when Unwrap(args[0]) is string p2:
				result = p2 == LocationPath ? 1 : 0; return true;
			case ("System.IO.FileStream", ".ctor")
				when isNew && args.Length >= 2 && Unwrap(args[1]) is string p4 && p4 == LocationPath:
				result = new MemoryStream(File.ReadAllBytes(p4), writable: false); return true;
			case ("System.Reflection.Assembly", "get_EntryPoint"):
				result = null; return true; // a plugin DLL has no entry point
			case ("System.Reflection.Assembly", "GetName"):
				result = new IlEmulator.Marker("AssemblyName"); return true;
			case ("System.Reflection.AssemblyName", "GetPublicKeyToken"):
				result = Module!.Assembly.PublicKeyToken?.Data ?? []; return true;
			case ("System.Object", ".ctor"):
				result = null; return true;
			// Token plumbing answered statically from metadata.
			case ("System.ModuleHandle", "GetRuntimeTypeHandleFromMetadataToken"):
				result = new IlEmulator.Marker("token", Module!.ResolveToken((uint)Convert.ToInt64(Unwrap(args[^1]))));
				return true;
			// Equality on reflection objects (Module/Assembly/Type/MemberInfo markers): reference comparison.
			case (_, "op_Equality") when type.StartsWith("System.Reflection.") || type == "System.Type":
				result = ReferenceEquals(Unwrap(args[0]), Unwrap(args[1])) ? 1 : 0; return true;
			case (_, "op_Inequality") when type.StartsWith("System.Reflection.") || type == "System.Type":
				result = ReferenceEquals(Unwrap(args[0]), Unwrap(args[1])) ? 0 : 1; return true;
			// Anti-analysis query: answered with a fixed benign value, never forwarded.
			case ("System.Diagnostics.Debugger", "get_IsAttached"):
				result = 0; return true;
			// Single-threaded emulation: locks are no-ops.
			case ("System.Threading.Monitor", "Enter"):
				if (args.Length == 2 && args[1] is IlEmulator.ByRef taken) taken.Set(1);
				result = null; return true;
			case ("System.Threading.Monitor", "Exit"):
				result = null; return true;
			// Global crypto configuration setter: modelled as a no-op so the real process setting is never touched.
			case ("System.Security.Cryptography.RSACryptoServiceProvider", "set_UseMachineKeyStore"):
				result = null; return true;
			case ("System.Runtime.CompilerServices.RuntimeHelpers", "InitializeArray")
				when args[0] is Array target && args[1] is IlEmulator.Marker { Payload: FieldDef fd }:
				var data = fd.InitialValue ?? throw new InvalidOperationException("no field RVA data");
				Buffer.BlockCopy(data, 0, target, 0, Math.Min(data.Length, Buffer.ByteLength(target)));
				return true;
		}

		if (!ForwardTypes.Contains(StripGeneric(type)))
			return false;
		// Emulator objects may only be stored in collections (opaque items); never passed to other BCL code.
		var isCollection = StripGeneric(type) is "System.Collections.Generic.List`1" or "System.Collections.Hashtable"
			or "System.Array";
		if (!isCollection && args.Any(a => a is IlEmulator.Marker or IlEmulator.ObjectInstance))
			return false;

		result = Forward(m, args, isNew);
		return true;
	}

	private static MemoryStream ResourceStream(string name)
	{
		var res = Module!.Resources.FindEmbeddedResource(name)
				  ?? throw new InvalidOperationException("resource not found: " + name);
		return new MemoryStream(res.CreateReader().ToArray(), writable: false);
	}

	private static string StripGeneric(string fullName)
	{
		var lt = fullName.IndexOf('<');
		return lt < 0 ? fullName : fullName[..lt];
	}

	private static object? Forward(IMethod m, object?[] args, bool isNew)
	{
		var declaring = ResolveBclType(m.DeclaringType)
			?? throw new InvalidOperationException("cannot resolve " + m.DeclaringType.FullName);
		var sig = m.MethodSig;
		var paramTypes = sig.Params
			.Select(p => ResolveBclType(p) ?? throw new InvalidOperationException("param " + p.FullName))
			.ToArray();
		var hasThis = sig.HasThis && !isNew;
		var callArgs = args.Skip(hasThis || isNew ? 1 : 0).Select((a, i) => ToClr(a, paramTypes[i])).ToArray();

		if (isNew)
		{
			var ctor = declaring.GetConstructor(paramTypes)
				?? throw new InvalidOperationException("ctor " + m.FullName);
			return FromClr(ctor.Invoke(callArgs));
		}

		var flags = BindingFlags.Public | BindingFlags.NonPublic
			| (hasThis ? BindingFlags.Instance : BindingFlags.Static);
		var method = declaring.GetMethod(m.Name, flags, null, paramTypes, null);
		if (method is null && m.Name.StartsWith("get_") || method is null && m.Name.StartsWith("set_"))
			method = declaring.GetMethod(m.Name, flags);
		if (method is null) throw new InvalidOperationException("method " + m.FullName);
		var target = hasThis ? Unwrap(args[0]) : null;
		if (hasThis && (target is null || !IsBclObject(target)))
			throw new InvalidOperationException("refusing instance call on non-BCL object");
		return FromClr(method.Invoke(target, callArgs));
	}

	private static bool IsBclObject(object o)
	{
		var asm = o.GetType().Assembly;
		return asm == typeof(object).Assembly || asm.GetName().Name!.StartsWith("System.");
	}

	private static object? Unwrap(object? o) => o is IlEmulator.ByRef b ? b.Get() : o;

	private static Type? ResolveBclType(ITypeDefOrRef t) => ResolveBclType(t.ToTypeSig());

	internal static Type? ResolveBclType(TypeSig t)
	{
		switch (t)
		{
			case SZArraySig sz: return ResolveBclType(sz.Next)?.MakeArrayType();
			case ByRefSig br: return ResolveBclType(br.Next)?.MakeByRefType();
			case GenericInstSig gi:
				{
					var open = ResolveBclType(gi.GenericType.TypeDefOrRef);
					// Target-defined generic arguments become object: their instances are opaque emulator objects.
					var argsT = gi.GenericArguments.Select(a => ResolveBclType(a) ?? typeof(object)).ToArray();
					return open is null ? null : open.MakeGenericType(argsT);
				}
			case GenericVar or GenericMVar: return typeof(object);
		}
		var name = t.ReflectionFullName;
		var assemblies = new[]
		{
			typeof(object).Assembly, typeof(System.Security.Cryptography.Aes).Assembly, typeof(Stream).Assembly,
			typeof(List<>).Assembly, typeof(System.Text.Encoding).Assembly,
		};
		foreach (var asm in assemblies)
			if (asm.GetType(name) is { } found) return found;
		return Type.GetType(name);
	}

	private static object? ToClr(object? v, Type target)
	{
		v = Unwrap(v);
		if (v is null) return null;
		if (target.IsByRef) target = target.GetElementType()!;
		if (target == typeof(object) || target.IsInstanceOfType(v)) return v;
		if (target.IsEnum) return Enum.ToObject(target, v is long l ? l : Convert.ToInt64(v));
		return Type.GetTypeCode(target) switch
		{
			TypeCode.Byte => (byte)Convert.ToInt64(v),
			TypeCode.SByte => (sbyte)Convert.ToInt64(v),
			TypeCode.Int16 => (short)Convert.ToInt64(v),
			TypeCode.UInt16 => (ushort)Convert.ToInt64(v),
			TypeCode.Int32 => (int)Convert.ToInt64(v),
			TypeCode.UInt32 => (uint)Convert.ToInt64(v),
			TypeCode.Int64 => Convert.ToInt64(v),
			TypeCode.UInt64 => (ulong)Convert.ToInt64(v),
			TypeCode.Boolean => Convert.ToInt64(v) != 0,
			TypeCode.Double => Convert.ToDouble(v),
			_ => v,
		};
	}

	private static object? FromClr(object? v) => v switch
	{
		bool b => b ? 1 : 0,
		byte b => (int)b,
		sbyte s => (int)s,
		short s => (int)s,
		ushort u => (int)u,
		char c => (int)c,
		uint u => (int)u,
		ulong u => (long)u,
		float f => (double)f,
		Enum e => Convert.ToInt32(e),
		_ => v,
	};
}
