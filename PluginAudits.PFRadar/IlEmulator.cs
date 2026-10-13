using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace PluginAudits.PFRadar;

/// <summary>
/// Minimal IL interpreter used to statically trace .NET Reactor loader methods.
/// It never executes the target: pure IL ops are interpreted, the target's own small methods are interpreted
/// recursively, and external calls are only allowed through an explicit whitelist of models that operate on
/// data we provide (embedded resources as byte arrays, BinaryReader over a MemoryStream, etc.).
/// Any other external call raises <see cref="StopException"/>.
/// </summary>
internal sealed class IlEmulator(ModuleDefMD module)
{
	public sealed class StopException(string reason, MethodDef method, Instruction? at) : Exception(reason)
	{
		public MethodDef Method { get; } = method;
		public Instruction? At { get; } = at;
	}

	/// <summary>Opaque stand-in for runtime objects we only need to pass around (Type, Assembly, ...).</summary>
	public sealed record Marker(string What, object? Payload = null);

	/// <summary>Instance of a type defined in the target: just a field bag.</summary>
	public sealed class ObjectInstance
	{
		public ObjectInstance(TypeDef type)
		{
			Type = type;
			if (type.IsExplicitLayout)
			{
				var size = (int)(type.ClassLayout?.ClassSize ?? 0);
				foreach (var f in type.Fields.Where(f => !f.IsStatic && f.FieldOffset is not null))
					size = Math.Max(size, (int)f.FieldOffset!.Value + PrimitiveSize(f.FieldSig.Type));
				Raw = new byte[Math.Max(size, 8)];
			}
		}

		public TypeDef Type { get; }
		public Dictionary<string, object?> Fields { get; } = new();
		/// <summary>Backing memory for explicit-layout (union) types: primitive fields alias by offset.</summary>
		public byte[]? Raw { get; }

		public static int PrimitiveSize(TypeSig t) => t.ElementType switch
		{
			ElementType.Boolean or ElementType.I1 or ElementType.U1 => 1,
			ElementType.Char or ElementType.I2 or ElementType.U2 => 2,
			ElementType.I4 or ElementType.U4 or ElementType.R4 => 4,
			ElementType.I8 or ElementType.U8 or ElementType.R8 or ElementType.I or ElementType.U => 8,
			_ => 0,
		};

		private int? UnionOffset(IField f)
		{
			if (Raw is null) return null;
			var fd = f.ResolveFieldDef() ?? Type.Fields.FirstOrDefault(x => x.Name == f.Name);
			if (fd?.FieldOffset is null || PrimitiveSize(fd.FieldSig.Type) == 0) return null;
			return (int)fd.FieldOffset.Value;
		}

		public bool TryGet(IField f, out object? value)
		{
			value = null;
			if (UnionOffset(f) is not { } off) return false;
			var raw = Raw!;
			// Arms are boxed explicitly: a switch expression would otherwise unify int/long/double to double.
			value = f.FieldSig.Type.ElementType switch
			{
				ElementType.Boolean or ElementType.U1 => (object)(int)raw[off],
				ElementType.I1 => (object)(int)(sbyte)raw[off],
				ElementType.Char or ElementType.U2 => (object)(int)BitConverter.ToUInt16(raw, off),
				ElementType.I2 => (object)(int)BitConverter.ToInt16(raw, off),
				ElementType.I4 or ElementType.U4 => (object)BitConverter.ToInt32(raw, off),
				ElementType.R4 => (object)(double)BitConverter.ToSingle(raw, off),
				ElementType.R8 => (object)BitConverter.ToDouble(raw, off),
				_ => (object)BitConverter.ToInt64(raw, off),
			};
			return true;
		}

		public bool TrySet(IField f, object? value)
		{
			if (UnionOffset(f) is not { } off) return false;
			var raw = Raw!;
			var v = value switch
			{
				int i => i,
				long l => l,
				double d => BitConverter.DoubleToInt64Bits(d),
				null => 0L,
				_ => Convert.ToInt64(value),
			};
			switch (f.FieldSig.Type.ElementType)
			{
				case ElementType.Boolean or ElementType.U1 or ElementType.I1: raw[off] = (byte)v; break;
				case ElementType.Char or ElementType.U2 or ElementType.I2:
					BitConverter.GetBytes((short)v).CopyTo(raw, off); break;
				case ElementType.I4 or ElementType.U4: BitConverter.GetBytes((int)v).CopyTo(raw, off); break;
				case ElementType.R4:
					BitConverter.GetBytes((float)(value is double dd ? dd : v)).CopyTo(raw, off); break;
				case ElementType.R8: BitConverter.GetBytes(value is double d2 ? d2 : v).CopyTo(raw, off); break;
				default: BitConverter.GetBytes(v).CopyTo(raw, off); break;
			}
			return true;
		}
	}

	public sealed class ByRef(Func<object?> get, Action<object?> set)
	{
		public object? Get() => get();
		public void Set(object? v) => set(v);
	}

	public readonly Dictionary<string, object?> StaticFields = new();
	public Dictionary<uint, (uint MethodToken, bool Flag)> ProxyMap { get; } = ProxyTable.Load(module);
	public int? StartState { get; set; }
	public MethodDef? StartMethod { get; set; }
	private bool _jumped;
	public long Steps { get; private set; }
	private const long MaxSteps = 400_000_000;
	private const int MaxDepth = 24;

	public object? Run(MethodDef method, object?[] args, int depth = 0)
	{
		if (depth > MaxDepth)
			throw new StopException("max depth", method, null);
		if (!method.HasBody)
			throw new StopException("no body: " + method.FullName, method, null);

		var body = method.Body;
		var instrs = body.Instructions;
		var index = new Dictionary<Instruction, int>(instrs.Count);
		for (var i = 0; i < instrs.Count; i++) index[instrs[i]] = i;

		var locals = new object?[body.Variables.Count];
		for (var i = 0; i < locals.Length; i++)
		{
			var lt = body.Variables[i].Type;
			// Target-defined structs start as empty field bags (zero-initialised value types).
			locals[i] = lt.IsValueType
				&& lt.ToTypeDefOrRef()?.ResolveTypeDef() is { IsEnum: false } std && std.Module == module
				? new ObjectInstance(std)
				: DefaultFor(lt);
		}
		var stack = new Stack<object?>();
		var pc = 0;
		try
		{
			while (true)
			{
				if (++Steps > MaxSteps) throw new StopException("step limit", method, instrs[pc]);
				var ins = instrs[pc];
				var op = ins.OpCode.Code;
				pc++;
				switch (op)
				{
					case Code.Nop:
					case Code.Volatile:
					case Code.Readonly:
					case Code.Constrained:
					case Code.Unaligned:
					case Code.Tailcall:
						break;
					case Code.Ldc_I4:
					case Code.Ldc_I4_S:
					case Code.Ldc_I4_0:
					case Code.Ldc_I4_1:
					case Code.Ldc_I4_2:
					case Code.Ldc_I4_3:
					case Code.Ldc_I4_4:
					case Code.Ldc_I4_5:
					case Code.Ldc_I4_6:
					case Code.Ldc_I4_7:
					case Code.Ldc_I4_8:
					case Code.Ldc_I4_M1:
						stack.Push(ins.GetLdcI4Value()); break;
					case Code.Ldc_I8: stack.Push((long)ins.Operand); break;
					case Code.Ldc_R8: stack.Push((double)ins.Operand); break;
					case Code.Ldc_R4: stack.Push((double)(float)ins.Operand); break;
					case Code.Ldnull: stack.Push(null); break;
					case Code.Ldstr: stack.Push((string)ins.Operand); break;
					case Code.Dup: { var v = stack.Peek(); stack.Push(v); break; }
					case Code.Pop: stack.Pop(); break;

					case Code.Ldloc:
					case Code.Ldloc_S:
					case Code.Ldloc_0:
					case Code.Ldloc_1:
					case Code.Ldloc_2:
					case Code.Ldloc_3:
						stack.Push(CopyIfStruct(locals[ins.GetLocal(body.Variables).Index])); break;
					case Code.Stloc:
					case Code.Stloc_S:
					case Code.Stloc_0:
					case Code.Stloc_1:
					case Code.Stloc_2:
					case Code.Stloc_3:
						locals[ins.GetLocal(body.Variables).Index] =
							CopyIfStruct(Coerce(stack.Pop(), ins.GetLocal(body.Variables).Type));
						break;
					case Code.Ldloca:
					case Code.Ldloca_S:
						{
							var idx = ((Local)ins.Operand).Index;
							stack.Push(new ByRef(() => locals[idx], v => locals[idx] = v)); break;
						}
					case Code.Ldarg:
					case Code.Ldarg_S:
					case Code.Ldarg_0:
					case Code.Ldarg_1:
					case Code.Ldarg_2:
					case Code.Ldarg_3:
						stack.Push(args[ins.GetParameterIndex()]); break;
					case Code.Starg:
					case Code.Starg_S:
						args[((Parameter)ins.Operand).Index] = stack.Pop(); break;

					case Code.Ldsfld:
						{
							var f = (IField)ins.Operand;
							// Proxy-call delegate fields resolve to their real target method (decrypted proxy table).
							if (ProxyMap.TryGetValue(f.MDToken.Raw, out var proxy) && !StaticFields.ContainsKey(Key(f)))
							{
								stack.Push(new Marker("delegate", module.ResolveToken(proxy.MethodToken)));
								break;
							}
							stack.Push(StaticFields.TryGetValue(Key(f), out var v) ? v : DefaultFor(f.FieldSig.Type));
							break;
						}
					case Code.Stsfld: StaticFields[Key((IField)ins.Operand)] = stack.Pop(); break;
					case Code.Ldsflda:
						{
							var f = (IField)ins.Operand; var k = Key(f);
							if (!StaticFields.ContainsKey(k)) StaticFields[k] = DefaultFor(f.FieldSig.Type);
							stack.Push(new ByRef(() => StaticFields[k], v => StaticFields[k] = v)); break;
						}
					case Code.Initobj:
						{
							var target = stack.Pop() as ByRef
								?? throw new StopException("initobj without address", method, ins);
							var td = ((ITypeDefOrRef)ins.Operand).ResolveTypeDef();
							target.Set(td is not null && td.Module == module
								? new ObjectInstance(td)
								: DefaultFor(((ITypeDefOrRef)ins.Operand).ToTypeSig()));
							break;
						}
					case Code.Ldflda:
						{
							var f = (IField)ins.Operand; var o = Deref(stack.Pop());
							if (o is not ObjectInstance oi)
								throw new StopException("ldflda on " + Describe(o), method, ins);
							if (oi.TryGet(f, out _))
							{
								stack.Push(new ByRef(
									() => { oi.TryGet(f, out var uv); return uv; },
									v => oi.TrySet(f, v)));
								break;
							}
							if (!oi.Fields.ContainsKey(f.Name)) oi.Fields[f.Name] = DefaultFor(f.FieldSig.Type);
							stack.Push(new ByRef(() => oi.Fields[f.Name], v => oi.Fields[f.Name] = v));
							break;
						}
					case Code.Ldobj:
						stack.Push(Deref(stack.Pop())); break;
					case Code.Box:
					case Code.Castclass:
						stack.Push(Deref(stack.Pop())); break;
					case Code.Unbox_Any:
						{
							// Unboxed primitives become plain stack values (int/long/double),
							// as on the real evaluation stack.
							var v = Deref(stack.Pop());
							stack.Push(v switch
							{
								long or ulong => (object)ToLong(v),
								double or float => (object)Convert.ToDouble(v),
								_ when IsNumeric(v) => (object)ToInt(v),
								_ => v,
							});
							break;
						}
					case Code.Unbox:
						{
							var v = Deref(stack.Pop());
							stack.Push(new ByRef(() => v, nv => v = nv)); break;
						}
					case Code.Isinst:
						stack.Push(IsInstance(Deref(stack.Pop()), (ITypeDefOrRef)ins.Operand)); break;
					case Code.Ldind_I1:
					case Code.Ldind_U1:
					case Code.Ldind_I2:
					case Code.Ldind_U2:
					case Code.Ldind_I4:
					case Code.Ldind_U4:
					case Code.Ldind_I8:
					case Code.Ldind_I:
					case Code.Ldind_R4:
					case Code.Ldind_R8:
					case Code.Ldind_Ref:
						{
							var r = stack.Pop() as ByRef
								?? throw new StopException("ldind on non-reference", method, ins);
							stack.Push(r.Get()); break;
						}
					case Code.Stind_I1:
					case Code.Stind_I2:
					case Code.Stind_I4:
					case Code.Stind_I8:
					case Code.Stind_I:
					case Code.Stind_R4:
					case Code.Stind_R8:
					case Code.Stind_Ref:
						{
							var v = stack.Pop();
							var r = stack.Pop() as ByRef
								?? throw new StopException("stind on non-reference", method, ins);
							r.Set(v); break;
						}
					case Code.Ldarga:
					case Code.Ldarga_S:
						{
							var idx = ((Parameter)ins.Operand).Index;
							stack.Push(new ByRef(() => args[idx], v => args[idx] = v)); break;
						}
					case Code.Stobj:
						{
							var v = stack.Pop();
							var target = stack.Pop() as ByRef
								?? throw new StopException("stobj without address", method, ins);
							target.Set(v); break;
						}
					case Code.Ldfld:
						{
							var f = (IField)ins.Operand; var o = stack.Pop();
							if (o is ByRef br) o = br.Get();
							if (o is ObjectInstance oi)
							{
								if (oi.TryGet(f, out var uv))
								{
									var unionType = f.FieldSig.Type.ElementType;
									if (uv is double && unionType is not (ElementType.R4 or ElementType.R8))
									{
										throw new StopException($"union read type mismatch: {f.FullName} " +
											$"et={unionType} raw={Convert.ToHexString(oi.Raw!)}", method, ins);
									}
									stack.Push(uv);
								}
								else
								{
									if (!oi.Fields.TryGetValue(f.Name, out var v))
										oi.Fields[f.Name] = v = DefaultFor(f.FieldSig.Type);
									stack.Push(CopyIfStruct(v));
								}
							}
							else throw new StopException("ldfld on " + Describe(o), method, ins);
							break;
						}
					case Code.Stfld:
						{
							var v = stack.Pop(); var o = stack.Pop();
							if (o is ByRef br) o = br.Get();
							var f = (IField)ins.Operand;
							if (o is ObjectInstance oi) { if (!oi.TrySet(f, v)) oi.Fields[f.Name] = CopyIfStruct(v); }
							else throw new StopException("stfld on " + Describe(o), method, ins);
							break;
						}

					case Code.Add: Bin(stack, (a, b) => a + b, (a, b) => a + b); break;
					case Code.Sub: Bin(stack, (a, b) => a - b, (a, b) => a - b); break;
					case Code.Mul: Bin(stack, (a, b) => a * b, (a, b) => a * b); break;
					case Code.Div: Bin(stack, (a, b) => a / b, (a, b) => a / b); break;
					case Code.Div_Un: BinU(stack, (a, b) => a / b, (a, b) => a / b); break;
					case Code.Rem: Bin(stack, (a, b) => a % b, (a, b) => a % b); break;
					case Code.Rem_Un: BinU(stack, (a, b) => a % b, (a, b) => a % b); break;
					case Code.And: Bin(stack, (a, b) => a & b, (a, b) => a & b); break;
					case Code.Or: Bin(stack, (a, b) => a | b, (a, b) => a | b); break;
					case Code.Xor: Bin(stack, (a, b) => a ^ b, (a, b) => a ^ b); break;
					case Code.Shl:
						{
							var s = ToInt(stack.Pop());
							var a = stack.Pop();
							stack.Push(a is long l ? l << s : (object)(ToInt(a) << s));
							break;
						}
					case Code.Shr:
						{
							var s = ToInt(stack.Pop());
							var a = stack.Pop();
							stack.Push(a is long l ? l >> s : (object)(ToInt(a) >> s));
							break;
						}
					case Code.Shr_Un:
						{
							var s = ToInt(stack.Pop());
							var a = stack.Pop();
							stack.Push(a is long l ? (long)((ulong)l >> s) : (object)(int)((uint)ToInt(a) >> s));
							break;
						}
					case Code.Not: { var a = stack.Pop(); stack.Push(a is long l ? ~l : (object)~ToInt(a)); break; }
					case Code.Neg:
						{
							var a = stack.Pop();
							stack.Push(a is long l ? -l : a is double d ? -d : (object)(-ToInt(a)));
							break;
						}

					case Code.Conv_I1: stack.Push((int)(sbyte)ToLong(stack.Pop())); break;
					case Code.Conv_U1: stack.Push((int)(byte)ToLong(stack.Pop())); break;
					case Code.Conv_I2: stack.Push((int)(short)ToLong(stack.Pop())); break;
					case Code.Conv_U2: stack.Push((int)(ushort)ToLong(stack.Pop())); break;
					case Code.Conv_I4: stack.Push((int)ToLong(stack.Pop())); break;
					case Code.Conv_U4: stack.Push((int)(uint)ToLong(stack.Pop())); break;
					case Code.Conv_I8:
					case Code.Conv_I:
						{
							var a = stack.Pop();
							stack.Push(a is int i ? (long)i : ToLong(a));
							break;
						}
					case Code.Conv_U8:
					case Code.Conv_U:
						{
							var a = stack.Pop();
							stack.Push(a is int i ? (long)(uint)i : ToLong(a));
							break;
						}
					case Code.Conv_R8:
					case Code.Conv_R4:
						{
							var a = stack.Pop();
							stack.Push(a is double d ? d : (double)ToLong(a));
							break;
						}
					case Code.Conv_R_Un:
						{
							var a = stack.Pop();
							stack.Push(a is int i ? (double)(uint)i : (double)(ulong)ToLong(a));
							break;
						}
					case Code.Conv_Ovf_I1:
					case Code.Conv_Ovf_I1_Un:
						stack.Push((int)checked((sbyte)ToLong(stack.Pop()))); break;
					case Code.Conv_Ovf_I2:
					case Code.Conv_Ovf_I2_Un:
						stack.Push((int)checked((short)ToLong(stack.Pop()))); break;
					case Code.Conv_Ovf_U2:
					case Code.Conv_Ovf_U2_Un:
						stack.Push((int)checked((ushort)ToLong(stack.Pop()))); break;
					case Code.Conv_Ovf_I:
					case Code.Conv_Ovf_I_Un:
					case Code.Conv_Ovf_I8:
					case Code.Conv_Ovf_I8_Un:
						{ var a = stack.Pop(); stack.Push(a is int i ? (long)i : ToLong(a)); break; }
					case Code.Conv_Ovf_U:
					case Code.Conv_Ovf_U_Un:
					case Code.Conv_Ovf_U8:
					case Code.Conv_Ovf_U8_Un:
						{
							var a = stack.Pop();
							var l = a is int i ? (long)(uint)i : ToLong(a);
							if (l < 0 && op is Code.Conv_Ovf_U or Code.Conv_Ovf_U8) throw new OverflowException();
							stack.Push(l);
							break;
						}
					case Code.Add_Ovf: case Code.Add_Ovf_Un: Bin(stack, (a, b) => a + b, (a, b) => a + b); break;
					case Code.Sub_Ovf: case Code.Sub_Ovf_Un: Bin(stack, (a, b) => a - b, (a, b) => a - b); break;
					case Code.Mul_Ovf: case Code.Mul_Ovf_Un: Bin(stack, (a, b) => a * b, (a, b) => a * b); break;
					case Code.Sizeof:
						{
							var st = ((ITypeDefOrRef)ins.Operand).ToTypeSig();
							var sz = ObjectInstance.PrimitiveSize(st);
							stack.Push(sz > 0 ? sz : 8); break;
						}
					case Code.Ckfinite: break;
					case Code.Conv_Ovf_U1:
					case Code.Conv_Ovf_U1_Un:
						stack.Push((int)checked((byte)ToLong(stack.Pop()))); break;
					case Code.Conv_Ovf_I4:
					case Code.Conv_Ovf_I4_Un:
						stack.Push(checked((int)ToLong(stack.Pop()))); break;
					case Code.Conv_Ovf_U4:
					case Code.Conv_Ovf_U4_Un:
						stack.Push((int)checked((uint)ToLong(stack.Pop()))); break;

					case Code.Ceq: { var b = stack.Pop(); var a = stack.Pop(); stack.Push(Eq(a, b) ? 1 : 0); break; }
					case Code.Cgt:
						{
							var b = stack.Pop();
							var a = stack.Pop();
							stack.Push(Cmp(a, b, false) > 0 ? 1 : 0);
							break;
						}
					case Code.Cgt_Un:
						{
							var b = stack.Pop();
							var a = stack.Pop();
							stack.Push(a is not null && b is null ? 1 : Cmp(a, b, true) > 0 ? 1 : 0);
							break;
						}
					case Code.Clt:
						{
							var b = stack.Pop();
							var a = stack.Pop();
							stack.Push(Cmp(a, b, false) < 0 ? 1 : 0);
							break;
						}
					case Code.Clt_Un:
						{
							var b = stack.Pop();
							var a = stack.Pop();
							stack.Push(Cmp(a, b, true) < 0 ? 1 : 0);
							break;
						}

					case Code.Br:
					case Code.Br_S:
					case Code.Leave:
					case Code.Leave_S:
						pc = index[(Instruction)ins.Operand]; break;
					case Code.Brtrue:
					case Code.Brtrue_S:
						if (Truthy(stack.Pop())) pc = index[(Instruction)ins.Operand]; break;
					case Code.Brfalse:
					case Code.Brfalse_S:
						if (!Truthy(stack.Pop())) pc = index[(Instruction)ins.Operand]; break;
					case Code.Beq:
					case Code.Beq_S:
						{
							var b = stack.Pop();
							var a = stack.Pop();
							if (Eq(a, b)) pc = index[(Instruction)ins.Operand];
							break;
						}
					case Code.Bne_Un:
					case Code.Bne_Un_S:
						{
							var b = stack.Pop();
							var a = stack.Pop();
							if (!Eq(a, b)) pc = index[(Instruction)ins.Operand];
							break;
						}
					case Code.Bgt:
					case Code.Bgt_S:
						{
							var b = stack.Pop();
							var a = stack.Pop();
							if (Cmp(a, b, false) > 0) pc = index[(Instruction)ins.Operand];
							break;
						}
					case Code.Bgt_Un:
					case Code.Bgt_Un_S:
						{
							var b = stack.Pop();
							var a = stack.Pop();
							if (Cmp(a, b, true) > 0) pc = index[(Instruction)ins.Operand];
							break;
						}
					case Code.Bge:
					case Code.Bge_S:
						{
							var b = stack.Pop();
							var a = stack.Pop();
							if (Cmp(a, b, false) >= 0) pc = index[(Instruction)ins.Operand];
							break;
						}
					case Code.Bge_Un:
					case Code.Bge_Un_S:
						{
							var b = stack.Pop();
							var a = stack.Pop();
							if (Cmp(a, b, true) >= 0) pc = index[(Instruction)ins.Operand];
							break;
						}
					case Code.Blt:
					case Code.Blt_S:
						{
							var b = stack.Pop();
							var a = stack.Pop();
							if (Cmp(a, b, false) < 0) pc = index[(Instruction)ins.Operand];
							break;
						}
					case Code.Blt_Un:
					case Code.Blt_Un_S:
						{
							var b = stack.Pop();
							var a = stack.Pop();
							if (Cmp(a, b, true) < 0) pc = index[(Instruction)ins.Operand];
							break;
						}
					case Code.Ble:
					case Code.Ble_S:
						{
							var b = stack.Pop();
							var a = stack.Pop();
							if (Cmp(a, b, false) <= 0) pc = index[(Instruction)ins.Operand];
							break;
						}
					case Code.Ble_Un:
					case Code.Ble_Un_S:
						{
							var b = stack.Pop();
							var a = stack.Pop();
							if (Cmp(a, b, true) <= 0) pc = index[(Instruction)ins.Operand];
							break;
						}
					case Code.Switch:
						{
							var targets = (IList<Instruction>)ins.Operand; var v = (uint)ToInt(stack.Pop());
							// Optional: the first time the flattened dispatcher runs, jump straight to a chosen state.
							if (StartState is { } start && method == StartMethod && targets.Count >= 100 && !_jumped)
							{
								_jumped = true;
								v = (uint)start;
							}
							if (v < targets.Count) pc = index[targets[(int)v]];
							break;
						}
					case Code.Ret:
						return method.MethodSig.RetType.ElementType == ElementType.Void ? null : stack.Pop();
					case Code.Endfinally:
					case Code.Endfilter:
						throw new StopException("endfinally/filter reached", method, ins);
					case Code.Throw:
					case Code.Rethrow:
						throw new StopException("throw reached", method, ins);

					case Code.Newarr:
						{
							var n = ToInt(stack.Pop()); var t = ((ITypeDefOrRef)ins.Operand).FullName;
							stack.Push(t switch
							{
								"System.Byte" => new byte[n],
								"System.Int32" or "System.UInt32" => new int[n],
								"System.Int64" or "System.UInt64" => new long[n],
								_ => new object?[n],
							});
							break;
						}
					case Code.Ldlen: stack.Push(((Array)Deref(stack.Pop())!).Length); break;
					case Code.Stelem_I1:
					case Code.Stelem_I4:
					case Code.Stelem_I8:
					case Code.Stelem_Ref:
					case Code.Stelem:
					case Code.Stelem_I2:
						{
							var v = stack.Pop(); var i = ToInt(stack.Pop()); var arr = Deref(stack.Pop());
							switch (arr)
							{
								case byte[] b: b[i] = (byte)ToLong(v); break;
								case int[] ia: ia[i] = (int)ToLong(v); break;
								case long[] la: la[i] = ToLong(v); break;
								case object?[] oa: oa[i] = v; break;
								default: throw new StopException("stelem on " + Describe(arr), method, ins);
							}
							break;
						}
					case Code.Ldelem_U1:
					case Code.Ldelem_I1:
					case Code.Ldelem_I4:
					case Code.Ldelem_U4:
					case Code.Ldelem_I8:
					case Code.Ldelem_Ref:
					case Code.Ldelem:
						{
							var i = ToInt(stack.Pop()); var arr = Deref(stack.Pop());
							stack.Push(arr switch
							{
								byte[] b => op == Code.Ldelem_I1 ? (int)(sbyte)b[i] : b[i],
								int[] ia => ia[i],
								long[] la => la[i],
								object?[] oa => oa[i],
								_ => throw new StopException("ldelem on " + Describe(arr), method, ins),
							});
							break;
						}
					case Code.Ldtoken: stack.Push(new Marker("token", ins.Operand)); break;
					case Code.Ldftn: stack.Push(new Marker("fn", ins.Operand)); break;
					case Code.Ldvirtftn: stack.Pop(); stack.Push(new Marker("fn", ins.Operand)); break;

					case Code.Call:
					case Code.Callvirt:
					case Code.Newobj:
						{
							var m = (IMethod)ins.Operand;
							var sig = m.MethodSig;
							var argc = sig.Params.Count + (sig.HasThis && op != Code.Newobj ? 1 : 0);
							var callArgs = new object?[argc + (op == Code.Newobj ? 1 : 0)];
							var offset = op == Code.Newobj ? 1 : 0;
							for (var i = argc - 1; i >= 0; i--) callArgs[i + offset] = stack.Pop();
							var result = Invoke(m, callArgs, op == Code.Newobj, depth, method, ins);
							if (op == Code.Newobj) stack.Push(result);
							else if (sig.RetType.ElementType != ElementType.Void) stack.Push(result);
							break;
						}
					default:
						throw new StopException("unsupported opcode " + ins.OpCode, method, ins);
				}
			}
		}
		catch (StopException)
		{
			throw;
		}
		catch (Exception ex) when (ex.InnerException is StopException inner)
		{
			throw inner; // unwrap stops raised inside BCL callbacks (e.g. List.Sort comparisons)
		}
		catch (Exception ex)
		{
			throw new StopException($"emulation error: {ex.GetType().Name}: {ex.Message}", method,
				pc > 0 ? instrs[pc - 1] : null);
		}
		finally
		{
			LastFrames[method] = locals;
		}
	}

	/// <summary>Locals of the most recent completed or aborted frame per method.</summary>
	public Dictionary<MethodDef, object?[]> LastFrames { get; } = new();

	private object? Invoke(IMethod m, object?[] args, bool isNew, int depth, MethodDef caller, Instruction at)
	{
		// Invoke on a proxy delegate: dispatch to the real target with the remaining arguments.
		if (m.Name == "Invoke" && args.Length > 0 && args[0] is Marker { What: "delegate", Payload: IMethod target })
			return Invoke(target, args[1..], false, depth, caller, at);

		// new SomeDelegate(target, ftn): bound delegate marker (no real delegate is ever created).
		if (isNew && args.Length == 3 && args[2] is Marker { What: "fn", Payload: IMethod fn })
			return new Marker("bound", (Target: args[1], Method: fn));
		if (m.Name == "Invoke" && args.Length > 0
			&& args[0] is Marker { What: "bound", Payload: ValueTuple<object?, IMethod> bd })
		{
			var boundArgs = bd.Item2.MethodSig.HasThis ? new[] { bd.Item1 }.Concat(args[1..]).ToArray() : args[1..];
			return Invoke(bd.Item2, boundArgs, false, depth, caller, at);
		}

		// List<T>.Sort(Comparison<T>) with an emulated comparison: sort here, comparing through the interpreter.
		if (m.Name == "Sort" && m.DeclaringType.FullName.StartsWith("System.Collections.Generic.List`1")
			&& args.Length == 2 && Deref(args[0]) is System.Collections.IList list
			&& args[1] is Marker { What: "bound", Payload: ValueTuple<object?, IMethod> cmp })
		{
			var items = list.Cast<object?>().ToList();
			items.Sort((a, b) => ToInt(Invoke(cmp.Item2, cmp.Item2.MethodSig.HasThis ? [cmp.Item1, a, b] : [a, b],
				false, depth, caller, at)));
			list.Clear();
			foreach (var it in items) list.Add(it);
			return null;
		}

		var def = m.ResolveMethodDef() ?? ResolveLocal(m);
		// Virtual dispatch on emulator objects: most-derived override wins.
		if (!isNew && at.OpCode.Code == Code.Callvirt && m.MethodSig.HasThis
			&& args.Length > 0 && Deref(args[0]) is ObjectInstance self
			&& (def is null || def.IsVirtual || def.IsAbstract || !def.HasBody))
		{
			var argc = m.MethodSig.Params.Count;
			for (var td = self.Type; td is not null; td = td.BaseType?.ResolveTypeDef())
			{
				var impl = td.Methods.FirstOrDefault(x => x.HasBody && x.MethodSig.HasThis
					&& x.MethodSig.Params.Count == argc
					&& (x.Name == m.Name || x.Overrides.Any(o => o.MethodDeclaration.Name == m.Name)));
				if (impl is not null) { def = impl; break; }
			}
		}
		if (def is not null && def.Module == module && def.HasBody)
		{
			if (isNew)
			{
				var inst = new ObjectInstance(def.DeclaringType);
				args[0] = inst;
				Run(def, args, depth + 1);
				return inst;
			}
			return Run(def, args, depth + 1);
		}

		if (TryReflectionModel(m, args, depth, caller, at, out var reflected))
			return reflected;
		if (ExternalModels.TryInvoke(m, args, isNew, out var res))
			return res;
		throw new StopException("unmodelled external call: " + m.FullName
			+ (m.MethodSig.HasThis && args.Length > 0 ? $" [this={Describe(Deref(args[0]))}, via {at.OpCode}]" : ""),
			caller, at);
	}

	/// <summary>
	/// Reflection used by the obfuscator's VM, answered from metadata. MethodBase.Invoke is dispatched back into
	/// this interpreter, so nothing ever reaches real reflection.
	/// </summary>
	private bool TryReflectionModel(
		IMethod m, object?[] args, int depth, MethodDef caller, Instruction at, out object? result)
	{
		result = null;
		var type = m.DeclaringType.FullName;
		var name = m.Name.String;
		object? Arg(int i) => i >= args.Length ? null : args[i] is ByRef b ? b.Get() : args[i];

		if (type is "System.Reflection.Module" && name == "ResolveString")
		{
			result = module.ReadUserString((uint)ToLong(Arg(1)));
			return true;
		}
		if (type is "System.Reflection.Module"
			&& name is "ResolveMethod" or "ResolveField" or "ResolveMember" or "ResolveType")
		{
			var token = (uint)ToLong(Arg(1));
			var resolved = module.ResolveToken(token);
			// Types resolve to (interned) Type markers; methods and fields to member markers.
			result = resolved is ITypeDefOrRef tdr ? TypeMarker(tdr.ToTypeSig()) : new Marker("member", resolved);
			return true;
		}
		if (Arg(0) is Marker { What: "member", Payload: var payload })
		{
			switch (name)
			{
				case "GetParameters" when payload is IMethod pm:
					{
						var md = pm.ResolveMethodDef();
						var ps = md is not null
							? md.Parameters.Where(p => !p.IsHiddenThisParameter)
								.Select(p => (object?)new Marker("param", p.Type)).ToArray()
							: pm.MethodSig.Params.Select(t => (object?)new Marker("param", t)).ToArray();
						result = ps; return true;
					}
				case "get_IsVirtual" when payload is IMethod vm:
					result = vm.ResolveMethodDef()?.IsVirtual == true ? 1 : 0; return true;
				case "get_IsStatic" when payload is IMethod sm:
					result = sm.MethodSig.HasThis ? 0 : 1; return true;
				case "get_ReturnType" when payload is IMethod rm:
					result = TypeMarker(rm.MethodSig.RetType); return true;
				case "get_FieldType" when payload is IField ff:
					result = TypeMarker(ff.FieldSig.Type); return true;
				case "get_DeclaringType":
					result = TypeMarker((payload as IMemberRef)?.DeclaringType?.ToTypeSig()); return true;
				case "Invoke" when payload is IMethod { Name.String: ".ctor" } ctorM && args.Length == 2:
					{
						// ConstructorInfo.Invoke(object[]): construct via newobj semantics.
						var ctorArgs = (Arg(1) as object?[]) ?? [];
						result = Invoke(ctorM, new object?[] { null }.Concat(ctorArgs).ToArray(), true,
							depth, caller, at);
						return true;
					}
				case "Invoke" when payload is IMethod im:
					{
						var target = Arg(1);
						var argArray = (Arg(2) as object?[]) ?? [];
						var callArgs = im.MethodSig.HasThis
							? new[] { target }.Concat(argArray).ToArray()
							: argArray.ToArray();
						// Reflection returns boxed values of the declared type; the VM checks their runtime type.
						result = BoxAs(Invoke(im, callArgs, false, depth, caller, at), im.MethodSig.RetType);
						return true;
					}
				case "GetValue" when payload is IField gf:
					{
						var k = Key(gf);
						if (Arg(1) is ObjectInstance oi)
							result = oi.Fields.TryGetValue(gf.Name, out var v) ? v : DefaultFor(gf.FieldSig.Type);
						else
							result = StaticFields.TryGetValue(k, out var sv) ? sv : DefaultFor(gf.FieldSig.Type);
						return true;
					}
				case "SetValue" when payload is IField sfd:
					{
						if (Arg(1) is ObjectInstance oi) oi.Fields[sfd.Name] = Arg(2);
						else StaticFields[Key(sfd)] = Arg(2);
						return true;
					}
			}
		}
		if (Arg(0) is Marker { What: "param", Payload: TypeSig pt } && name == "get_ParameterType")
		{
			result = TypeMarker(pt);
			return true;
		}
		if (name == "GetType" && args.Length == 1 && m.MethodSig.HasThis && type == "System.Object")
		{
			var v = Arg(0);
			result = v switch
			{
				ObjectInstance oi => TypeMarker(oi.Type.ToTypeSig()),
				Marker { What: "Type" } => TypeMarker(new Importer(module).ImportAsTypeSig(typeof(Type))),
				null => throw new StopException("GetType on null", caller, at),
				_ => TypeMarker(new Importer(module).ImportAsTypeSig(v.GetType())),
			};
			return true;
		}
		if (type == "System.Array" && name == "SetValue" && Arg(0) is Array arr && args.Length >= 3)
		{
			var value = Arg(1); var si = ToInt(Arg(2));
			switch (arr)
			{
				case byte[] b: b[si] = (byte)ToLong(value); break;
				case int[] ia: ia[si] = (int)ToLong(value); break;
				case long[] la: la[si] = ToLong(value); break;
				case object?[] oa: oa[si] = value; break;
				default: arr.SetValue(value, si); break;
			}
			return true;
		}
		// Enums are represented by their integer values.
		if (type == "System.Enum" && name == "ToObject" && args.Length == 2)
		{
			result = Arg(1) is long or int ? Arg(1) : ToLong(Arg(1)); return true;
		}
		if (type == "System.Enum" && name == "GetUnderlyingType"
			&& Arg(0) is Marker { What: "Type", Payload: TypeSig ets })
		{
			var etd = ets.ToTypeDefOrRef()?.ResolveTypeDef();
			var clrEnum = etd is null ? ExternalModels.ResolveBclType(ets) : null;
			result = etd is { IsEnum: true } ? TypeMarker(etd.GetEnumUnderlyingType())
				: clrEnum is { IsEnum: true }
					? TypeMarker(new Importer(module).ImportAsTypeSig(Enum.GetUnderlyingType(clrEnum)))
					: null;
			return true;
		}
		// Only BCL types are created this way (zero values); the target's own types stay unmodelled.
		if (type == "System.Activator" && name == "CreateInstance"
			&& Arg(0) is Marker { What: "Type", Payload: TypeSig actType }
			&& actType.ToTypeDefOrRef()?.ResolveTypeDef()?.Module != module)
		{
			result = DefaultFor(actType); return true;
		}
		if (type == "System.Array" && name == "CreateInstance"
			&& Arg(0) is Marker { What: "Type", Payload: TypeSig arrElem })
		{
			var n = ToInt(Arg(1));
			result = arrElem.ElementType switch
			{
				ElementType.U1 or ElementType.I1 or ElementType.Boolean => new byte[n],
				ElementType.I4 or ElementType.U4 => new int[n],
				ElementType.I8 or ElementType.U8 => new long[n],
				_ => new object?[n],
			};
			return true;
		}
		if (type == "System.Type" && name == "GetTypeFromHandle")
		{
			result = Arg(0) is Marker { Payload: ITypeDefOrRef td } ? TypeMarker(td.ToTypeSig()) : TypeMarker(null);
			return true;
		}
		if (Arg(0) is Marker { What: "Type" } tm
			&& (type is "System.Type" or "System.Reflection.TypeInfo" or "System.Reflection.MemberInfo"))
		{
			var et = (tm.Payload as TypeSig)?.RemovePinnedAndModifiers();
			switch (name)
			{
				case "get_IsByRef": result = et is ByRefSig ? 1 : 0; return true;
				case "get_IsValueType": result = et?.IsValueType == true ? 1 : 0; return true;
				case "get_IsEnum":
					result = (et?.ToTypeDefOrRef()?.ResolveTypeDef()?.IsEnum
							  ?? (et is null ? null : ExternalModels.ResolveBclType(et)?.IsEnum)) == true ? 1 : 0;
					return true;
				case "GetElementType": result = et is NonLeafSig nl ? TypeMarker(nl.Next) : null; return true;
				case "get_TypeHandle": result = tm; return true;
			}
		}
		if (type == "System.Nullable" && name == "GetUnderlyingType"
			&& Arg(0) is Marker { What: "Type", Payload: var nt })
		{
			var ns = (nt as TypeSig)?.RemovePinnedAndModifiers();
			result = ns is GenericInstSig { GenericType.FullName: "System.Nullable`1" } gn
				? TypeMarker(gn.GenericArguments[0])
				: null;
			return true;
		}
		return false;
	}

	/// <summary>isinst semantics for emulator values.</summary>
	private object? IsInstance(object? v, ITypeDefOrRef t)
	{
		if (v is null) return null;
		var want = t.ToTypeSig().RemovePinnedAndModifiers();
		var wantName = want.FullName;
		if (wantName == "System.Object") return v;
		switch (v)
		{
			case ObjectInstance oi:
				for (var td = oi.Type; td is not null; td = td.BaseType?.ResolveTypeDef())
					if (td.FullName == (want.ToTypeDefOrRef()?.FullName ?? wantName)) return v;
				return oi.Type.Interfaces.Any(i => i.Interface.FullName == wantName) ? v : null;
			case Marker mk:
				// Reflection stand-ins are only instances of BCL reflection types, never of target-defined types.
				if (want.ToTypeDefOrRef()?.ResolveTypeDef()?.Module == module) return null;
				return mk.What switch
				{
					"Type" => wantName is "System.Type" or "System.Reflection.TypeInfo"
						or "System.Reflection.MemberInfo" or "System.Reflection.IReflect" ? v : null,
					"member" => wantName.StartsWith("System.Reflection.") ? v : null,
					"delegate" or "bound" => wantName is "System.Delegate" or "System.MulticastDelegate"
						|| wantName.StartsWith("System.Func") || wantName.StartsWith("System.Action")
						|| wantName.StartsWith("System.Comparison") ? v : null,
					_ => wantName.StartsWith("System.") ? v : null,
				};
		}
		var clr = v.GetType();
		var lt = wantName.IndexOf('<');
		var baseName = lt < 0 ? wantName : wantName[..lt];
		for (var ct = clr; ct is not null; ct = ct.BaseType)
		{
			var n = ct.FullName ?? ct.Name;
			var tick = n.IndexOf('[');
			if ((tick < 0 ? n : n[..tick]) == baseName.Replace('/', '+')) return v;
		}
		if (clr.GetInterfaces().Any(i => (i.FullName ?? i.Name).Split('[')[0] == baseName)) return v;
		if (want is SZArraySig && clr.IsArray) return v;
		return null;
	}

	/// <summary>
	/// Value-type semantics: target-defined structs are copied on load/store (addresses still alias).
	/// </summary>
	private static object? CopyIfStruct(object? v)
	{
		if (v is not ObjectInstance { Type.IsValueType: true } s) return v;
		var copy = new ObjectInstance(s.Type);
		foreach (var kv in s.Fields) copy.Fields[kv.Key] = CopyIfStruct(kv.Value);
		if (s.Raw is not null) Buffer.BlockCopy(s.Raw, 0, copy.Raw!, 0, Math.Min(s.Raw.Length, copy.Raw!.Length));
		return copy;
	}

	/// <summary>Resolves references to methods of the target's own (generic) types by name and arity.</summary>
	private MethodDef? ResolveLocal(IMethod m)
	{
		var td = m.DeclaringType?.ScopeType?.ResolveTypeDef()
			?? (m.DeclaringType as TypeSpec)?.TypeSig.ToGenericInstSig()?.GenericType?.TypeDefOrRef.ResolveTypeDef();
		if (td is null || td.Module != module) return null;
		var argc = m.MethodSig.Params.Count;
		return td.Methods.FirstOrDefault(x => x.Name == m.Name && x.MethodSig.Params.Count == argc
			&& x.MethodSig.HasThis == m.MethodSig.HasThis);
	}

	private readonly Dictionary<string, Marker> _typeMarkers = new();

	/// <summary>One marker per type signature so reference equality matches Type equality.</summary>
	private Marker TypeMarker(TypeSig? sig)
	{
		var key = sig?.FullName ?? "<unknown>";
		if (!_typeMarkers.TryGetValue(key, out var mk))
			_typeMarkers[key] = mk = new Marker("Type", sig);
		return mk;
	}

	// ---- helpers ----
	private static string Key(IField f) => f.DeclaringType.FullName + "::" + f.Name;

	private object? DefaultFor(TypeSig? t)
	{
		if (t is null) return null;
		// Target-defined structs: zero-initialised field bag. Enums: their underlying integer zero.
		if (t.ElementType == ElementType.ValueType
			&& t.ToTypeDefOrRef()?.ResolveTypeDef() is { } vtd && vtd.Module == module)
			return vtd.IsEnum ? DefaultFor(vtd.GetEnumUnderlyingType()) : new ObjectInstance(vtd);
		return t.ElementType switch
		{
			ElementType.Boolean or ElementType.Char or ElementType.I1 or ElementType.U1
				or ElementType.I2 or ElementType.U2
				or ElementType.I4 or ElementType.U4 => (object)0,
			ElementType.I8 or ElementType.U8 or ElementType.I or ElementType.U => (object)0L,
			ElementType.R4 or ElementType.R8 => (object)0.0,
			ElementType.ValueType => t.FullName is "System.IntPtr" or "System.UIntPtr" ? (object)0L : null,
			_ => (object?)null,
		};
	}

	private static object? Coerce(object? v, TypeSig t) => t.ElementType switch
	{
		ElementType.I8 or ElementType.U8 or ElementType.I or ElementType.U when v is int i =>
			t.ElementType is ElementType.U8 or ElementType.U ? (long)(uint)i : i,
		_ => v,
	};

	/// <summary>
	/// Box a value as the CLR primitive of the given signature (for values handed back through reflection).
	/// </summary>
	private static object? BoxAs(object? v, TypeSig t)
	{
		if (v is null or ObjectInstance or Marker or string or Array) return v;
		if (!IsNumeric(v)) return v;
		var l = ToLong(v);
		return t.RemovePinnedAndModifiers().ElementType switch
		{
			ElementType.Boolean => (object)(l != 0),
			ElementType.U1 => (object)(byte)l,
			ElementType.I1 => (object)(sbyte)l,
			ElementType.U2 => (object)(ushort)l,
			ElementType.I2 => (object)(short)l,
			ElementType.Char => (object)(char)l,
			ElementType.U4 => (object)(uint)l,
			ElementType.I4 => (object)(int)l,
			ElementType.U8 => (object)(ulong)l,
			ElementType.I8 => (object)l,
			_ => v,
		};
	}

	private static bool IsNumeric(object? o) =>
		o is int or long or double or bool or byte or sbyte or short or ushort or char or uint or ulong or float;
	private static object? Deref(object? o) => o is ByRef b ? b.Get() : o;
	private static int ToInt(object? o) => (int)ToLong(o);
	private static long ToLong(object? o) => Deref(o) switch
	{
		int i => i,
		long l => l,
		double d => d >= 0 ? (long)(ulong)d : (long)d,
		bool b => b ? 1 : 0,
		null => 0,
		byte b8 => b8,
		sbyte s8 => s8,
		short s16 => s16,
		ushort u16 => u16,
		char ch => ch,
		uint u32 => u32,
		ulong u64 => (long)u64,
		float f => (long)f,
		_ => throw new InvalidOperationException("not numeric: " + o),
	};
	private static bool Truthy(object? o) => Deref(o) switch
	{
		null => false,
		int i => i != 0,
		long l => l != 0,
		double d => d != 0,
		var n when IsNumeric(n) => ToLong(n) != 0,
		_ => true,
	};
	private static bool Eq(object? a, object? b)
	{
		a = Deref(a); b = Deref(b);
		if (IsNumeric(a) && IsNumeric(b) && a is not double && b is not double) return ToLong(a) == ToLong(b);
		if (a is null || b is null)
			return a is null && b is null
				|| (a is int ai && ai == 0 && b is null) || (b is int bi && bi == 0 && a is null)
				|| (a is long al && al == 0 && b is null) || (b is long bl && bl == 0 && a is null);
		if (a is double || b is double) return Convert.ToDouble(a) == Convert.ToDouble(b);
		if (a is int or long && b is int or long) return ToLong(a) == ToLong(b);
		return ReferenceEquals(a, b) || a.Equals(b);
	}
	private static int Cmp(object? a, object? b, bool unsigned)
	{
		a = Deref(a); b = Deref(b);
		if (a is double || b is double) return Convert.ToDouble(a).CompareTo(Convert.ToDouble(b));
		if (a is int ia && b is int ib) return unsigned ? ((uint)ia).CompareTo((uint)ib) : ia.CompareTo(ib);
		var la = ToLong(a); var lb = ToLong(b);
		return unsigned ? ((ulong)la).CompareTo((ulong)lb) : la.CompareTo(lb);
	}
	private static void Bin(Stack<object?> s, Func<long, long, long> l, Func<int, int, int> i)
	{
		var b = Deref(s.Pop()); var a = Deref(s.Pop());
		if (a is double || b is double) throw new InvalidOperationException("float arithmetic not modelled");
		if (a is long or ulong || b is long or ulong) s.Push(l(ToLong(a), ToLong(b)));
		else s.Push(unchecked(i(ToInt(a), ToInt(b))));
	}
	private static void BinU(Stack<object?> s, Func<ulong, ulong, ulong> l, Func<uint, uint, uint> i)
	{
		var b = Deref(s.Pop()); var a = Deref(s.Pop());
		if (a is long || b is long) s.Push((long)l((ulong)ToLong(a), (ulong)ToLong(b)));
		else s.Push((int)i((uint)ToInt(a), (uint)ToInt(b)));
	}
	internal static string Describe(object? o) => o switch
	{
		null => "null",
		Marker { Payload: IMemberRef mr } mk => $"{mk.What}:{mr.Name}",
		Marker { Payload: TypeSig ts } mk => $"{mk.What}:{ts.TypeName}",
		Marker mk => "marker:" + mk.What,
		ObjectInstance oi => "obj:" + oi.Type.Name,
		string s => "\"" + (s.Length > 40 ? s[..40] + "…" : s) + "\"",
		int or long => o.ToString()!,
		Array a => $"{o.GetType().Name}[{a.Length}]",
		_ => o.GetType().Name,
	};
}
