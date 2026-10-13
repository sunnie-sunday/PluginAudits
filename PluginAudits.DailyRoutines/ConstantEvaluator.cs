using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace PluginAudits.DailyRoutines;

/// <summary>
/// Evaluates the constant integer expressions .NET Reactor uses as string-table indices,
/// e.g. <c>0x7F3D068E ^ &lt;Module&gt;.inst.m_7891…</c> or <c>-unchecked(a - b) ^ c</c>,
/// with C# <c>int</c> (unchecked, 32-bit) semantics.
/// </summary>
internal sealed class ConstantEvaluator(IReadOnlyDictionary<string, int> fields)
{
	public bool TryEvaluate(ExpressionSyntax expression, out int value)
	{
		try
		{
			value = Eval(expression);
			return true;
		}
		catch (NotSupportedException)
		{
			value = 0;
			return false;
		}
	}

	private int Eval(ExpressionSyntax e) => e switch
	{
		LiteralExpressionSyntax lit => lit.Token.Value switch
		{
			int i => i,
			uint u => unchecked((int)u),
			long l => unchecked((int)l),
			ulong ul => unchecked((int)ul),
			_ => throw new NotSupportedException(),
		},
		ParenthesizedExpressionSyntax p => Eval(p.Expression),
		CheckedExpressionSyntax c => Eval(c.Expression),
		CastExpressionSyntax c => Eval(c.Expression),
		PrefixUnaryExpressionSyntax u => u.Kind() switch
		{
			SyntaxKind.UnaryMinusExpression => unchecked(-Eval(u.Operand)),
			SyntaxKind.UnaryPlusExpression => Eval(u.Operand),
			SyntaxKind.BitwiseNotExpression => ~Eval(u.Operand),
			// The decompiler prints -(-x) as "--x", which Roslyn parses as a pre-decrement.
			SyntaxKind.PreDecrementExpression => Eval(u.Operand),
			_ => throw new NotSupportedException(),
		},
		BinaryExpressionSyntax b => Binary(b),
		MemberAccessExpressionSyntax m when fields.TryGetValue(m.Name.Identifier.ValueText, out var f) => f,
		IdentifierNameSyntax id when fields.TryGetValue(id.Identifier.ValueText, out var f) => f,
		_ => throw new NotSupportedException(),
	};

	private int Binary(BinaryExpressionSyntax b)
	{
		var l = Eval(b.Left);
		var r = Eval(b.Right);
		return unchecked(b.Kind() switch
		{
			SyntaxKind.ExclusiveOrExpression => l ^ r,
			SyntaxKind.BitwiseOrExpression => l | r,
			SyntaxKind.BitwiseAndExpression => l & r,
			SyntaxKind.AddExpression => l + r,
			SyntaxKind.SubtractExpression => l - r,
			SyntaxKind.MultiplyExpression => l * r,
			SyntaxKind.DivideExpression when r != 0 => l / r,
			SyntaxKind.ModuloExpression when r != 0 => l % r,
			SyntaxKind.LeftShiftExpression => l << (r & 31),
			SyntaxKind.RightShiftExpression => l >> (r & 31),
			SyntaxKind.UnsignedRightShiftExpression => (int)((uint)l >> (r & 31)),
			_ => throw new NotSupportedException(),
		});
	}

	/// <summary>
	/// Collects the integer fields that .NET Reactor initialises in the &lt;Module&gt; type's static
	/// constructor (<c>inst.m_xxx = expr;</c>). Field names are GUID-derived, so the bare name is a unique key.
	/// </summary>
	public static Dictionary<string, int> CollectModuleFields(IEnumerable<SyntaxTree> trees)
	{
		var fields = new Dictionary<string, int>(StringComparer.Ordinal);
		var evaluator = new ConstantEvaluator(fields);
		foreach (var tree in trees)
		{
			var root = tree.GetRoot();
			foreach (var type in root.DescendantNodes().OfType<TypeDeclarationSyntax>())
			{
				if (!type.Identifier.ValueText.StartsWith("_003CModule_003E", StringComparison.Ordinal))
					continue;
				foreach (var assign in type.DescendantNodes().OfType<AssignmentExpressionSyntax>())
				{
					if (!assign.IsKind(SyntaxKind.SimpleAssignmentExpression))
						continue;
					var name = assign.Left switch
					{
						MemberAccessExpressionSyntax m => m.Name.Identifier.ValueText,
						IdentifierNameSyntax id => id.Identifier.ValueText,
						_ => null,
					};
					if (name is not null && evaluator.TryEvaluate(assign.Right, out var v))
						fields[name] = v;
				}
			}
		}
		return fields;
	}
}
