using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using static Microsoft.CodeAnalysis.CSharp.SyntaxFactory;

namespace PluginAudits.DailyRoutines;

/// <summary>Replaces every <c>Decryptor.Method(indexExpr)</c> call with the plaintext string literal.</summary>
internal sealed class CallSiteRewriter(
	string decryptorClass,
	string decryptorMethod,
	ConstantEvaluator evaluator,
	StringTable table) : CSharpSyntaxRewriter
{
	public int Resolved { get; private set; }
	public int Unresolved { get; private set; }
	public List<int> ResolvedIndices { get; } = [];

	public override SyntaxNode? VisitInvocationExpression(InvocationExpressionSyntax node)
	{
		var visited = (InvocationExpressionSyntax)base.VisitInvocationExpression(node)!;
		if (!IsDecryptorCall(visited))
			return visited;

		if (evaluator.TryEvaluate(visited.ArgumentList.Arguments[0].Expression, out var index)
			&& table.TryGet(index, out var text))
		{
			Resolved++;
			ResolvedIndices.Add(index);
			return LiteralExpression(SyntaxKind.StringLiteralExpression, Literal(text)).WithTriviaFrom(visited);
		}

		Unresolved++;
		return visited;
	}

	private bool IsDecryptorCall(InvocationExpressionSyntax call)
	{
		if (call.ArgumentList.Arguments.Count != 1)
			return false;
		return call.Expression switch
		{
			MemberAccessExpressionSyntax m => m.Name.Identifier.ValueText == decryptorMethod
											  && LastIdentifier(m.Expression) == decryptorClass,
			IdentifierNameSyntax id => id.Identifier.ValueText == decryptorMethod,
			_ => false,
		};
	}

	private static string? LastIdentifier(ExpressionSyntax e) => e switch
	{
		IdentifierNameSyntax id => id.Identifier.ValueText,
		MemberAccessExpressionSyntax m => m.Name.Identifier.ValueText,
		AliasQualifiedNameSyntax a => a.Name.Identifier.ValueText,
		_ => null,
	};
}
