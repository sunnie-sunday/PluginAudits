using System.Reflection;
using System.Runtime.Loader;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using static Microsoft.CodeAnalysis.CSharp.SyntaxFactory;

namespace PluginAudits.DailyRoutines;

/// <summary>The .NET Reactor string decryptor found in a decompiled assembly.</summary>
internal sealed record DecryptorInfo(
	SyntaxTree Tree,
	string Namespace,
	string ClassName,
	string MethodName,
	string ResourceName);

/// <summary>
/// Recompiles the <em>decompiled source</em> of the string decryptor on its own, feeds it the encrypted
/// resource as a byte array, and reads back the plaintext blob. The original assembly is never loaded.
/// </summary>
internal static class DecryptorRebuilder
{
	private const string HostNamespace = "DrdHost";
	private const string HostClass = "Resource";

	/// <summary>
	/// Types the rebuilt decryptor may touch. Anything else aborts unless --trust-decryptor is given.
	/// </summary>
	private static readonly HashSet<string> AllowedTypes =
	[
		"void", "object", "string", "bool", "byte", "sbyte", "char", "short", "ushort", "int", "uint", "long", "ulong",
		"System.Array", "System.Buffer", "System.BitConverter", "System.Convert", "System.Math",
		"System.Index", "System.Range",
		"System.IDisposable", "System.Attribute", "System.Exception", "System.Type",
		"System.Span<T>", "System.ReadOnlySpan<T>",
		"System.Text.Encoding",
		"System.IO.Stream", "System.IO.MemoryStream", "System.IO.BinaryReader",
	];

	public static DecryptorInfo? Locate(IEnumerable<SyntaxTree> trees)
	{
		foreach (var tree in trees)
		{
			foreach (var method in tree.GetRoot().DescendantNodes().OfType<MethodDeclarationSyntax>())
			{
				if (!method.Modifiers.Any(SyntaxKind.StaticKeyword)
					|| method.ReturnType is not PredefinedTypeSyntax { Keyword.ValueText: "string" }
					|| method.ParameterList.Parameters.Count != 1
					|| method.ParameterList.Parameters[0].Type is not PredefinedTypeSyntax { Keyword.ValueText: "int" }
					|| method.Parent is not ClassDeclarationSyntax cls
					|| cls.Parent is ClassDeclarationSyntax)
					continue;

				var resource = FindResourceCall(method)?.ArgumentList.Arguments[0].Expression
					as LiteralExpressionSyntax;
				if (resource?.Token.Value is not string resourceName)
					continue;

				var ns = cls.Ancestors().OfType<BaseNamespaceDeclarationSyntax>().FirstOrDefault()
					?.Name.ToString() ?? "";
				return new DecryptorInfo(tree, ns, cls.Identifier.ValueText, method.Identifier.ValueText, resourceName);
			}
		}
		return null;
	}

	public static byte[] DecryptBlob(DecryptorInfo info, byte[] encryptedResource, bool trustDecryptor, TextWriter log)
	{
		var tree = Patch(info, trustDecryptor, log, out var compilation);
		if (!trustDecryptor)
			EnforceAllowlist(compilation, tree, info);

		using var pe = new MemoryStream();
		var emit = compilation.Emit(pe);
		if (!emit.Success)
			throw new InvalidOperationException(
				"Rebuilt decryptor failed to compile:\n" + FormatErrors(emit.Diagnostics));

		pe.Position = 0;
		var alc = new AssemblyLoadContext("drdecrypt-" + info.ClassName, isCollectible: true);
		try
		{
			var asm = alc.LoadFromStream(pe);
			asm.GetType($"{HostNamespace}.{HostClass}", throwOnError: true)!
			   .GetField("Data")!.SetValue(null, encryptedResource);

			var fullName = string.IsNullOrEmpty(info.Namespace) ? info.ClassName : $"{info.Namespace}.{info.ClassName}";
			var type = asm.GetType(fullName, throwOnError: true)!;
			var method = type.GetMethod(info.MethodName,
				BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic)!;

			// Index 0 is always a valid record; the first call decrypts the whole resource into a static byte[].
			var run = Task.Run(() => method.Invoke(null, [0]));
			if (!run.Wait(TimeSpan.FromSeconds(60)))
				throw new TimeoutException("Rebuilt decryptor did not finish within 60 s.");

			var blob = type.GetFields(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic)
						   .Where(f => f.FieldType == typeof(byte[]))
						   .Select(f => (byte[]?)f.GetValue(null))
						   .Where(b => b is { Length: > 0 })
						   .MaxBy(b => b!.Length);
			return blob ?? throw new InvalidOperationException("Decryptor ran but no plaintext blob was found.");
		}
		finally
		{
			alc.Unload();
		}
	}

	private static InvocationExpressionSyntax? FindResourceCall(SyntaxNode node) =>
		node.DescendantNodes().OfType<InvocationExpressionSyntax>().FirstOrDefault(i =>
			i.Expression is MemberAccessExpressionSyntax { Name.Identifier.ValueText: "GetManifestResourceStream" }
			&& i.ArgumentList.Arguments.Count == 1);

	/// <summary>
	/// Makes the decompiled decryptor compile on its own:
	/// 1. drop non-System usings and route the resource read to an in-memory byte array;
	/// 2. delete statements that call into the rest of the obfuscated assembly (anti-tamper/init stubs);
	/// 3. hoist the decryptor method's locals to the top of the method, because the decompiler's
	///    goto-heavy output re-declares them as <c>T x = default(T);</c> after jump targets, which
	///    clobbers values (and trips definite-assignment checks) once compiled as C#.
	/// </summary>
	private static SyntaxTree Patch(
		DecryptorInfo info, bool allowUnsafe, TextWriter log, out CSharpCompilation compilation)
	{
		var parse = CSharpParseOptions.Default.WithLanguageVersion(LanguageVersion.Latest);
		var root = (CompilationUnitSyntax)info.Tree.GetRoot();

		var foreignUsings = root.Usings
			.Where(u => !(u.Name?.ToString() ?? "").StartsWith("System", StringComparison.Ordinal));
		root = root.RemoveNodes(foreignUsings, SyntaxRemoveOptions.KeepNoTrivia)!;
		var resourceCall = FindResourceCall(root)!;
		root = root.ReplaceNode(resourceCall,
			ParseExpression($"new global::System.IO.MemoryStream(global::{HostNamespace}.{HostClass}.Data, false)"));

		var host = CSharpSyntaxTree.ParseText(
			$"namespace {HostNamespace} {{ public static class {HostClass} {{ " +
			$"public static byte[] Data = new byte[0]; }} }}",
			parse);

		var options = new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary,
			optimizationLevel: OptimizationLevel.Release,
			allowUnsafe: allowUnsafe,
			nullableContextOptions: NullableContextOptions.Disable);
		var references = ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!)
			.Split(Path.PathSeparator)
			.Select(p => MetadataReference.CreateFromFile(p));

		CSharpCompilation Compile(CompilationUnitSyntax r) =>
			CSharpCompilation.Create("drdecrypt_" + info.ClassName,
				[CSharpSyntaxTree.Create(r, parse, info.Tree.FilePath), host], references, options);

		// Remove dangling calls into the rest of the assembly until only real errors remain.
		string[] unresolvedIds = ["CS0103", "CS0117", "CS0234", "CS0246", "CS0400", "CS1061"];
		for (var pass = 0; pass < 20; pass++)
		{
			var c = Compile(root);
			var tree = c.SyntaxTrees[0];
			var doomed = c.GetDiagnostics()
				.Where(d => d.Severity == DiagnosticSeverity.Error && unresolvedIds.Contains(d.Id)
					&& d.Location.SourceTree == tree)
				.Select(d => (SyntaxNode?)tree.GetRoot().FindNode(d.Location.SourceSpan)
					.AncestorsAndSelf()
					.FirstOrDefault(n => n is ExpressionStatementSyntax or AttributeListSyntax or UsingDirectiveSyntax))
				.OfType<SyntaxNode>()
				.Distinct()
				.ToList();
			if (doomed.Count == 0)
				break;
			log.WriteLine($"    stripped {doomed.Count} reference(s) to the rest of the obfuscated assembly");
			root = ((CompilationUnitSyntax)tree.GetRoot()).RemoveNodes(doomed, SyntaxRemoveOptions.KeepNoTrivia)!;
		}

		root = HoistLocals(info, Compile(root));
		compilation = Compile(root);
		return compilation.SyntaxTrees[0];
	}

	private static CompilationUnitSyntax HoistLocals(DecryptorInfo info, CSharpCompilation compilation)
	{
		var tree = compilation.SyntaxTrees[0];
		var model = compilation.GetSemanticModel(tree);
		var method = tree.GetRoot().DescendantNodes().OfType<MethodDeclarationSyntax>()
			.First(m => m.Identifier.ValueText == info.MethodName && m.ParameterList.Parameters.Count == 1);
		if (method.Body is null)
			return (CompilationUnitSyntax)tree.GetRoot();

		var declarations = method.Body.DescendantNodes()
			.OfType<LocalDeclarationStatementSyntax>()
			.Where(d => !d.IsConst && d.UsingKeyword.IsKind(SyntaxKind.None)
						&& !d.Ancestors().TakeWhile(a => a != method.Body)
							 .Any(a => a is AnonymousFunctionExpressionSyntax or LocalFunctionStatementSyntax))
			.ToList();

		var hoisted = new Dictionary<string, string>(StringComparer.Ordinal);
		foreach (var variable in declarations.SelectMany(d => d.Declaration.Variables))
		{
			if (model.GetDeclaredSymbol(variable) is not ILocalSymbol local)
				continue;
			var type = local.Type.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat);
			if (hoisted.TryGetValue(local.Name, out var existing) && existing != type)
				throw new InvalidOperationException(
					$"Cannot hoist local '{local.Name}': declared as both {existing} and {type}.");
			hoisted[local.Name] = type;
		}

		var body = method.Body.ReplaceNodes(declarations, (original, _) =>
		{
			var assignments = original.Declaration.Variables
				.Where(v => v.Initializer is not null
							&& v.Initializer.Value is not DefaultExpressionSyntax
							&& !v.Initializer.Value.IsKind(SyntaxKind.DefaultLiteralExpression))
				.Select(v => (StatementSyntax)ExpressionStatement(
					AssignmentExpression(SyntaxKind.SimpleAssignmentExpression,
						IdentifierName(v.Identifier.ValueText), v.Initializer!.Value)))
				.ToList();
			StatementSyntax replacement = assignments.Count switch
			{
				0 => EmptyStatement(),
				1 => assignments[0],
				_ => Block(assignments),
			};
			return replacement.WithTriviaFrom(original);
		});

		var prologue = hoisted.Select(kv => (StatementSyntax)ParseStatement($"{kv.Value} {kv.Key} = default;\n"));
		body = body.WithStatements(List(prologue.Concat(body.Statements)));
		return ((CompilationUnitSyntax)tree.GetRoot()).ReplaceNode(method.Body, body);
	}

	private static void EnforceAllowlist(CSharpCompilation compilation, SyntaxTree tree, DecryptorInfo info)
	{
		var model = compilation.GetSemanticModel(tree);
		var violations = new SortedSet<string>(StringComparer.Ordinal);

		foreach (var node in tree.GetRoot().DescendantNodes())
		{
			if (node is MethodDeclarationSyntax m
				&& (m.Modifiers.Any(SyntaxKind.ExternKeyword) || m.Modifiers.Any(SyntaxKind.UnsafeKeyword)))
				violations.Add($"extern/unsafe method {m.Identifier.ValueText}");
			if (node is FunctionPointerTypeSyntax or PointerTypeSyntax or UnsafeStatementSyntax)
				violations.Add("pointer/unsafe code");

			if (node is not (ExpressionSyntax or TypeSyntax))
				continue;
			var symbol = model.GetSymbolInfo(node).Symbol;
			var type = symbol switch
			{
				INamedTypeSymbol t => t,
				IMethodSymbol or IFieldSymbol or IPropertySymbol or IEventSymbol => symbol.ContainingType,
				_ => null,
			};
			if (type is null || IsOwn(type, info))
				continue;
			if (type is IArrayTypeSymbol)
				continue;
			var name = type.OriginalDefinition.ToDisplayString();
			if (!AllowedTypes.Contains(name))
				violations.Add(name + (symbol is INamedTypeSymbol ? "" : "." + symbol!.Name));
		}

		if (violations.Count > 0)
			throw new InvalidOperationException(
				"The decryptor uses APIs outside the allowlist, so it was not executed:\n  " +
				string.Join("\n  ", violations) +
				"\nReview the decompiled decryptor and re-run with --trust-decryptor if this is expected.");
	}

	private static bool IsOwn(INamedTypeSymbol type, DecryptorInfo info)
	{
		for (var t = type; t is not null; t = t.ContainingType)
		{
			if (t.Name == info.ClassName && t.ContainingType is null)
				return true;
			if (t.ContainingNamespace?.ToDisplayString() == HostNamespace)
				return true;
		}
		return false;
	}

	private static string FormatErrors(IEnumerable<Diagnostic> diagnostics) =>
		string.Join("\n", diagnostics
			.Where(d => d.Severity == DiagnosticSeverity.Error)
			.Take(20)
			.Select(d => "  " + d));
}
