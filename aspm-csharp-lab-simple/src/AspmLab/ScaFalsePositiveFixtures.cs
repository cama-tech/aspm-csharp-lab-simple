// SCA-FP-001: these strings resemble dependency declarations but they are not
// PackageReference elements. A dependency scanner must not report them as an
// installed vulnerable component.
public static class ScaFalsePositiveFixtures
{
    public const string DocumentationExample = "PackageReference Include=Fake.Vulnerable.Package Version=1.0.0";
    public const string NonDependencyName = "Newtonsoft.Json.Legacy.Documentation";
}
