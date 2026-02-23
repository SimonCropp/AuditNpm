class AuditReportParserTests
{
    static string LoadScenario(string name)
    {
        var path = Path.Combine(AppContext.BaseDirectory, "Scenarios", name);
        return File.ReadAllText(path);
    }

    [Test]
    public Task CleanAudit()
    {
        var json = LoadScenario("clean-audit.json");
        var report = AuditReportParser.Parse(json);

        return Verify(report);
    }

    [Test]
    public Task MixedVulnerabilities()
    {
        var json = LoadScenario("vulnerabilities-mixed.json");
        var report = AuditReportParser.Parse(json);

        return Verify(report);
    }
}
