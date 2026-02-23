class AuditReportAnalyzerTests
{
    static string LoadScenario(string name)
    {
        var path = Path.Combine(AppContext.BaseDirectory, "Scenarios", name);
        return File.ReadAllText(path);
    }

    static AuditReport ParseMixed() => AuditReportParser.Parse(LoadScenario("vulnerabilities-mixed.json"));

    [Test]
    public Task DefaultThreshold_ReportsModerateAndAbove()
    {
        var report = ParseMixed();
        var config = new AuditConfig("moderate", []);

        return Verify(AuditReportAnalyzer.Analyze(report, config));
    }

    [Test]
    public Task CriticalThreshold_ReportsOnlyCritical()
    {
        var report = ParseMixed();
        var config = new AuditConfig("critical", []);

        return Verify(AuditReportAnalyzer.Analyze(report, config));
    }

    [Test]
    public Task LowThreshold_ReportsAll()
    {
        var report = ParseMixed();
        var config = new AuditConfig("low", []);

        return Verify(AuditReportAnalyzer.Analyze(report, config));
    }

    [Test]
    public Task IgnoreSingleCve_IgnoresMatchingVuln()
    {
        var report = ParseMixed();
        var config = new AuditConfig("low", ["CVE-2024-29041"]);

        return Verify(AuditReportAnalyzer.Analyze(report, config));
    }

    [Test]
    public Task IgnoreAllCves_ForMultiAdvisoryVuln_IgnoresIt()
    {
        var report = ParseMixed();
        var config = new AuditConfig("low", ["CVE-2018-14732", "CVE-2018-14733"]);

        return Verify(AuditReportAnalyzer.Analyze(report, config));
    }

    [Test]
    public Task IgnorePartialCves_ForMultiAdvisoryVuln_StillReportsIt()
    {
        var report = ParseMixed();
        var config = new AuditConfig("low", ["CVE-2018-14732"]);

        return Verify(AuditReportAnalyzer.Analyze(report, config));
    }

    [Test]
    public Task CleanAudit_NoFailures()
    {
        var report = AuditReportParser.Parse(LoadScenario("clean-audit.json"));
        var config = new AuditConfig("moderate", []);

        return Verify(AuditReportAnalyzer.Analyze(report, config));
    }
}
