namespace testing;

class AuditReportAnalyzerTests
{
    static string LoadScenario(string name)
    {
        var path = Path.Combine(AppContext.BaseDirectory, "Scenarios", name);
        return File.ReadAllText(path);
    }

    static AuditReport ParseMixed() => AuditReportParser.Parse(LoadScenario("vulnerabilities-mixed.json"));

    [Test]
    public async Task DefaultThreshold_ReportsModerateAndAbove()
    {
        var report = ParseMixed();
        var config = new AuditConfig("moderate", []);

        var result = AuditReportAnalyzer.Analyze(report, config);

        // lodash (critical), webpack-dev-server (high), minimist (moderate) = 3
        // mkdirp (moderate but via-strings-only, no advisories) is skipped
        await Assert.That(result.Reported).Count().IsEqualTo(3);
        await Assert.That(result.HasFailures).IsTrue();
    }

    [Test]
    public async Task CriticalThreshold_ReportsOnlyCritical()
    {
        var report = ParseMixed();
        var config = new AuditConfig("critical", []);

        var result = AuditReportAnalyzer.Analyze(report, config);

        await Assert.That(result.Reported).Count().IsEqualTo(1);
        await Assert.That(result.Reported[0].Name).IsEqualTo("lodash");
    }

    [Test]
    public async Task LowThreshold_ReportsAll()
    {
        var report = ParseMixed();
        var config = new AuditConfig("low", []);

        var result = AuditReportAnalyzer.Analyze(report, config);

        // All 4 with advisories: lodash, minimist, express, webpack-dev-server
        // mkdirp skipped (no advisories)
        await Assert.That(result.Reported).Count().IsEqualTo(4);
    }

    [Test]
    public async Task IgnoreSingleCve_IgnoresMatchingVuln()
    {
        var report = ParseMixed();
        var config = new AuditConfig("low", ["CVE-2024-29041"]);

        var result = AuditReportAnalyzer.Analyze(report, config);

        await Assert.That(result.Reported).Count().IsEqualTo(3);
        await Assert.That(result.Ignored).Count().IsEqualTo(1);
        await Assert.That(result.Ignored[0].Name).IsEqualTo("express");
    }

    [Test]
    public async Task IgnoreAllCves_ForMultiAdvisoryVuln_IgnoresIt()
    {
        var report = ParseMixed();
        var config = new AuditConfig("low", ["CVE-2018-14732", "CVE-2018-14733"]);

        var result = AuditReportAnalyzer.Analyze(report, config);

        // webpack-dev-server has 2 advisories with 2 CVEs, both ignored
        var ignoredNames = result.Ignored.Select(i => i.Name).ToList();
        await Assert.That(ignoredNames).Contains("webpack-dev-server");
    }

    [Test]
    public async Task IgnorePartialCves_ForMultiAdvisoryVuln_StillReportsIt()
    {
        var report = ParseMixed();
        // Only ignore one of webpack-dev-server's two CVEs
        var config = new AuditConfig("low", ["CVE-2018-14732"]);

        var result = AuditReportAnalyzer.Analyze(report, config);

        var reportedNames = result.Reported.Select(r => r.Name).ToList();
        await Assert.That(reportedNames).Contains("webpack-dev-server");
    }

    [Test]
    public async Task CleanAudit_NoFailures()
    {
        var report = AuditReportParser.Parse(LoadScenario("clean-audit.json"));
        var config = new AuditConfig("moderate", []);

        var result = AuditReportAnalyzer.Analyze(report, config);

        await Assert.That(result.Reported).IsEmpty();
        await Assert.That(result.Ignored).IsEmpty();
        await Assert.That(result.HasFailures).IsFalse();
    }
}
