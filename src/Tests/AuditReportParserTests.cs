namespace testing;

class AuditReportParserTests
{
    static string LoadScenario(string name)
    {
        var path = Path.Combine(AppContext.BaseDirectory, "Scenarios", name);
        return File.ReadAllText(path);
    }

    [Test]
    public async Task CleanAudit_ReturnsEmptyVulnerabilities()
    {
        var json = LoadScenario("clean-audit.json");
        var report = AuditReportParser.Parse(json);

        await Assert.That(report.Vulnerabilities).IsEmpty();
        await Assert.That(report.Metadata.TotalVulnerabilities).IsEqualTo(0);
    }

    [Test]
    public async Task MixedVulnerabilities_ParsesAllEntries()
    {
        var json = LoadScenario("vulnerabilities-mixed.json");
        var report = AuditReportParser.Parse(json);

        await Assert.That(report.Vulnerabilities).Count().IsEqualTo(5);
    }

    [Test]
    public async Task MixedVulnerabilities_ParsesDirectAdvisory()
    {
        var json = LoadScenario("vulnerabilities-mixed.json");
        var report = AuditReportParser.Parse(json);

        var lodash = report.Vulnerabilities["lodash"];
        await Assert.That(lodash.Severity).IsEqualTo("critical");
        await Assert.That(lodash.IsDirect).IsTrue();
        await Assert.That(lodash.Advisories).Count().IsEqualTo(1);
        await Assert.That(lodash.Advisories[0].GhsaId).IsEqualTo("GHSA-jf85-cpcp-j695");
        await Assert.That(lodash.Advisories[0].CveIds).Contains("CVE-2021-23337");
        await Assert.That(lodash.FixAvailable).IsTrue();
    }

    [Test]
    public async Task MixedVulnerabilities_ParsesTransitiveViaStrings()
    {
        var json = LoadScenario("vulnerabilities-mixed.json");
        var report = AuditReportParser.Parse(json);

        // mkdirp has via: ["minimist"] (string, not object) - no advisories
        var mkdirp = report.Vulnerabilities["mkdirp"];
        await Assert.That(mkdirp.Advisories).IsEmpty();
        await Assert.That(mkdirp.IsDirect).IsTrue();
    }

    [Test]
    public async Task MixedVulnerabilities_ParsesMultipleAdvisories()
    {
        var json = LoadScenario("vulnerabilities-mixed.json");
        var report = AuditReportParser.Parse(json);

        var webpack = report.Vulnerabilities["webpack-dev-server"];
        await Assert.That(webpack.Advisories).Count().IsEqualTo(2);
        await Assert.That(webpack.Advisories[0].CveIds).Contains("CVE-2018-14732");
        await Assert.That(webpack.Advisories[1].CveIds).Contains("CVE-2018-14733");
        await Assert.That(webpack.FixAvailable).IsFalse();
    }

    [Test]
    public async Task MixedVulnerabilities_ParsesFixAvailableAsObject()
    {
        var json = LoadScenario("vulnerabilities-mixed.json");
        var report = AuditReportParser.Parse(json);

        var express = report.Vulnerabilities["express"];
        await Assert.That(express.FixAvailable).IsTrue();
    }

    [Test]
    public async Task MixedVulnerabilities_ParsesMetadata()
    {
        var json = LoadScenario("vulnerabilities-mixed.json");
        var report = AuditReportParser.Parse(json);

        await Assert.That(report.Metadata.TotalVulnerabilities).IsEqualTo(5);
        await Assert.That(report.Metadata.SeverityCounts["critical"]).IsEqualTo(1);
        await Assert.That(report.Metadata.SeverityCounts["high"]).IsEqualTo(1);
        await Assert.That(report.Metadata.SeverityCounts["moderate"]).IsEqualTo(2);
        await Assert.That(report.Metadata.SeverityCounts["low"]).IsEqualTo(1);
    }
}
