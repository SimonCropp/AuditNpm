static class AuditReportAnalyzer
{
    static readonly Dictionary<string, int> severityRanking = new()
    {
        ["info"] = 0,
        ["low"] = 1,
        ["moderate"] = 2,
        ["high"] = 3,
        ["critical"] = 4,
    };

    public static AnalysisResult Analyze(AuditReport report, AuditConfig config)
    {
        var threshold = GetSeverityRank(config.Severity);
        var reported = new List<ReportedVulnerability>();
        var ignored = new List<IgnoredVulnerability>();

        foreach (var (name, vuln) in report.Vulnerabilities)
        {
            // Skip transitive-only entries (via all strings, no direct advisories)
            // The root advisory will appear in its own entry
            if (vuln.Advisories.Count == 0)
            {
                continue;
            }

            var rank = GetSeverityRank(vuln.Severity);
            if (rank < threshold)
            {
                continue;
            }

            var allCveIds = vuln.Advisories
                .SelectMany(a => a.CveIds)
                .Where(id => !string.IsNullOrEmpty(id))
                .ToList();

            var matchedIgnores = allCveIds
                .Where(id => config.Ignore.Contains(id))
                .ToList();

            // A vuln is ignored only if ALL its CVE IDs are in the ignore set
            if (allCveIds.Count != 0 &&
                matchedIgnores.Count == allCveIds.Count)
            {
                ignored.Add(new(name, vuln, matchedIgnores));
            }
            else
            {
                reported.Add(new(name, vuln));
            }
        }

        return new(reported, ignored);
    }

    static int GetSeverityRank(string severity) =>
        severityRanking.GetValueOrDefault(severity.ToLowerInvariant(), 0);
}
