static class ConsoleReporter
{
    static readonly Dictionary<string, int> severityOrder = new()
    {
        ["critical"] = 4,
        ["high"] = 3,
        ["moderate"] = 2,
        ["low"] = 1,
        ["info"] = 0,
    };

    public static void Report(AnalysisResult result, IReadOnlyList<ExpiredIgnore> expiredIgnores)
    {
        if (expiredIgnores.Count != 0)
        {
            Log.Information("");
            Log.Information("Expired ignores (no longer suppressed):");
            foreach (var expired in expiredIgnores)
            {
                Log.Information("  {Id} (expired {Until})", expired.Id, expired.Until);
            }
        }

        if (result.Ignored.Count != 0)
        {
            Log.Information("");
            Log.Information("Ignored vulnerabilities ({Count}):", result.Ignored.Count);
            foreach (var (name, vuln, matchedCveIds) in result.Ignored)
            {
                var cveList = string.Join(", ", matchedCveIds);
                Log.Information("  {Severity} | {Name} | {Range} | ignored: {CveIds}",
                    vuln.Severity.ToUpperInvariant(),
                    name,
                    vuln.Range,
                    cveList);
            }
        }

        if (result.Reported.Count != 0)
        {
            Log.Information("");
            Log.Information("Vulnerabilities found ({Count}):", result.Reported.Count);

            var sorted = result.Reported
                .OrderByDescending(r => severityOrder.GetValueOrDefault(r.Vulnerability.Severity, 0))
                .ToList();

            foreach (var (name, vuln) in sorted)
            {
                var directLabel = vuln.IsDirect ? "direct" : "transitive";
                var fixLabel = vuln.FixAvailable switch
                {
                    true => "fix available",
                    false => "no fix",
                    _ => "unknown",
                };

                var cveIds = vuln.Advisories
                    .SelectMany(a => a.CveIds)
                    .Where(id => !string.IsNullOrEmpty(id))
                    .ToList();

                var ghsaIds = vuln.Advisories
                    .Where(a => !string.IsNullOrEmpty(a.GhsaId))
                    .Select(a => a.GhsaId)
                    .ToList();

                var idDisplay = cveIds.Count != 0
                    ? string.Join(", ", cveIds)
                    : ghsaIds.Count != 0
                        ? string.Join(", ", ghsaIds)
                        : "no ID";

                Log.Information("  {Severity} | {Name} | {DirectLabel} | {FixLabel} | {Range} | {Ids}",
                    vuln.Severity.ToUpperInvariant(),
                    name,
                    directLabel,
                    fixLabel,
                    vuln.Range,
                    idDisplay);
            }
        }

        Log.Information("");
        if (result.HasFailures)
        {
            Log.Error("npm audit failed: {Count} vulnerabilities found above threshold", result.Reported.Count);
        }
        else
        {
            Log.Information("npm audit passed: no vulnerabilities above threshold");
        }
    }
}
