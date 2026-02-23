record AnalysisResult(
    List<ReportedVulnerability> Reported,
    List<IgnoredVulnerability> Ignored)
{
    public bool HasFailures => Reported.Count != 0;
}

record ReportedVulnerability(string Name, Vulnerability Vulnerability);

record IgnoredVulnerability(string Name, Vulnerability Vulnerability, List<string> MatchedCveIds);
