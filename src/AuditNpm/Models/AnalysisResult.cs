record AnalysisResult(
    List<ReportedVulnerability> Reported,
    List<IgnoredVulnerability> Ignored)
{
    public bool HasFailures => Reported.Count != 0;
}
