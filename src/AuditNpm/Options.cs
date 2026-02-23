class Options
{
    [Option('t', "target-directory", Required = false, HelpText = "Directory containing package.json (default: cwd)")]
    public string? TargetDirectory { get; set; }

    [Option('s', "severity", Required = false, HelpText = "Severity threshold: critical, high, moderate, low (default: moderate)")]
    public string? Severity { get; set; }

    [Option('i', "ignore", Required = false, Separator = ',', HelpText = "Comma-separated CVE IDs to ignore")]
    public IEnumerable<string>? Ignore { get; set; }

    [Option('c', "config", Required = false, HelpText = "Config file path (default: audit-npm.config.json in target dir)")]
    public string? ConfigFile { get; set; }
}
