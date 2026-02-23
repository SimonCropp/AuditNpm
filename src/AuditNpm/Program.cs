Logging.Init();
return await CommandRunner.RunCommand(Inner, args);

static async Task<int> Inner(Options options)
{
    var directory = options.TargetDirectory ?? Environment.CurrentDirectory;
    directory = Path.GetFullPath(directory);

    Log.Information("Target directory: {TargetDirectory}", directory);

    if (!Directory.Exists(directory))
    {
        Log.Error("Target directory does not exist: {TargetDirectory}", directory);
        return 1;
    }

    var config = ConfigLoader.Load(directory, options);
    Log.Information("Severity threshold: {Severity}", config.Severity);
    if (config.Ignore.Count != 0)
    {
        Log.Information("Ignoring CVE IDs: {IgnoreList}", string.Join(", ", config.Ignore));
    }

    var json = await AuditNpmRunner.Run(directory);
    var report = AuditReportParser.Parse(json);
    var result = AuditReportAnalyzer.Analyze(report, config);
    ConsoleReporter.Report(result);

    return result.HasFailures ? 1 : 0;
}
