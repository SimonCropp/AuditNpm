class IntegrationTests
{
    static readonly bool npmAvailable = CheckNpmAvailable();

    static bool CheckNpmAvailable()
    {
        try
        {
            using var process = Process.Start(AuditNpmRunner.CreateStartInfo("--version"));

            if (process == null)
            {
                return false;
            }

            process.WaitForExit(10000);
            return process.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }

    static void RequireNpm()
    {
        if (!npmAvailable)
        {
            Skip.Test("npm is not installed");
        }
    }

    [Test]
    public async Task CleanProject_ExitCodeZero()
    {
        RequireNpm();

        using var temp = new TempDirectory();

        await File.WriteAllTextAsync(
            Path.Combine(temp, "package.json"),
            """
            {
              "name": "clean-test",
              "version": "1.0.0",
              "lockfileVersion": 3,
              "dependencies": {}
            }
            """);

        await File.WriteAllTextAsync(
            Path.Combine(temp, "package-lock.json"),
            """
            {
              "name": "clean-test",
              "version": "1.0.0",
              "lockfileVersion": 3,
              "requires": true,
              "packages": {
                "": {
                  "name": "clean-test",
                  "version": "1.0.0"
                }
              }
            }
            """);

        var json = await AuditNpmRunner.Run(temp);
        var report = AuditReportParser.Parse(json);
        var config = new AuditConfig("moderate", []);
        var result = AuditReportAnalyzer.Analyze(report, config);

        await Assert.That(result.HasFailures).IsFalse();
        await Assert.That(result.Reported).IsEmpty();
    }

    [Test]
    public async Task FullPipeline_WithConfigAndIgnore()
    {
        RequireNpm();

        using var temp = new TempDirectory();

        await File.WriteAllTextAsync(
            Path.Combine(temp, "package.json"),
            """
            {
              "name": "clean-test",
              "version": "1.0.0",
              "dependencies": {}
            }
            """);

        await File.WriteAllTextAsync(
            Path.Combine(temp, "package-lock.json"),
            """
            {
              "name": "clean-test",
              "version": "1.0.0",
              "lockfileVersion": 3,
              "requires": true,
              "packages": {
                "": {
                  "name": "clean-test",
                  "version": "1.0.0"
                }
              }
            }
            """);

        await File.WriteAllTextAsync(
            Path.Combine(temp, "audit-npm.config.json"),
            """
            {
              "severity": "low",
              "ignore": []
            }
            """);

        var options = new Options
        {
            TargetDirectory = temp
        };
        var config = ConfigLoader.Load(temp, options);

        await Assert.That(config.Severity).IsEqualTo("low");

        var json = await AuditNpmRunner.Run(temp);
        var report = AuditReportParser.Parse(json);
        var result = AuditReportAnalyzer.Analyze(report, config);

        await Assert.That(result.HasFailures).IsFalse();
    }
}
