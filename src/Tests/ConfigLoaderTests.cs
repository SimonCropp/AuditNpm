class ConfigLoaderTests
{
    [Test]
    public Task NoConfigFile_ReturnsDefaults()
    {
        using var temp = new TempDirectory();

        var options = new Options();
        var config = ConfigLoader.Load(temp, options);

        return Verify(config);
    }

    [Test]
    public Task ConfigFile_LoadsSeverityAndIgnore()
    {
        using var temp = new TempDirectory();

        var configContent = """
            {
              "severity": "high",
              "ignore": ["CVE-2021-23337"]
            }
            """;
        File.WriteAllText(Path.Combine(temp, "audit-npm.config.json"), configContent);

        var options = new Options();
        var config = ConfigLoader.Load(temp, options);

        return Verify(config);
    }

    [Test]
    public Task CliSeverity_OverridesConfig()
    {
        using var temp = new TempDirectory();

        var configContent = """
            {
              "severity": "high"
            }
            """;
        File.WriteAllText(Path.Combine(temp, "audit-npm.config.json"), configContent);

        var options = new Options { Severity = "critical" };
        var config = ConfigLoader.Load(temp, options);

        return Verify(config);
    }

    [Test]
    public Task CliIgnore_IsAdditiveWithConfig()
    {
        using var temp = new TempDirectory();

        var configContent = """
            {
              "ignore": ["CVE-2021-23337"]
            }
            """;
        File.WriteAllText(Path.Combine(temp, "audit-npm.config.json"), configContent);

        var options = new Options { Ignore = ["CVE-2024-29041"] };
        var config = ConfigLoader.Load(temp, options);

        return Verify(config);
    }

    [Test]
    public Task IgnoreWithFutureUntil_IsIncluded()
    {
        using var temp = new TempDirectory();

        var configContent = """
            {
              "ignore": [
                {
                  "id": "CVE-2021-23337",
                  "until": "2025-06-01"
                }
              ]
            }
            """;
        File.WriteAllText(Path.Combine(temp, "audit-npm.config.json"), configContent);

        var options = new Options();
        var today = new Date(2025, 3, 15);
        var config = ConfigLoader.Load(temp, options, today);

        return Verify(config);
    }

    [Test]
    public Task IgnoreWithPastUntil_IsExcluded()
    {
        using var temp = new TempDirectory();

        var configContent = """
            {
              "ignore": [
                {
                  "id": "CVE-2021-23337",
                  "until": "2025-06-01"
                }
              ]
            }
            """;
        File.WriteAllText(Path.Combine(temp, "audit-npm.config.json"), configContent);

        var options = new Options();
        var today = new Date(2025, 7, 01);
        var config = ConfigLoader.Load(temp, options, today);

        return Verify(config);
    }

    [Test]
    public Task MixedStringAndObjectIgnores()
    {
        using var temp = new TempDirectory();

        var configContent = """
            {
              "ignore": [
                "CVE-2024-29041",
                {
                  "id": "CVE-2021-23337",
                  "until": "2025-06-01"
                },
                {
                  "id": "CVE-2020-12345",
                  "until": "2025-01-01"
                }
              ]
            }
            """;
        File.WriteAllText(Path.Combine(temp, "audit-npm.config.json"), configContent);

        var options = new Options();
        var today = new Date(2025, 3, 15);
        var config = ConfigLoader.Load(temp, options, today);

        return Verify(config);
    }

    [Test]
    public Task ConfigWithCommentsAndTrailingCommas_Parses()
    {
        using var temp = new TempDirectory();

        var configContent = """
            {
              // This is a comment
              "severity": "low",
              "ignore": [
                "CVE-2021-23337",
              ],
            }
            """;
        File.WriteAllText(Path.Combine(temp, "audit-npm.config.json"), configContent);

        var options = new Options();
        var config = ConfigLoader.Load(temp, options);

        return Verify(config);
    }
}
