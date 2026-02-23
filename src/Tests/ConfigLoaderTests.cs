namespace testing;

class ConfigLoaderTests
{
    [Test]
    public async Task NoConfigFile_ReturnsDefaults()
    {
        var dir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(dir);

        try
        {
            var options = new Options();
            var config = ConfigLoader.Load(dir, options);

            await Assert.That(config.Severity).IsEqualTo("moderate");
            await Assert.That(config.Ignore).IsEmpty();
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Test]
    public async Task ConfigFile_LoadsSeverityAndIgnore()
    {
        var dir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(dir);

        try
        {
            var configContent = """
                {
                  "severity": "high",
                  "ignore": ["CVE-2021-23337"]
                }
                """;
            File.WriteAllText(Path.Combine(dir, "audit-npm.config.json"), configContent);

            var options = new Options();
            var config = ConfigLoader.Load(dir, options);

            await Assert.That(config.Severity).IsEqualTo("high");
            await Assert.That(config.Ignore).Count().IsEqualTo(1);
            await Assert.That(config.Ignore).Contains("CVE-2021-23337");
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Test]
    public async Task CliSeverity_OverridesConfig()
    {
        var dir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(dir);

        try
        {
            var configContent = """
                {
                  "severity": "high"
                }
                """;
            File.WriteAllText(Path.Combine(dir, "audit-npm.config.json"), configContent);

            var options = new Options { Severity = "critical" };
            var config = ConfigLoader.Load(dir, options);

            await Assert.That(config.Severity).IsEqualTo("critical");
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Test]
    public async Task CliIgnore_IsAdditiveWithConfig()
    {
        var dir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(dir);

        try
        {
            var configContent = """
                {
                  "ignore": ["CVE-2021-23337"]
                }
                """;
            File.WriteAllText(Path.Combine(dir, "audit-npm.config.json"), configContent);

            var options = new Options { Ignore = ["CVE-2024-29041"] };
            var config = ConfigLoader.Load(dir, options);

            await Assert.That(config.Ignore).Count().IsEqualTo(2);
            await Assert.That(config.Ignore).Contains("CVE-2021-23337");
            await Assert.That(config.Ignore).Contains("CVE-2024-29041");
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Test]
    public async Task ConfigWithCommentsAndTrailingCommas_Parses()
    {
        var dir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(dir);

        try
        {
            var configContent = """
                {
                  // This is a comment
                  "severity": "low",
                  "ignore": [
                    "CVE-2021-23337",
                  ],
                }
                """;
            File.WriteAllText(Path.Combine(dir, "audit-npm.config.json"), configContent);

            var options = new Options();
            var config = ConfigLoader.Load(dir, options);

            await Assert.That(config.Severity).IsEqualTo("low");
            await Assert.That(config.Ignore).Contains("CVE-2021-23337");
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }
}
