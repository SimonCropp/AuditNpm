static class ConfigLoader
{
    const string defaultConfigFileName = "audit-npm.config.json";

    static readonly JsonDocumentOptions jsonOptions = new()
    {
        CommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
    };

    public static AuditConfig Load(string directory, Options options)
    {
        var severity = "moderate";
        var ignore = new HashSet<string>(StringComparer.Ordinal);

        var configPath = !string.IsNullOrEmpty(options.ConfigFile)
            ? options.ConfigFile
            : Path.Combine(directory, defaultConfigFileName);

        if (File.Exists(configPath))
        {
            Log.Information("Loading config from {ConfigPath}", configPath);
            var json = File.ReadAllText(configPath);
            using var doc = JsonDocument.Parse(json, jsonOptions);
            var root = doc.RootElement;

            if (root.TryGetProperty("severity", out var severityElement))
            {
                var configSeverity = severityElement.GetString();
                if (!string.IsNullOrEmpty(configSeverity))
                {
                    severity = configSeverity;
                }
            }

            if (root.TryGetProperty("ignore", out var ignoreElement))
            {
                foreach (var item in ignoreElement.EnumerateArray())
                {
                    var id = item.GetString();
                    if (!string.IsNullOrEmpty(id))
                    {
                        ignore.Add(id);
                    }
                }
            }
        }

        // CLI --severity overrides config file
        if (!string.IsNullOrEmpty(options.Severity))
        {
            severity = options.Severity;
        }

        // CLI --ignore is additive with config file
        if (options.Ignore != null)
        {
            foreach (var id in options.Ignore)
            {
                if (!string.IsNullOrEmpty(id))
                {
                    ignore.Add(id);
                }
            }
        }

        return new(severity, ignore);
    }
}
