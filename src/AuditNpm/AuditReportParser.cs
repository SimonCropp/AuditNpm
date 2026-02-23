static class AuditReportParser
{
    public static AuditReport Parse(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        var vulnerabilities = new Dictionary<string, Vulnerability>();

        if (root.TryGetProperty("vulnerabilities", out var vulnsElement))
        {
            foreach (var prop in vulnsElement.EnumerateObject())
            {
                var vuln = ParseVulnerability(prop.Name, prop.Value);
                vulnerabilities[prop.Name] = vuln;
            }
        }

        var metadata = ParseMetadata(root);

        return new(vulnerabilities, metadata);
    }

    static Vulnerability ParseVulnerability(string name, JsonElement element)
    {
        var severity = element.GetProperty("severity").GetString() ?? "info";
        var isDirect = element.GetProperty("isDirect").GetBoolean();
        var range = element.GetProperty("range").GetString() ?? "";

        var advisories = new List<Advisory>();
        var viaElement = element.GetProperty("via");

        foreach (var via in viaElement.EnumerateArray())
        {
            if (via.ValueKind == JsonValueKind.Object)
            {
                var advisory = ParseAdvisory(via);
                advisories.Add(advisory);
            }
            // strings are transitive references to other packages - skip them
        }

        var effects = new List<string>();
        if (element.TryGetProperty("effects", out var effectsElement))
        {
            foreach (var effect in effectsElement.EnumerateArray())
            {
                var effectName = effect.GetString();
                if (effectName != null)
                {
                    effects.Add(effectName);
                }
            }
        }

        bool? fixAvailable = null;
        if (element.TryGetProperty("fixAvailable", out var fixElement))
        {
            if (fixElement.ValueKind == JsonValueKind.True)
            {
                fixAvailable = true;
            }
            else if (fixElement.ValueKind == JsonValueKind.False)
            {
                fixAvailable = false;
            }
            else if (fixElement.ValueKind == JsonValueKind.Object)
            {
                // fixAvailable is an object when it describes a semver-major fix
                fixAvailable = true;
            }
        }

        return new(name, severity, isDirect, advisories, effects, range, fixAvailable);
    }

    static Advisory ParseAdvisory(JsonElement element)
    {
        var title = element.GetProperty("title").GetString() ?? "";
        var url = element.GetProperty("url").GetString() ?? "";
        var severity = element.GetProperty("severity").GetString() ?? "info";
        var range = element.GetProperty("range").GetString() ?? "";

        var ghsaId = ExtractGhsaId(element, url);
        var cveIds = ExtractCveIds(element);

        return new(ghsaId, cveIds, title, url, severity, range);
    }

    static string ExtractGhsaId(JsonElement element, string url)
    {
        // Try github_advisory_id field first (npm v9+)
        if (element.TryGetProperty("github_advisory_id", out var ghsaElement))
        {
            var id = ghsaElement.GetString();
            if (!string.IsNullOrEmpty(id))
            {
                return id;
            }
        }

        // Fallback: parse GHSA ID from URL like https://github.com/advisories/GHSA-xxxx-xxxx-xxxx
        if (!string.IsNullOrEmpty(url))
        {
            var lastSlash = url.LastIndexOf('/');
            if (lastSlash >= 0)
            {
                var segment = url[(lastSlash + 1)..];
                if (segment.StartsWith("GHSA-", StringComparison.Ordinal))
                {
                    return segment;
                }
            }
        }

        return "";
    }

    static List<string> ExtractCveIds(JsonElement element)
    {
        var cveIds = new List<string>();

        if (element.TryGetProperty("cves", out var cvesElement) &&
            cvesElement.ValueKind == JsonValueKind.Array)
        {
            foreach (var cve in cvesElement.EnumerateArray())
            {
                var id = cve.GetString();
                if (!string.IsNullOrEmpty(id))
                {
                    cveIds.Add(id);
                }
            }
        }

        return cveIds;
    }

    static VulnerabilityMetadata ParseMetadata(JsonElement root)
    {
        var total = 0;
        var severityCounts = new Dictionary<string, int>();

        if (root.TryGetProperty("metadata", out var metadataElement) &&
            metadataElement.TryGetProperty("vulnerabilities", out var vulnCounts))
        {
            foreach (var prop in vulnCounts.EnumerateObject())
            {
                var count = prop.Value.GetInt32();
                severityCounts[prop.Name] = count;
                if (prop.Name != "total")
                {
                    total += count;
                }
            }

            if (severityCounts.TryGetValue("total", out var reportedTotal))
            {
                total = reportedTotal;
                severityCounts.Remove("total");
            }
        }

        return new(total, severityCounts);
    }
}
