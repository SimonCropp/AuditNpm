static class AuditNpmRunner
{
    internal static ProcessStartInfo CreateStartInfo(string arguments)
    {
        var startInfo = new ProcessStartInfo
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            startInfo.FileName = "cmd.exe";
            startInfo.Arguments = $"/c npm {arguments}";
        }
        else
        {
            startInfo.FileName = "npm";
            startInfo.Arguments = arguments;
        }

        return startInfo;
    }

    public static async Task<string> Run(string directory)
    {
        Log.Information("Running npm audit in {Directory}", directory);

        var startInfo = CreateStartInfo("audit --json");
        startInfo.WorkingDirectory = directory;

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("Failed to start npm process");

        var stdout = await process.StandardOutput.ReadToEndAsync();
        var stderr = await process.StandardError.ReadToEndAsync();

        await process.WaitForExitAsync();

        if (!string.IsNullOrEmpty(stderr))
        {
            Log.Debug("npm audit stderr: {StdErr}", stderr);
        }

        // npm exits non-zero when vulnerabilities exist - that's expected, not an error
        // Only empty stdout is an error
        if (string.IsNullOrWhiteSpace(stdout))
        {
            throw new InvalidOperationException(
                $"npm audit produced no output. Exit code: {process.ExitCode}. stderr: {stderr}");
        }

        Log.Information("npm audit completed with exit code {ExitCode}", process.ExitCode);

        return stdout;
    }
}
