static class CommandRunner
{
    public static Task<int> RunCommand(Invoke invoke, params string[] args)
    {
        if (args.Length == 1)
        {
            var firstArg = args[0];
            if (!firstArg.StartsWith('-'))
            {
                var options = new Options
                {
                    TargetDirectory = firstArg,
                };
                return invoke(options);
            }
        }

        return Parser.Default.ParseArguments<Options>(args)
            .MapResult(
                options =>
                {
                    options.TargetDirectory = FindTargetDirectory(options.TargetDirectory);
                    return invoke(options);
                },
                _ => Task.FromResult(1));
    }

    static string FindTargetDirectory(string? targetDirectory)
    {
        if (targetDirectory == null)
        {
            return Environment.CurrentDirectory;
        }

        return Path.GetFullPath(targetDirectory);
    }
}
