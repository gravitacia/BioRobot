using BioRobot.Commands;

namespace BioRobot;

class Program
{
    static void Main(string[] args)
    {
        var commands = new Dictionary<string, ICommand>
        {
            { "scan", new ScanCommand() },
            { "strings", new StringsCommand() },
            { "pack", new PackCommand() },
            { "analyze", new AnalyzeCommand() }
        };

        if (args.Length == 0)
        {
            PrintUsage(commands);
            return;
        }

        string commandName = args[0].ToLower();

        if (commands.TryGetValue(commandName, out ICommand? command))
        {
            string[] commandArgs = args.Skip(1).ToArray();
            int result = command.Execute(commandArgs);
            Environment.Exit(result);
        }
        else
        {
            Console.WriteLine($"[-] Unknown command: {commandName}");
            PrintUsage(commands);
            Environment.Exit(1);
        }
    }

    static void PrintUsage(Dictionary<string, ICommand> commands)
    {
        Console.WriteLine("BioRobot - PE Binary Analyzer");
        Console.WriteLine("\nUsage:");
        Console.WriteLine("  biorobot <command> [arguments]");
        Console.WriteLine("\nCommands:");

        foreach (var cmd in commands.Values)
        {
            Console.WriteLine($"  {cmd.Name,-10} {cmd.Description}");
        }

        Console.WriteLine("\nExamples:");
        Console.WriteLine("  biorobot scan C:\\Windows\\System32\\notepad.exe");
    }
}