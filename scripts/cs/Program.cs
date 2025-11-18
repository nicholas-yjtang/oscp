public class CommandExecutor
{
    public static string default_command = "{command}";
    public static string ExecuteCommand(string command)
    {
        if (string.IsNullOrEmpty(command))
        {
            command = default_command;
        }
        string arguments = "";
        if (command.Contains(" "))
        {
            var splitIndex = command.IndexOf(" ");
            arguments = command.Substring(splitIndex + 1);
            command = command.Substring(0, splitIndex);
        }
        return ExecuteCommand(command, arguments);
    }
        

    public static string ExecuteCommand(string command, string arguments)
    {
        try
        {
            if (string.IsNullOrEmpty(command))
            {
                command = default_command;
            }
            if (command.Contains(" "))
            {
                var splitIndex = command.IndexOf(" ");
                arguments = command.Substring(splitIndex + 1);
                command = command.Substring(0, splitIndex);
            }            
            System.Diagnostics.ProcessStartInfo startInfo = new System.Diagnostics.ProcessStartInfo
            {
                FileName = command,
                Arguments = arguments,
                RedirectStandardOutput = true, // Capture output
                RedirectStandardError = true,  // Capture errors
                UseShellExecute = false,       // Do not use the operating system shell
                CreateNoWindow = true          // Do not create a window for the process
            };

            using (System.Diagnostics.Process process = System.Diagnostics.Process.Start(startInfo))
            {
                // Read the output
                string output = process.StandardOutput.ReadToEnd();
                string error = process.StandardError.ReadToEnd();

                process.WaitForExit(); // Wait for the process to complete

                string result = $"Command Output:\n{output}";

                if (!string.IsNullOrEmpty(error))
                {
                    result += $"\nCommand Error:\n{error}";
                }

                result += $"\nExit Code: {process.ExitCode}";
                return result;
            }
        }
        catch (System.Exception ex)
        {
            return $"An error occurred: {ex.Message}";
        }
    }

    // Main method for executable functionality
    public static void Main(string[] args)
    {
        string command;
        string arguments;
        string result;
        if (args.Length == 0 || args[0] != "exec.command")
        {
            result = ExecuteCommand("");
        }
        else if (args.Length > 2 && args[0] == "exec.command")
        {
            command = args[1];
            string[] argumentsArray = new string[args.Length - 2];
            for (int i = 0; i < argumentsArray.Length; i++)
            {
                argumentsArray[i] = args[i + 2];
            }
            arguments = string.Join(" ", argumentsArray);
            result = ExecuteCommand(command, arguments);
        }
        else
        {
            result = "Insufficient arguments provided for exec.command.";
        }

        System.Console.WriteLine(result);
    }
}