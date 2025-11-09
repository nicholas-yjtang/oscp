const { exec } = require('child_process');

const command = '{command}';

exec(command, (error, stdout, stderr) => {
  if (error) {
    console.error(`Error executing command: ${error.message}`);
    return;
  }
  if (stderr) {
    console.error(`Command stderr: ${stderr}`);
  }
  console.log(`Command output:\n${stdout}`);
});