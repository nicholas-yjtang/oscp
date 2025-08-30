<?php
$password = "{php_password}";
$password_algorithm = {php_password_algorithm};
$hashed_password = password_hash($password, $password_algorithm);
echo $hashed_password;
?>