<?php
if(!defined('ABSPATH')){
    exit;//Exit if accessed directly
}

include_once(dirname(__FILE__) . '/wp-security-configure-settings.php');//Allows activating via wp-cli

class AIOWPSecurity_Deactivation
{
    static function run_deactivation_tasks()
    {	
        global $wpdb;
        global $aio_wp_security;
        
        //Let's first save the current aio_wp_security_configs options in a temp option
        update_option('aiowps_temp_configs', $aio_wp_security->configs->configs);
        
        //Deactivate all firewall and other .htaccess rules
        AIOWPSecurity_Configure_Settings::turn_off_all_firewall_rules();
    }
}
