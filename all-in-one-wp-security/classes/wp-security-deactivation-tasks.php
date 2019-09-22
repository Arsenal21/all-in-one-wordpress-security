<?php
if(!defined('ABSPATH')){
    exit;//Exit if accessed directly
}

include_once(dirname(__FILE__) . '/wp-security-configure-settings.php');//Allows activating via wp-cli

class AIOWPSecurity_Deactivation
{
    /**
     * Runs various deactivation tasks
     * Handles single and multi-site (NW activation) cases
     * @global type $wpdb
     * @global type $aio_wp_security
     * @param type $networkwide
     */
    static function run_deactivation_tasks($networkwide)
    {	
        global $wpdb;
        global $aio_wp_security;
        
        if (AIOWPSecurity_Utility::is_multisite_install()){
            delete_site_transient('users_online');
        }
        else{
            delete_transient('users_online');
        }
        
        if (AIOWPSecurity_Utility::is_multisite_install() && $networkwide) {
            // check if it is a network activation
            $blogids = $wpdb->get_col("SELECT blog_id FROM $wpdb->blogs");
            foreach ($blogids as $blog_id) {
                switch_to_blog($blog_id);
                //Let's first save the current aio_wp_security_configs options in a temp option
                update_option('aiowps_temp_configs', $aio_wp_security->configs->configs);
                
                AIOWPSecurity_Deactivation::clear_cron_events();
                restore_current_blog();
            }
        } else {
            //Let's first save the current aio_wp_security_configs options in a temp option
            update_option('aiowps_temp_configs', $aio_wp_security->configs->configs);
            
            AIOWPSecurity_Deactivation::clear_cron_events();
        }
        //Deactivate all firewall and other .htaccess rules
        AIOWPSecurity_Configure_Settings::turn_off_all_firewall_rules();
    }
    
    /**
     * Helper function which clears aiowps cron events
     */
    static function clear_cron_events() {
        wp_clear_scheduled_hook('aiowps_hourly_cron_event');
        wp_clear_scheduled_hook('aiowps_daily_cron_event');
    }
}
