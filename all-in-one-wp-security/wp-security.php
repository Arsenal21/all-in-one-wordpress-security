<?php
/*
Plugin Name: All In One WP Security
Version: 4.4.8
Plugin URI: https://www.tipsandtricks-hq.com/wordpress-security-and-firewall-plugin
Author: Tips and Tricks HQ, Peter Petreski, Ruhul, Ivy
Author URI: https://www.tipsandtricks-hq.com/
Description: All round best WordPress security plugin!
Text Domain: all-in-one-wp-security-and-firewall
Domain Path: /languages
License: GPL3
*/

if(!defined('ABSPATH')){
    exit;//Exit if accessed directly
}

include_once('wp-security-core.php');
register_activation_hook(__FILE__,array('AIO_WP_Security','activate_handler'));//activation hook
register_deactivation_hook(__FILE__,array('AIO_WP_Security','deactivate_handler'));//deactivation hook

function aiowps_show_plugin_settings_link($links, $file)
{
    if ($file == plugin_basename(__FILE__)){
            $settings_link = '<a href="admin.php?page=aiowpsec_settings">Settings</a>';
            array_unshift($links, $settings_link);
    }
    return $links;
}
add_filter('plugin_action_links', 'aiowps_show_plugin_settings_link', 10, 2 );

function aiowps_ms_handle_new_site($new_site){
    global $wpdb;
    $plugin_basename = plugin_basename( __FILE__ );
    if (is_plugin_active_for_network($plugin_basename))
    {
        if(!class_exists('AIOWPSecurity_Installer')){
            include_once('classes/wp-security-installer.php');
        }
        $old_blog = $wpdb->blogid;
        switch_to_blog($new_site->blog_id);
        AIOWPSecurity_Installer::create_db_tables();
        switch_to_blog($old_blog);
    }


}
add_action('wp_insert_site', 'aiowps_ms_handle_new_site', 10, 1);
