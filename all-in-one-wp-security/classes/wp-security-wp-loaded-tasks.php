<?php

/* * * This class handles tasks that need to be executed at wp-loaded time ** */
if(!defined('ABSPATH')){
    exit;//Exit if accessed directly
}

class AIOWPSecurity_WP_Loaded_Tasks {

    function __construct() {
        //Add tasks that need to be executed at wp-loaded time

        global $aio_wp_security;
        do_action( 'aiowps_wp_loaded_tasks_start', $this);

        //Handle the rename login page feature
        if ($aio_wp_security->configs->get_value('aiowps_enable_rename_login_page') == '1') {
            include_once(AIO_WP_SECURITY_PATH . '/classes/wp-security-process-renamed-login-page.php');
            $login_object = new AIOWPSecurity_Process_Renamed_Login_Page();
            AIOWPSecurity_Process_Renamed_Login_Page::renamed_login_init_tasks();
        }else{
            add_action('login_init', array(&$this, 'aiowps_login_init'));
        }

        //For site lockout feature (ie, maintenance mode). It needs to be checked after the rename login page
        if ($aio_wp_security->configs->get_value('aiowps_site_lockout') == '1') {
            if (!is_user_logged_in()) {
                //now check if user trying to reach login pages
                if(!in_array($GLOBALS['pagenow'], array('wp-login.php'))){
                    self::site_lockout_tasks();
                }
            }else if(is_user_logged_in() && !current_user_can('manage_options') && !is_admin() && !in_array($GLOBALS['pagenow'], array('wp-login.php')) ){
                self::site_lockout_tasks();
            }
        }
        do_action( 'aiowps_wp_loaded_tasks_end', $this);

    }

    static function site_lockout_tasks() {
        $lockout_output = apply_filters('aiowps_site_lockout_output', '');
        if (empty($lockout_output)) {
            nocache_headers();
            header("HTTP/1.0 503 Service Unavailable");
            remove_action('wp_head', 'head_addons', 7);
            $template = apply_filters('aiowps_site_lockout_template_include', AIO_WP_SECURITY_PATH . '/other-includes/wp-security-visitor-lockout-page.php');
            include_once($template);
        } else {
            echo $lockout_output;
        }

        exit();
    }
    
    static function aiowps_login_init(){
        //if user is logged in and tries to access login page - redirect them to wp-admin
        //this will prevent issues such as the following:
        //https://wordpress.org/support/topic/already-logged-in-no-captcha
        if(is_user_logged_in()){
            wp_redirect(admin_url());
        }
    }

}