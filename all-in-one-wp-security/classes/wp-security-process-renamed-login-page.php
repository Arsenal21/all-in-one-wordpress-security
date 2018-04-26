<?php
if(!defined('ABSPATH')){
    exit;//Exit if accessed directly
}

class AIOWPSecurity_Process_Renamed_Login_Page
{

    function __construct() 
    {
        add_action('login_init', array(&$this, 'aiowps_login_init'));
        add_filter('site_url', array(&$this, 'aiowps_site_url'), 10, 2);
        add_filter('network_site_url', array(&$this, 'aiowps_site_url'), 10, 2);
        add_filter('wp_redirect', array(&$this, 'aiowps_wp_redirect'), 10, 2);
        add_filter('register', array(&$this, 'register_link'));
        remove_action('template_redirect', 'wp_redirect_admin_locations', 1000); //To prevent redirect to login page when people type "login" at end of home URL
        
    }
    
    function aiowps_login_init() 
    {
        if (strpos($_SERVER['REQUEST_URI'], 'wp-login') !== false){
            $referer = wp_get_referer();
            if($referer && strpos($referer, 'wp-activate.php') !== false){
                $parsed_referer = parse_url($referer);
                if($parsed_referer && !empty($parsed_referer['query'])){
                    parse_str($parsed_referer['query'], $referer);
                    if (!empty($parsed_referer['key'])){
                        $result = wpmu_activate_signup($parsed_referer['key']); //MS site creation
                        if($result && is_wp_error($result) && ($result->get_error_code() === 'already_active' || $result->get_error_code() === 'blog_taken')){
                            $aiowps_new_login_url = AIOWPSecurity_Process_Renamed_Login_Page::new_login_url();
                            wp_safe_redirect($aiowps_new_login_url . (!empty($_SERVER['QUERY_STRING']) ? '?' . $_SERVER['QUERY_STRING'] : ''));
                            die;
                        }
                    }
                }                
            }
            AIOWPSecurity_Process_Renamed_Login_Page::aiowps_set_404();
        }

    }
    
    function aiowps_site_url($url, $path) 
    {
        return $this->aiowps_filter_wp_login_file($url);
    }

    function aiowps_wp_redirect($location, $status)
    {
        return $this->aiowps_filter_wp_login_file($location);
    }

    //Filter register link on the login page
    function register_link($registration_url)
    {
        return $this->aiowps_filter_wp_login_file($registration_url);
    }
    
    //Filter all login url strings on the login page
    function aiowps_filter_wp_login_file($url)
    {
        if (strpos($url, 'wp-login.php') !== false){
            $args = explode( '?', $url );
            if (isset($args[1])){
                if (strpos($args[1], 'action=postpass') !== FALSE){
                    return $url; //Don't reveal the secret URL in the post password action url 
                }
                parse_str($args[1], $args);
                $url = esc_url(add_query_arg($args, AIOWPSecurity_Process_Renamed_Login_Page::new_login_url()));
                $url = html_entity_decode($url);
            }else{
                $url = AIOWPSecurity_Process_Renamed_Login_Page::new_login_url();
            }
        }
        return $url;
    }

    static function renamed_login_init_tasks()
    {
        global $aio_wp_security;

        //The following will process the native wordpress post password protection form
        //Normally this is done by wp-login.php file but we cannot use that since the login page has been renamed 
        $action = isset($_GET['action'])?strip_tags($_GET['action']):'';
        if(isset($_POST['post_password']) && $action == 'postpass'){
            require_once ABSPATH . 'wp-includes/class-phpass.php';
            $hasher = new PasswordHash( 8, true );

            /**
             * Filter the life span of the post password cookie.
             *
             * By default, the cookie expires 10 days from creation. To turn this
             * into a session cookie, return 0.
             *
             * @since 3.7.0
             *
             * @param int $expires The expiry time, as passed to setcookie().
             */
            $expire = apply_filters( 'post_password_expires', time() + 10 * DAY_IN_SECONDS );
            setcookie( 'wp-postpass_' . COOKIEHASH, $hasher->HashPassword( wp_unslash( $_POST['post_password'] ) ), $expire, COOKIEPATH );

            wp_safe_redirect( wp_get_referer() );
            exit();
        }
        
        //case where someone attempting to reach wp-admin 
        if (is_admin() && !is_user_logged_in() && !defined('DOING_AJAX') && basename( $_SERVER["SCRIPT_FILENAME"] ) !== 'admin-post.php'){
            //Fix to prevent fatal error caused by some themes and Yoast SEO
            do_action('aiowps_before_wp_die_renamed_login');
            wp_die( __( 'Not available.', 'all-in-one-wp-security-and-firewall' ), 403 );
        }

        //case where someone attempting to reach wp-login
        if(isset($_SERVER['REQUEST_URI']) && strpos( $_SERVER['REQUEST_URI'], 'wp-login.php' ) && !is_user_logged_in()){
            //Check if the maintenance (lockout) mode is active - if so prevent access to site by not displaying 404 page!
            if($aio_wp_security->configs->get_value('aiowps_site_lockout') == '1'){
                AIOWPSecurity_WP_Loaded_Tasks::site_lockout_tasks();
            }else{
                AIOWPSecurity_Process_Renamed_Login_Page::aiowps_set_404();
            }
        }
        
        //case where someone attempting to reach the standard register or signup pages
        if(isset( $_SERVER['REQUEST_URI'] ) && strpos( $_SERVER['REQUEST_URI'], 'wp-register.php' ) ||
            isset( $_SERVER['REQUEST_URI'] ) && strpos( $_SERVER['REQUEST_URI'], 'wp-signup.php' )){
            //Check if the maintenance (lockout) mode is active - if so prevent access to site by not displaying 404 page!
            if($aio_wp_security->configs->get_value('aiowps_site_lockout') == '1'){
                AIOWPSecurity_WP_Loaded_Tasks::site_lockout_tasks();
            }else{
                AIOWPSecurity_Process_Renamed_Login_Page::aiowps_set_404();
            }
        }

        $parsed_url = parse_url($_SERVER['REQUEST_URI']);

        $login_slug = $aio_wp_security->configs->get_value('aiowps_login_page_slug');
        $home_url_with_slug = home_url($login_slug, 'relative');
        
        /*
         * Compatibility fix for WPML plugin
         */
        if (function_exists('icl_object_id') && strpos($home_url_with_slug,$login_slug)){
            $home_url_with_slug = home_url($login_slug);
            function qtranxf_init_language() {}
        }

        /*
         * *** Compatibility fix for qTranslate-X plugin ***
         * qTranslate-X plugin modifies the result for the following command by adding the protocol and host to the url path:
         * home_url($login_slug, 'relative');
         * Therefore we will remove the protocol and host for the following cases:
         * qTranslate-X is active AND the URL being accessed contains the secret slug
         */
        if (function_exists('qtranxf_init_language') && strpos($home_url_with_slug,$login_slug)){
            $parsed_home_url_with_slug = parse_url($home_url_with_slug);
            $home_url_with_slug = $parsed_home_url_with_slug['path']; //this will return just the path minus the protocol and host
        }

        if(untrailingslashit($parsed_url['path']) === $home_url_with_slug
                || (!get_option('permalink_structure') && isset($_GET[$login_slug]))){
            if(empty($action) && is_user_logged_in()){
                //if user is already logged in but tries to access the renamed login page, send them to the dashboard
                AIOWPSecurity_Utility::redirect_to_url(AIOWPSEC_WP_URL."/wp-admin");
            }else{
                status_header( 200 );
                require_once(AIO_WP_SECURITY_PATH . '/other-includes/wp-security-rename-login-feature.php' );
                die;
            }
        }        
    }
    
    static function new_login_url()
    {
        global $aio_wp_security;
        $login_slug = $aio_wp_security->configs->get_value('aiowps_login_page_slug');
        if(get_option('permalink_structure')){
            return trailingslashit(trailingslashit(home_url()) . $login_slug);
        }else{
            return trailingslashit(home_url()) . '?' . $login_slug;
        }
    }

    static function aiowps_set_404() 
    {
        global $wp_query;
        do_action('aiopws_before_set_404'); //This hook is for themes which produce a fatal error when the rename login feature is enabled and someone visits "wp-admin" slug directly

        status_header(404);
        $wp_query->set_404();
        if ((($template = get_404_template()) || ($template = get_index_template()))
            && ($template = apply_filters('template_include', $template))){
            include($template);
        }
        die;
    }
    
}