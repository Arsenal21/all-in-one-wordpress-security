<?php
if(!defined('ABSPATH')){
    exit;//Exit if accessed directly
}

class AIOWPSecurity_User_Login
{
    /**
     * This will store a URI query string key for passing messages to the login form
     * @var string
     */
    var $key_login_msg;
    function __construct()
    {
        $this->key_login_msg = 'aiowps_login_msg_id';
        // As a first authentication step, check if user's IP is locked.
        add_filter('authenticate', array($this, 'block_ip_if_locked'), 1, 1);
        // Check whether user needs to be manually approved after default WordPress authenticate hooks (with priority 20).
        add_filter('authenticate', array($this, 'check_manual_registration_approval'), 30, 1);
        // Check login captcha
        add_filter('authenticate', array($this, 'check_captcha'), 30, 1);
        // As a last authentication step, perform post authentication steps
        add_filter('authenticate', array($this, 'post_authenticate'), 100, 3);
        add_action('aiowps_force_logout_check', array($this, 'aiowps_force_logout_action_handler'));
        add_action('clear_auth_cookie', array($this, 'wp_logout_action_handler'));
        add_filter('login_message', array($this, 'aiowps_login_message')); //WP filter to add or modify messages on the login page
    }
    /**
     * Terminate the execution via wp_die with 503 status code, if current
     * user's IP is currently locked.
     *
     * @global AIO_WP_Security $aio_wp_security
     * @param WP_Error|WP_User $user
     * @return WP_User
     */
    function block_ip_if_locked($user)
    {
        global $aio_wp_security;
        $user_locked = $this->check_locked_user();
        if ( $user_locked != NULL ) {
            $aio_wp_security->debug_logger->log_debug("Login attempt from blocked IP range - ".$user_locked['failed_login_ip'],2);
            // Allow the error message to be filtered.
            $error_msg = apply_filters( 'aiowps_ip_blocked_error_msg', __('<strong>ERROR</strong>: Access from your IP address has been blocked for security reasons. Please contact the administrator.', 'all-in-one-wp-security-and-firewall') );
            // If unlock requests are allowed, add the "Request Unlock" button to the message.
            if( $aio_wp_security->configs->get_value('aiowps_allow_unlock_requests') == '1' )
            {
                $error_msg .= $this->get_unlock_request_form();
            }
            wp_die($error_msg, __('Service Temporarily Unavailable', 'all-in-one-wp-security-and-firewall'), 503);
        } else {
            return $user;
	}
    }
    
    /**
     * Check login captcha (if enabled).
     * @global AIO_WP_Security $aio_wp_security
     * @param WP_Error|WP_User $user
     * @return WP_Error|WP_User
     */
    function check_captcha($user)
    {
        global $aio_wp_security;
        if ( is_wp_error($user) )
        {
            // Authentication has failed already at some earlier step.
            return $user;
        }
        if ( ! (isset($_POST['log']) && isset($_POST['pwd'])) )
        {
            // XML-RPC authentication (not via wp-login.php), nothing to do here.
            return $user;
        }
        if ( $aio_wp_security->configs->get_value('aiowps_enable_login_captcha') != '1' )
        {
            // Captcha not enabled, nothing to do here.
            return $user;
        }
        $captcha_error = new WP_Error('authentication_failed', __('<strong>ERROR</strong>: Your answer was incorrect - please try again.', 'all-in-one-wp-security-and-firewall'));
        $captcha_answer = filter_input(INPUT_POST, 'aiowps-captcha-answer', FILTER_VALIDATE_INT);
        if ( is_null($captcha_answer) || ($captcha_answer === false) )
        {
            // null - no post data, false - not an integer
            return $captcha_error;
        }
        $captcha_temp_string = filter_input(INPUT_POST, 'aiowps-captcha-temp-string', FILTER_SANITIZE_STRING);
        if ( is_null($captcha_temp_string) )
        {
            return $captcha_error;
        }
        $captcha_secret_string = $aio_wp_security->configs->get_value('aiowps_captcha_secret_key');
        $submitted_encoded_string = base64_encode($captcha_temp_string.$captcha_secret_string.$captcha_answer);
        $trans_handle = sanitize_text_field(filter_input(INPUT_POST, 'aiowps-captcha-string-info', FILTER_SANITIZE_STRING));
        $captcha_string_info_trans = (AIOWPSecurity_Utility::is_multisite_install() ? get_site_transient('aiowps_captcha_string_info_'.$trans_handle) : get_transient('aiowps_captcha_string_info_'.$trans_handle));
        if ( $submitted_encoded_string !== $captcha_string_info_trans )
        {
            return $captcha_error;
        }
        return $user;
    }
    /**
     * Check, whether $user needs to be manually approved by site admin yet.
     * @global AIO_WP_Security $aio_wp_security
     * @param WP_Error|WP_User $user
     * @param string $username
     * @param string $password
     * @return WP_Error|WP_User
     */
    function check_manual_registration_approval($user)
    {
        global $aio_wp_security;
        if ( !($user instanceof WP_User) ) {
            // Not a WP_User - nothing to do here.
            return $user;
        }
        //Check if auto pending new account status feature is enabled
        if ($aio_wp_security->configs->get_value('aiowps_enable_manual_registration_approval') == '1')
        {
            $aiowps_account_status = get_user_meta($user->ID, 'aiowps_account_status', TRUE);
            if ($aiowps_account_status == 'pending') {
                // Account needs to be activated yet
                return new WP_Error('account_pending', __('<strong>ACCOUNT PENDING</strong>: Your account is currently not active. An administrator needs to activate your account before you can login.', 'all-in-one-wp-security-and-firewall'));
            }
        }
        return $user;
    }
    /**
     * Handle post authentication steps (in case of failed login):
     * - increment number of failed logins for $username
     * - (optionally) lock the user
     * - (optionally) display a generic error message
     * @global AIO_WP_Security $aio_wp_security
     * @param WP_Error|WP_User $user
     * @param string $username
     * @param string $password
     * @return WP_Error|WP_User
     */
    function post_authenticate($user, $username, $password)
    {
        global $aio_wp_security;
        if ( !is_wp_error($user) ) {
            // Authentication has been successful, there's nothing to do here.
            return $user;
        }
        if ( empty($username) || empty($password) ) {
            // Neither log nor block login attempts with empty username or password.
            return $user;
        }
        if ( $user->get_error_code() === 'account_pending' ) {
            // Neither log nor block users attempting to log in before their registration is approved.
            return $user;
        }
        // Login failed for non-trivial reason
        $this->increment_failed_logins($username);
        if ( $aio_wp_security->configs->get_value('aiowps_enable_login_lockdown') == '1' )
        {
            $is_whitelisted = false;
            //check if lockdown whitelist enabled
            if ( $aio_wp_security->configs->get_value('aiowps_lockdown_enable_whitelisting') == '1' ){
                $ip = AIOWPSecurity_Utility_IP::get_user_ip_address(); //Get the IP address of user
                $whitelisted_ips = $aio_wp_security->configs->get_value('aiowps_lockdown_allowed_ip_addresses');
                $is_whitelisted = AIOWPSecurity_Utility_IP::is_ip_whitelisted($ip, $whitelisted_ips);
            }
            
            if($is_whitelisted === false){
                // Too many failed logins from user's IP?
                $login_attempts_permitted = absint($aio_wp_security->configs->get_value('aiowps_max_login_attempts'));
                $too_many_failed_logins = $login_attempts_permitted <= $this->get_login_fail_count();
                // Is an invalid username or email the reason for login error?
                $invalid_username = ($user->get_error_code() === 'invalid_username' || $user->get_error_code() == 'invalid_email');
                // Should an invalid username be immediately locked?
                $invalid_username_lockdown = $aio_wp_security->configs->get_value('aiowps_enable_invalid_username_lockdown') == '1';
                $lock_invalid_username = $invalid_username && $invalid_username_lockdown;
                // Should an invalid username be blocked as per blacklist?
                $instant_lockout_users_list = $aio_wp_security->configs->get_value('aiowps_instantly_lockout_specific_usernames');
                if ( !is_array($instant_lockout_users_list) ) {
                    $instant_lockout_users_list = array();
                }
                $username_blacklisted = $invalid_username && in_array($username, $instant_lockout_users_list);
                if ( $too_many_failed_logins || $lock_invalid_username || $username_blacklisted )
                {
                    $this->lock_the_user($username, 'login_fail');
                }
            }
        }
        
        if ( $aio_wp_security->configs->get_value('aiowps_set_generic_login_msg') == '1' )
        {
            // Return generic error message if configured
            return new WP_Error('authentication_failed', __('<strong>ERROR</strong>: Invalid login credentials.', 'all-in-one-wp-security-and-firewall'));
        }
        return $user;
    }
    /*
     * This function queries the aiowps_login_lockdown table.
     * If the release_date has not expired AND the current visitor IP addr matches
     * it will return a record
     */
    function check_locked_user()
    {
        global $wpdb;
        $login_lockdown_table = AIOWPSEC_TBL_LOGIN_LOCKDOWN;
        $ip = AIOWPSecurity_Utility_IP::get_user_ip_address(); //Get the IP address of user
        $ip_range = AIOWPSecurity_Utility_IP::get_sanitized_ip_range($ip); //Get the IP range of the current user
        if(empty($ip_range)) return false;
        $now = current_time( 'mysql' );
        $locked_user = $wpdb->get_row("SELECT * FROM $login_lockdown_table " .
                                        "WHERE release_date > '".$now."' AND " .
                                        "failed_login_ip LIKE '" . esc_sql($ip_range) . "%'", ARRAY_A);
        return $locked_user;
    }
    /*
     * This function queries the aiowps_failed_logins table and returns the number of failures for current IP range within allowed failure period
     */
    function get_login_fail_count()
    {
        global $wpdb, $aio_wp_security;
        $failed_logins_table = AIOWPSEC_TBL_FAILED_LOGINS;
        $login_retry_interval = $aio_wp_security->configs->get_value('aiowps_retry_time_period');
        $ip = AIOWPSecurity_Utility_IP::get_user_ip_address(); //Get the IP address of user
        $ip_range = AIOWPSecurity_Utility_IP::get_sanitized_ip_range($ip); //Get the IP range of the current user
        if(empty($ip_range)) return false;
        $login_failures = $wpdb->get_var("SELECT COUNT(ID) FROM $failed_logins_table " . 
                                "WHERE failed_login_date + INTERVAL " .
                                $login_retry_interval . " MINUTE > now() AND " . 
                                "login_attempt_ip LIKE '" . esc_sql($ip_range) . "%'");
        return $login_failures;
    }
    /**
     * Adds an entry to the `aiowps_login_lockdown` table.
     * @param string $username User's username or email
     * @param string $lock_reason
     */
    function lock_the_user($username, $lock_reason='login_fail')
    {
        global $wpdb, $aio_wp_security;
        $login_lockdown_table = AIOWPSEC_TBL_LOGIN_LOCKDOWN;
        $lockout_time_length = $aio_wp_security->configs->get_value('aiowps_lockout_time_length');
        $ip = AIOWPSecurity_Utility_IP::get_user_ip_address(); //Get the IP address of user
        $ip_range = AIOWPSecurity_Utility_IP::get_sanitized_ip_range($ip); //Get the IP range of the current user
        if(empty($ip_range)) return;
        $user = is_email($username) ? get_user_by('email', $username) : get_user_by('login', $username); //Returns WP_User object if exists
        $ip_range = apply_filters('aiowps_before_lockdown', $ip_range);
        if ($user)
        {
            //If the login attempt was made using a valid user set variables for DB storage later on
            $user_id = $user->ID;
        } else {
            //If the login attempt was made using a non-existent user then let's set user_id to blank and record the attempted user login name for DB storage later on
            $user_id = 0;
        }
        $ip_range_str = esc_sql($ip_range).'.*';
        
        $lock_time = current_time( 'mysql' );
        $lock_minutes = $lockout_time_length;
        $newtimestamp = strtotime($lock_time.' + '.$lock_minutes.' minute');
        $release_time = date('Y-m-d H:i:s', $newtimestamp);
        $data = array('user_id' => $user_id, 'user_login' => $username, 'lockdown_date' => $lock_time, 'release_date' => $release_time, 'failed_login_IP' => $ip_range_str, 'lock_reason' => $lock_reason);
        $format = array('%d', '%s', '%s', '%s', '%s', '%s');
        $result = $wpdb->insert($login_lockdown_table, $data, $format);
        
        if ($result === FALSE)
        {
            $aio_wp_security->debug_logger->log_debug("Error inserting record into ".$login_lockdown_table,4);//Log the highly unlikely event of DB error
        }
        else
        {
            do_action('aiowps_lockdown_event', $ip_range, $username);
            $this->send_ip_lock_notification_email($username, $ip_range, $ip);
            $aio_wp_security->debug_logger->log_debug("The following IP address range has been locked out for exceeding the maximum login attempts: ".$ip_range,2);//Log the lockdown event
        }
    }
    /**
     * Adds an entry to the `aiowps_failed_logins` table.
     * @param string $username User's username or email
     */
    function increment_failed_logins($username)
    {
        global $wpdb, $aio_wp_security;
        $login_fails_table = AIOWPSEC_TBL_FAILED_LOGINS;
        $ip = AIOWPSecurity_Utility_IP::get_user_ip_address(); //Get the IP address of user
        if(empty($ip)) return;
        $user = is_email($username) ? get_user_by('email', $username) : get_user_by('login', $username); //Returns WP_User object if it exists
        if ($user)
        {
            //If the login attempt was made using a valid user set variables for DB storage later on
            $user_id = $user->ID;
        } else {
            //If the login attempt was made using a non-existent user then let's set user_id to blank and record the attempted user login name for DB storage later on
            $user_id = 0;
        }
        $ip_str = esc_sql($ip);
        $now = current_time( 'mysql' );
        $data = array('user_id' => $user_id, 'user_login' => $username, 'failed_login_date' => $now, 'login_attempt_ip' => $ip_str);
        $format = array('%d', '%s', '%s', '%s');
        $result = $wpdb->insert($login_fails_table, $data, $format);
        if ($result === FALSE)
        {
            $aio_wp_security->debug_logger->log_debug("Error inserting record into ".$login_fails_table,4);//Log the highly unlikely event of DB error
        }
    }
    /**
     * @param string $username User's username or email
     */
    function send_ip_lock_notification_email($username, $ip_range, $ip)
    {
        global $aio_wp_security;
        $email_notification_enabled = $aio_wp_security->configs->get_value('aiowps_enable_email_notify');
        if ($email_notification_enabled == 1)
        {
            $to_email_address = $aio_wp_security->configs->get_value('aiowps_email_address');
            $subject = '['.get_option('home').'] '. __('Site Lockout Notification','all-in-one-wp-security-and-firewall');
            $email_msg = __('A lockdown event has occurred due to too many failed login attempts or invalid username:','all-in-one-wp-security-and-firewall')."\n";
            $email_msg .= __('Username:', 'all-in-one-wp-security-and-firewall') . ' ' . $username . "\n";
            $email_msg .= __('IP Address:', 'all-in-one-wp-security-and-firewall') . ' ' . $ip . "\n\n";
            $email_msg .= __('IP Range:', 'all-in-one-wp-security-and-firewall') . ' ' . $ip_range . '.*' . "\n\n";
            $email_msg .= __("Log into your site's WordPress administration panel to see the duration of the lockout or to unlock the user.",'all-in-one-wp-security-and-firewall') . "\n";
            $site_title = get_bloginfo( 'name' );
            $from_name = empty($site_title)?'WordPress':$site_title;
            $email_header = 'From: '.$from_name.' <'.get_bloginfo('admin_email').'>' . "\r\n\\";
            $sendMail = wp_mail($to_email_address, $subject, $email_msg, $email_header);
            if(FALSE === $sendMail){
                $aio_wp_security->debug_logger->log_debug("Lockout notification email failed to send to ".$to_email_address." for IP ".$ip,4);
            }
        }
    }
    
    /**
     * Generates and returns an unlock request link which will be used to send to the user.
     * 
     * @global type $wpdb
     * @global AIO_WP_Security $aio_wp_security
     * @param type $ip_range
     * @return string or FALSE on failure
     */
    static function generate_unlock_request_link($ip_range)
    {
        //Get the locked user row from lockdown table
        global $wpdb, $aio_wp_security;
        $unlock_link = '';
        $lockdown_table_name = AIOWPSEC_TBL_LOGIN_LOCKDOWN;
        $secret_rand_key = (md5(uniqid(rand(), true)));
        $sql = $wpdb->prepare("UPDATE $lockdown_table_name SET unlock_key = '$secret_rand_key' WHERE release_date > now() AND failed_login_ip LIKE %s","%".esc_sql($ip_range)."%");
        $res = $wpdb->query($sql);
        if($res == NULL){
            $aio_wp_security->debug_logger->log_debug("No locked user found with IP range ".$ip_range,4);
            return false;
        }else{
            //Check if unlock requestor submitted from a woocommerce account login page
            if(isset($_POST['aiowps-woo-login'])){
                $date_time = current_time( 'mysql' );
                $data = array('date_time' => $date_time, 'meta_key1' => 'woo_unlock_request_key', 'meta_value1' => $secret_rand_key);
                $result = $wpdb->insert(AIOWPSEC_TBL_GLOBAL_META_DATA, $data);
                if ($result === false){
                    $aio_wp_security->debug_logger->log_debug("generate_unlock_request_link() - Error inserting woo_unlock_request_key to AIOWPSEC_TBL_GLOBAL_META_DATA table for secret key ".$secret_rand_key,4);
                }
            }
            $query_param = array('aiowps_auth_key'=>$secret_rand_key);
            $wp_site_url = AIOWPSEC_WP_URL;
            $unlock_link = esc_url(add_query_arg($query_param, $wp_site_url));
        }
        return $unlock_link;
    }
    /*
     * This function will process an unlock request when someone clicks on the special URL
     * It will check if the special random code matches that in lockdown table for the relevant user
     * If so, it will unlock the user
     */
    static function process_unlock_request($unlock_key)
    {
        global $wpdb, $aio_wp_security;
        $lockdown_table_name = AIOWPSEC_TBL_LOGIN_LOCKDOWN;
        
        $unlock_command = $wpdb->prepare( "UPDATE ".$lockdown_table_name." SET release_date = now() WHERE unlock_key = %s", $unlock_key );
        $result = $wpdb->query($unlock_command);
        if($result === false)
        {
            $aio_wp_security->debug_logger->log_debug("Error unlocking user with unlock_key ".$unlock_key,4);
        }
        else
        {
            //Now check if this unlock operation is for a woocommerce login
            $aiowps_global_meta_tbl_name = AIOWPSEC_TBL_GLOBAL_META_DATA;
            $sql = $wpdb->prepare("SELECT * FROM $aiowps_global_meta_tbl_name WHERE meta_key1=%s AND meta_value1=%s", 'woo_unlock_request_key', $unlock_key);
            $woo_result = $wpdb->get_row($sql, OBJECT);
            if(empty($woo_result)){
                $woo_unlock = false;
            }else{
                $woo_unlock = true;
            }
            if($aio_wp_security->configs->get_value('aiowps_enable_rename_login_page')=='1'){
                if (get_option('permalink_structure')){
                    $home_url = trailingslashit(home_url());
                }else{
                    $home_url = trailingslashit(home_url()) . '?';
                }
                if ( $woo_unlock ){
                    $login_url = wc_get_page_permalink( 'myaccount' ); //redirect to woo login page if applicable
                    //Now let's cleanup after ourselves and delete the woo-related row in the AIOWPSEC_TBL_GLOBAL_META_DATA table
                    $delete = $wpdb->delete( $aiowps_global_meta_tbl_name, array( 'meta_key1' => 'woo_unlock_request_key', 'meta_value1' => $unlock_key ) );
                    if($delete === false){
                        $aio_wp_security->debug_logger->log_debug("process_unlock_request(): Error deleting row from AIOWPSEC_TBL_GLOBAL_META_DATA for meta_key1=woo_unlock_request_key and meta_value1=".$unlock_key,4);
                    }
                }else{
                    $login_url = $home_url.$aio_wp_security->configs->get_value('aiowps_login_page_slug');
                }
                
                AIOWPSecurity_Utility::redirect_to_url($login_url);
            }else{
                AIOWPSecurity_Utility::redirect_to_url(wp_login_url());
            }
        }
    }
    
    /*
     * This function sends an unlock request email to a locked out user
     */
    static function send_unlock_request_email($email, $unlock_link)
    {
        global $aio_wp_security;
        $subject = '['.get_option('siteurl').'] '. __('Unlock Request Notification','all-in-one-wp-security-and-firewall');
        $email_msg
            = sprintf(__('You have requested for the account with email address %s to be unlocked. Please click the link below to unlock your account:','all-in-one-wp-security-and-firewall'), $email) . "\n"
            . sprintf(__('Unlock link: %s', 'all-in-one-wp-security-and-firewall'), $unlock_link) . "\n\n"
            . __('After clicking the above link you will be able to login to the WordPress administration panel.', 'all-in-one-wp-security-and-firewall') . "\n"
        ;
        $site_title = get_bloginfo( 'name' );
        $from_name = empty($site_title)?'WordPress':$site_title;
        $email_header = 'From: '.$from_name.' <'.get_bloginfo('admin_email').'>' . "\r\n\\";
        $sendMail = wp_mail($email, $subject, $email_msg, $email_header);
        if ( false === $sendMail ) {
            $aio_wp_security->debug_logger->log_debug("Unlock Request Notification email failed to send to " . $email, 4);
        }
    }
    
    /*
     * This function will check the settings and log the user after the configured time period
     */
    function aiowps_force_logout_action_handler()
    {
        global $aio_wp_security;
        //$aio_wp_security->debug_logger->log_debug("Force Logout - Checking if any user need to be logged out...");
        if($aio_wp_security->configs->get_value('aiowps_enable_forced_logout')=='1') //if this feature is enabled then do something
        {
            if(is_user_logged_in())
            {
                $current_user = wp_get_current_user();
                $user_id = $current_user->ID;
                $current_time = current_time( 'mysql' );
                $login_time = $this->get_wp_user_last_login_time($user_id);
                $diff = strtotime($current_time) - strtotime($login_time);
                $logout_time_interval_value = $aio_wp_security->configs->get_value('aiowps_logout_time_period');
                $logout_time_interval_val_seconds = $logout_time_interval_value * 60;
                if($diff > $logout_time_interval_val_seconds)
                {
                    $aio_wp_security->debug_logger->log_debug("Force Logout - This user logged in more than (".$logout_time_interval_value.") minutes ago. Doing a force log out for the user with username: ".$current_user->user_login);
                    $this->wp_logout_action_handler(); //this will register the logout time/date in the logout_date column
                    
                    $curr_page_url = AIOWPSecurity_Utility::get_current_page_url();
                    $after_logout_payload = array('redirect_to'=>$curr_page_url, 'msg'=>$this->key_login_msg.'=session_expired');
                    //Save some of the logout redirect data to a transient
                    AIOWPSecurity_Utility::is_multisite_install() ? set_site_transient('aiowps_logout_payload', $after_logout_payload, 30 * 60) : set_transient('aiowps_logout_payload', $after_logout_payload, 30 * 60);
                    $logout_url = AIOWPSEC_WP_URL.'?aiowpsec_do_log_out=1';
                    $logout_url = AIOWPSecurity_Utility::add_query_data_to_url($logout_url, 'al_additional_data', '1');
                    AIOWPSecurity_Utility::redirect_to_url($logout_url);
                }
            }
        }
    }
    
    function get_wp_user_last_login_time($user_id)
    {
        $last_login = get_user_meta($user_id, 'last_login_time', true);
        return $last_login;
    }
    static function wp_login_action_handler($user_login, $user='') 
    {
        global $wpdb, $aio_wp_security;
        $login_activity_table = AIOWPSEC_TBL_USER_LOGIN_ACTIVITY;
        
        if ($user == ''){
            //Try and get user object
            $user = get_user_by('login', $user_login); //This should return WP_User obj
            if (!$user){
                $aio_wp_security->debug_logger->log_debug("AIOWPSecurity_User_Login::wp_login_action_handler: Unable to get WP_User object for login ".$user_login,4);
                return;
            }
        }
        $login_date_time = current_time( 'mysql' );
        update_user_meta($user->ID, 'last_login_time', $login_date_time); //store last login time in meta table
        $curr_ip_address = AIOWPSecurity_Utility_IP::get_user_ip_address();
        $insert = "INSERT INTO " . $login_activity_table . " (user_id, user_login, login_date, login_ip) " .
                        "VALUES ('" . $user->ID . "', '" . $user_login . "', '" . $login_date_time . "', '" . $curr_ip_address . "')";
        $result = $wpdb->query($insert);
        if ($result === FALSE)
        {
            $aio_wp_security->debug_logger->log_debug("Error inserting record into ".$login_activity_table,4);//Log the highly unlikely event of DB error
        }
        
    }
    /**
     * The handler for logout events, ie, uses the WP "clear_auth_cookies" action.
     
     * Modifies the login activity record for the current user by registering the logout time/date in the logout_date column.
     * (NOTE: Because of the way we are doing a force logout, the "clear_auth_cookies" hook does not fire.
     * upon auto logout. The current workaround is to call this function directly from the aiowps_force_logout_action_handler() when 
     * an auto logout occurs due to the "force logout" feature). 
     *
     */
    function wp_logout_action_handler() 
    {
        global $wpdb, $aio_wp_security;
        $current_user = wp_get_current_user();
        $ip_addr = AIOWPSecurity_Utility_IP::get_user_ip_address();
        $user_id = $current_user->ID;
        //Clean up transients table
        $this->update_user_online_transient($user_id, $ip_addr);
        $login_activity_table = AIOWPSEC_TBL_USER_LOGIN_ACTIVITY;
        $logout_date_time = current_time( 'mysql' );
        $data = array('logout_date' => $logout_date_time);
        $where = array('user_id' => $user_id,
                        'login_ip' => $ip_addr,
                        'logout_date' => '0000-00-00 00:00:00');
        $result = $wpdb->update($login_activity_table, $data, $where);
        if ($result === FALSE)
        {
            $aio_wp_security->debug_logger->log_debug("Error inserting record into ".$login_activity_table,4);//Log the highly unlikely event of DB error
        }
    }
    /**
     * This will clean up the "users_online" transient entry for the current user. 
     *
     */
    function update_user_online_transient($user_id, $ip_addr) 
    {
        global $aio_wp_security;
        $logged_in_users = (AIOWPSecurity_Utility::is_multisite_install() ? get_site_transient('users_online') : get_transient('users_online'));
        //$logged_in_users = get_transient('users_online');
        if ($logged_in_users === false || $logged_in_users == NULL)
        {
            return;
        }
        $j = 0;
        foreach ($logged_in_users as $value)
        {
            if ($value['user_id'] == $user_id && strcmp($value['ip_address'], $ip_addr) == 0)
            {
                unset($logged_in_users[$j]);
                break;
            }
            $j++;
        }
        //Save the transient
        AIOWPSecurity_Utility::is_multisite_install() ? set_site_transient('users_online', $logged_in_users, 30 * 60) : set_transient('users_online', $logged_in_users, 30 * 60);
        //set_transient('users_online', $logged_in_users, 30 * 60); //Set transient with the data obtained above and also set the expiry to 30min
        return;
    }
    
    /**
     * The handler for the WP "login_message" filter
     * Adds custom messages to the other messages that appear above the login form.
     *
     * NOTE: This method is automatically called by WordPress for displaying
     * text above the login form.
     *
     * @param string $message  the output from earlier login_message filters
     * @return string
     *
     */
    function aiowps_login_message($message = '') 
    {
        global $aio_wp_security;
        $msg = '';
        if(isset($_GET[$this->key_login_msg]) && !empty($_GET[$this->key_login_msg]))
        {
            $logout_msg = strip_tags($_GET[$this->key_login_msg]);
        }
        if (!empty($logout_msg))
        {
            switch ($logout_msg) {
                    case 'session_expired':
                            $msg = sprintf(__('Your session has expired because it has been over %d minutes since your last login.', 'all-in-one-wp-security-and-firewall'), $aio_wp_security->configs->get_value('aiowps_logout_time_period'));
                            $msg .= ' ' . __('Please log back in to continue.', 'all-in-one-wp-security-and-firewall');
                            break;
                    case 'admin_user_changed':
                            $msg = __('You were logged out because you just changed the "admin" username.', 'all-in-one-wp-security-and-firewall');
                            $msg .= ' ' . __('Please log back in to continue.', 'all-in-one-wp-security-and-firewall');
                            break;
                    default:
            }
        }
        if (!empty($msg))
        {
            $msg = htmlspecialchars($msg, ENT_QUOTES, 'UTF-8');
            $message .= '<p class="login message">'. $msg . '</p>';
        }
        return $message;
    }
    /**
     * This function will generate an unlock request form to be inserted inside
     * error message when user gets locked out.
     *
     * @return string
     */
    function get_unlock_request_form()
    {
        global $aio_wp_security;
        $unlock_request_form = '';
        //Let's encode some hidden data and make a form
        $unlock_secret_string = $aio_wp_security->configs->get_value('aiowps_unlock_request_secret_key');
        $current_time = time();
        $enc_result = base64_encode($current_time.$unlock_secret_string);
        $unlock_request_form .= '<form method="post" action=""><div style="padding-bottom:10px;"><input type="hidden" name="aiowps-unlock-string-info" id="aiowps-unlock-string-info" value="'.$enc_result.'" />';
        $unlock_request_form .= '<input type="hidden" name="aiowps-unlock-temp-string" id="aiowps-unlock-temp-string" value="'.$current_time.'" />';
        if(isset($_POST['woocommerce-login-nonce'])){
            $unlock_request_form .= '<input type="hidden" name="aiowps-woo-login" id="aiowps-woo-login" value="1" />';
        }
        $unlock_request_form .= '<button type="submit" name="aiowps_unlock_request" id="aiowps_unlock_request" class="button">'.__('Request Unlock', 'all-in-one-wp-security-and-firewall').'</button></div></form>';
        return $unlock_request_form;
    }
}
