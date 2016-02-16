<?php

class AIOWPSecurity_Utility
{
    function __construct()
    {
        //NOP
    }

    static function get_current_page_url()
    {
        $pageURL = 'http';
        if (isset($_SERVER["HTTPS"]) && $_SERVER["HTTPS"] == "on") {
            $pageURL .= "s";
        }
        $pageURL .= "://";
        if ($_SERVER["SERVER_PORT"] != "80") {
            $pageURL .= $_SERVER["SERVER_NAME"] . ":" . $_SERVER["SERVER_PORT"] . $_SERVER["REQUEST_URI"];
        } else {
            $pageURL .= $_SERVER["SERVER_NAME"] . $_SERVER["REQUEST_URI"];
        }
        return $pageURL;
    }

    static function redirect_to_url($url, $delay = '0', $exit = '1')
    {
        if (empty($url)) {
            echo "<br /><strong>Error! The URL value is empty. Please specify a correct URL value to redirect to!</strong>";
            exit;
        }
        if (!headers_sent()) {
            header('Location: ' . $url);
        } else {
            echo '<meta http-equiv="refresh" content="' . $delay . ';url=' . $url . '" />';
        }
        if ($exit == '1') {
            exit;
        }
    }

    static function get_logout_url_with_after_logout_url_value($after_logout_url)
    {
        return AIOWPSEC_WP_URL . '?aiowpsec_do_log_out=1&after_logout=' . $after_logout_url;
    }

    /*
     * Checks if a particular username exists in the WP Users table
     */
    static function check_user_exists($username)
    {
        global $wpdb;

        //if username is empty just return false
        if ($username == '') {
            return false;
        }

        //If multisite 
        if (AIOWPSecurity_Utility::is_multisite_install()) {
            $blog_id = get_current_blog_id();
            $admin_users = get_users('blog_id=' . $blog_id . 'orderby=login&role=administrator');
            $acct_name_exists = false;
            foreach ($admin_users as $user) {
                if ($user->user_login == $username) {
                    $acct_name_exists = true;
                    break;
                }
            }
            return $acct_name_exists;
        }

        //check users table
        $sanitized_username = sanitize_text_field($username);
        $sql_1 = $wpdb->prepare("SELECT user_login FROM $wpdb->users WHERE user_login=%s", $sanitized_username);
        $user_login = $wpdb->get_var($sql_1);
        if ($user_login == $sanitized_username) {
            $users_table_value_exists = true;
        } else {
            //make sure that the sanitized username is an integer before comparing it to the users table's ID column
            $sanitized_username_is_an_integer = (1 === preg_match('/^\d+$/', $sanitized_username)) ? true : false;
            if ($sanitized_username_is_an_integer) {
                $sql_2 = $wpdb->prepare("SELECT ID FROM $wpdb->users WHERE ID=%d", intval($sanitized_username));
                $userid = $wpdb->get_var($sql_2);
                $users_table_value_exists = ($userid == $sanitized_username) ? true : false;
            } else {
                $users_table_value_exists = false;
            }
        }
        return $users_table_value_exists;

    }

    /*
     * This function will return a list of user accounts which have login and nick names which are identical
     */
    static function check_identical_login_and_nick_names()
    {
        global $wpdb;
        $accounts_found = $wpdb->get_results("SELECT ID,user_login FROM `" . $wpdb->users . "` WHERE user_login<=>display_name;", ARRAY_A);
        return $accounts_found;
    }


    static function add_query_data_to_url($url, $name, $value)
    {
        if (strpos($url, '?') === false) {
            $url .= '?';
        } else {
            $url .= '&';
        }
        $url .= $name . '=' . urlencode($value);
        return $url;
    }


    /*
     * Generates a random alpha-numeric number
     */
    static function generate_alpha_numeric_random_string($string_length)
    {
        //Charecters present in table prefix
        $allowed_chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
        $string = '';
        //Generate random string
        for ($i = 0; $i < $string_length; $i++) {
            $string .= $allowed_chars[rand(0, strlen($allowed_chars) - 1)];
        }
        return $string;
    }


    /*
     * Generates a random number using a-z characters
     */
    static function generate_alpha_random_string($string_length)
    {
        //Charecters present in table prefix
        $allowed_chars = 'abcdefghijklmnopqrstuvwxyz';
        $string = '';
        //Generate random string
        for ($i = 0; $i < $string_length; $i++) {
            $string .= $allowed_chars[rand(0, strlen($allowed_chars) - 1)];
        }
        return $string;
    }

    static function set_cookie_value($cookie_name, $cookie_value, $expiry_seconds = 86400, $path = '/', $cookie_domain = '')
    {
        $expiry_time = time() + intval($expiry_seconds);
        if (empty($cookie_domain)) {
            $cookie_domain = COOKIE_DOMAIN;
        }
        setcookie($cookie_name, $cookie_value, $expiry_time, $path, $cookie_domain);
    }

    static function get_cookie_value($cookie_name)
    {
        if (isset($_COOKIE[$cookie_name])) {
            return $_COOKIE[$cookie_name];
        }
        return "";
    }

    static function is_multisite_install()
    {
        if (function_exists('is_multisite') && is_multisite()) {
            return true;
        } else {
            return false;
        }
    }

    //This is a general yellow box message for when we want to suppress a feature's config items because site is subsite of multi-site
    static function display_multisite_message()
    {
        echo '<div class="aio_yellow_box">';
        echo '<p>' . __('The plugin has detected that you are using a Multi-Site WordPress installation.', 'all-in-one-wp-security-and-firewall') . '</p>
              <p>' . __('This feature can only be configured by the "superadmin" on the main site.', 'all-in-one-wp-security-and-firewall') . '</p>';
        echo '</div>';
    }

    /*
     * Modifies the wp-config.php file to disable PHP file editing from the admin panel
     * This func will add the following code:
     * define('DISALLOW_FILE_EDIT', false);
     * 
     * NOTE: This function will firstly check if the above code already exists and it will modify the bool value, otherwise it will insert the code mentioned above
     */
    static function disable_file_edits()
    {
        global $aio_wp_security;
        $edit_file_config_entry_exists = false;

        //Config file path
        $config_file = AIOWPSecurity_Utility_File::get_wp_config_file_path();

        //Get wp-config.php file contents so we can check if the "DISALLOW_FILE_EDIT" variable already exists
        $config_contents = file($config_file);

        foreach ($config_contents as $line_num => $line) {
            if (strpos($line, "'DISALLOW_FILE_EDIT', false")) {
                $config_contents[$line_num] = str_replace('false', 'true', $line);
                $edit_file_config_entry_exists = true;
                //$this->show_msg_updated(__('Settings Saved - The ability to edit PHP files via the admin the panel has been DISABLED.', 'all-in-one-wp-security-and-firewall'));
            } else if (strpos($line, "'DISALLOW_FILE_EDIT', true")) {
                $edit_file_config_entry_exists = true;
                //$this->show_msg_updated(__('Your system config file is already configured to disallow PHP file editing.', 'all-in-one-wp-security-and-firewall'));
                return true;

            }

            //For wp-config.php files originating from early WP versions we will remove the closing php tag
            if (strpos($line, "?>") !== false) {
                $config_contents[$line_num] = str_replace("?>", "", $line);
            }
        }

        if (!$edit_file_config_entry_exists) {
            //Construct the config code which we will insert into wp-config.php
            $new_snippet = '//Disable File Edits' . PHP_EOL;
            $new_snippet .= 'define(\'DISALLOW_FILE_EDIT\', true);';
            $config_contents[] = $new_snippet; //Append the new snippet to the end of the array
        }

        //Make a backup of the config file
        if (!AIOWPSecurity_Utility_File::backup_and_rename_wp_config($config_file)) {
            AIOWPSecurity_Admin_Menu::show_msg_error_st(__('Failed to make a backup of the wp-config.php file. This operation will not go ahead.', 'all-in-one-wp-security-and-firewall'));
            //$aio_wp_security->debug_logger->log_debug("Disable PHP File Edit - Failed to make a backup of the wp-config.php file.",4);
            return false;
        } else {
            //$this->show_msg_updated(__('A backup copy of your wp-config.php file was created successfully....', 'all-in-one-wp-security-and-firewall'));
        }

        //Now let's modify the wp-config.php file
        if (AIOWPSecurity_Utility_File::write_content_to_file($config_file, $config_contents)) {
            //$this->show_msg_updated(__('Settings Saved - Your system is now configured to not allow PHP file editing.', 'all-in-one-wp-security-and-firewall'));
            return true;
        } else {
            //$this->show_msg_error(__('Operation failed! Unable to modify wp-config.php file!', 'all-in-one-wp-security-and-firewall'));
            $aio_wp_security->debug_logger->log_debug("Disable PHP File Edit - Unable to modify wp-config.php", 4);
            return false;
        }
    }

    /*
     * Modifies the wp-config.php file to allow PHP file editing from the admin panel
     * This func will modify the following code by replacing "true" with "false":
     * define('DISALLOW_FILE_EDIT', true);
     */

    static function enable_file_edits()
    {
        global $aio_wp_security;
        $edit_file_config_entry_exists = false;

        //Config file path
        $config_file = AIOWPSecurity_Utility_File::get_wp_config_file_path();

        //Get wp-config.php file contents
        $config_contents = file($config_file);
        foreach ($config_contents as $line_num => $line) {
            if (strpos($line, "'DISALLOW_FILE_EDIT', true")) {
                $config_contents[$line_num] = str_replace('true', 'false', $line);
                $edit_file_config_entry_exists = true;
            } else if (strpos($line, "'DISALLOW_FILE_EDIT', false")) {
                $edit_file_config_entry_exists = true;
                //$this->show_msg_updated(__('Your system config file is already configured to allow PHP file editing.', 'all-in-one-wp-security-and-firewall'));
                return true;
            }
        }

        if (!$edit_file_config_entry_exists) {
            //if the DISALLOW_FILE_EDIT settings don't exist in wp-config.php then we don't need to do anything
            //$this->show_msg_updated(__('Your system config file is already configured to allow PHP file editing.', 'all-in-one-wp-security-and-firewall'));
            return true;
        } else {
            //Now let's modify the wp-config.php file
            if (AIOWPSecurity_Utility_File::write_content_to_file($config_file, $config_contents)) {
                //$this->show_msg_updated(__('Settings Saved - Your system is now configured to allow PHP file editing.', 'all-in-one-wp-security-and-firewall'));
                return true;
            } else {
                //$this->show_msg_error(__('Operation failed! Unable to modify wp-config.php file!', 'all-in-one-wp-security-and-firewall'));
                //$aio_wp_security->debug_logger->log_debug("Disable PHP File Edit - Unable to modify wp-config.php",4);
                return false;
            }
        }
    }


    /**
     * Inserts event logs to the database
     * For now we are using for 404 events but in future will expand for other events
     *
     * @param string $event_type : Event type, eg, 404 (see below for list of event types)
     * @param string $username (optional): username
     *
     * Event types: 404 (...add more as we expand this)
     * @param $event_type
     * @param string $username
     * @return bool
     */
    static function event_logger($event_type, $username = '')
    {
        global $wpdb, $aio_wp_security;

        //Some initialising
        $url = '';
        $ip_or_host = '';
        $referer_info = '';
        $event_data = '';

        $events_table_name = AIOWPSEC_TBL_EVENTS;

        $ip_or_host = AIOWPSecurity_Utility_IP::get_user_ip_address(); //Get the IP address of user
        $username = sanitize_user($username);
        $user = get_user_by('login', $username); //Returns WP_User object if exists
        if ($user) {
            //If valid user set variables for DB storage later on
            $user_id = (absint($user->ID) > 0) ? $user->ID : 0;
        } else {
            //If the login attempt was made using a non-existent user then let's set user_id to blank and record the attempted user login name for DB storage later on
            $user_id = 0;
        }

        if ($event_type == '404') {
            //if 404 event get some relevant data
            $url = isset($_SERVER['REQUEST_URI']) ? esc_attr($_SERVER['REQUEST_URI']) : '';
            $referer_info = isset($_SERVER['HTTP_REFERER']) ? esc_attr($_SERVER['HTTP_REFERER']) : '';
        }

        $data = array(
            'event_type' => $event_type,
            'username' => $username,
            'user_id' => $user_id,
            'event_date' => current_time('mysql'),
            'ip_or_host' => $ip_or_host,
            'referer_info' => $referer_info,
            'url' => $url,
            'event_data' => '',
        );

        $data = apply_filters( 'filter_event_logger_data', $data );
        //log to database
        $result = $wpdb->insert($events_table_name, $data);
        if ($result === FALSE) {
            $aio_wp_security->debug_logger->log_debug("event_logger: Error inserting record into " . $events_table_name, 4);//Log the highly unlikely event of DB error
            return false;
        }
        return true;
    }

    /**
     * Checks if IP address is locked
     *
     * @param string $ip : ip address
     * @returns TRUE if locked, FALSE otherwise
     *
     **/
    static function check_locked_ip($ip)
    {
        global $wpdb;
        $login_lockdown_table = AIOWPSEC_TBL_LOGIN_LOCKDOWN;
        $locked_ip = $wpdb->get_row("SELECT * FROM $login_lockdown_table " .
            "WHERE release_date > now() AND " .
            "failed_login_ip = '" . esc_sql($ip) . "'", ARRAY_A);
        if ($locked_ip != NULL) {
            return TRUE;
        } else {
            return FALSE;
        }
    }

    /**
     * Returns list of IP addresses locked out
     *
     * * @returns array of addresses or FALSE otherwise
     *
     **/
    static function get_locked_ips()
    {
        global $wpdb;
        $login_lockdown_table = AIOWPSEC_TBL_LOGIN_LOCKDOWN;
        $locked_ips = $wpdb->get_results("SELECT * FROM $login_lockdown_table " .
            "WHERE release_date > now()", ARRAY_A);
        if ($locked_ips != NULL) {
            return $locked_ips;
        } else {
            return FALSE;
        }
    }


    /*
     * Locks an IP address - Adds an entry to the aiowps_lockdowns table
     */
    static function lock_IP($ip, $lock_reason = '', $username = '')
    {
        global $wpdb, $aio_wp_security;
        $login_lockdown_table = AIOWPSEC_TBL_LOGIN_LOCKDOWN;
        $lockout_time_length = $aio_wp_security->configs->get_value('aiowps_lockout_time_length'); //TODO add a setting for this feature
        $username = sanitize_user($username);
        $user = get_user_by('login', $username); //Returns WP_User object if exists

        if (FALSE == $user) {
            // Not logged in.
            $username = '';
            $user_id = 0;
        } else {
            // Logged in.
            $username = sanitize_user($user->user_login);
            $user_id = $user->ID;
        }

        $ip_str = esc_sql($ip);
        $insert = "INSERT INTO " . $login_lockdown_table . " (user_id, user_login, lockdown_date, release_date, failed_login_IP, lock_reason) " .
            "VALUES ('" . $user_id . "', '" . $username . "', now(), date_add(now(), INTERVAL " .
            $lockout_time_length . " MINUTE), '" . $ip_str . "', '" . $lock_reason . "')";
        $result = $wpdb->query($insert);
        if ($result > 0) {
        } else if ($result === FALSE) {
            $aio_wp_security->debug_logger->log_debug("lock_IP: Error inserting record into " . $login_lockdown_table, 4);//Log the highly unlikely event of DB error
        }
    }

    /*
     * Returns an array of blog_ids for a multisite install
     * If site is not multisite returns empty array
     */
    static function get_blog_ids()
    {
        global $wpdb, $aio_wp_security;
        if (AIOWPSecurity_Utility::is_multisite_install()) {
            global $wpdb;
            $blog_ids = $wpdb->get_col("SELECT blog_id FROM " . $wpdb->prefix . "blogs");
        } else {
            $blog_ids = array();
        }
        return $blog_ids;
    }


    //This function will delete the oldest rows from a table which are over the max amount of rows specified 
    static function cleanup_table($table_name, $max_rows = '10000')
    {
        global $wpdb, $aio_wp_security;

        $num_rows = $wpdb->get_var("select count(*) from $table_name");
        $result = true;
        if ($num_rows > $max_rows) {
            //if the table has more than max entries delete oldest rows

            $del_sql = "DELETE FROM $table_name
                        WHERE id <= (
                          SELECT id
                          FROM (
                            SELECT id
                            FROM $table_name
                            ORDER BY id DESC
                            LIMIT 1 OFFSET $max_rows
                          ) foo_tmp
                        )";

            $result = $wpdb->query($del_sql);
            if ($result === false) {
                $aio_wp_security->debug_logger->log_debug("AIOWPSecurity_Utility::cleanup_table failed for table name: " . $table_name, 4);
            }
        }
        return ($result === false) ? false : true;
    }

    //Gets server type. Returns -1 if server is not supported
    static function get_server_type()
    {
        //figure out what server they're using
        if (strstr(strtolower(filter_var($_SERVER['SERVER_SOFTWARE'], FILTER_SANITIZE_STRING)), 'apache')) {
            return 'apache';
        } else if (strstr(strtolower(filter_var($_SERVER['SERVER_SOFTWARE'], FILTER_SANITIZE_STRING)), 'nginx')) {
            return 'nginx';
        } else if (strstr(strtolower(filter_var($_SERVER['SERVER_SOFTWARE'], FILTER_SANITIZE_STRING)), 'litespeed')) {
            return 'litespeed';
        } else { //unsupported server
            return -1;
        }

    }

    /*
     * Checks if the string exists in the array key value of the provided array. If it doesn't exist, it returns the first key element from the valid values.
     */
    static function sanitize_value_by_array($to_check, $valid_values)
    {
        $keys = array_keys($valid_values);
        $keys = array_map('strtolower', $keys);
        if (in_array($to_check, $keys)) {
            return $to_check;
        }
        return reset($keys);//Return he first element from the valid values
    }

}
