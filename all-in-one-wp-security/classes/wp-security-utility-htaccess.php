<?php

class AIOWPSecurity_Utility_Htaccess
{
    //The following variables will store the comment markers for each of features added to the .htacces file
    //This will make it easy to locate the blocks of code for deletion if someone disables a feature
    public static $ip_blacklist_marker_start = '#AIOWPS_IP_BLACKLIST_START';
    public static $ip_blacklist_marker_end = '#AIOWPS_IP_BLACKLIST_END';

    public static $prevent_wp_file_access_marker_start = '#AIOWPS_BLOCK_WP_FILE_ACCESS_START';
    public static $prevent_wp_file_access_marker_end = '#AIOWPS_BLOCK_WP_FILE_ACCESS_END';

    public static $basic_htaccess_rules_marker_start = '#AIOWPS_BASIC_HTACCESS_RULES_START';
    public static $basic_htaccess_rules_marker_end = '#AIOWPS_BASIC_HTACCESS_RULES_END';

    public static $pingback_htaccess_rules_marker_start = '#AIOWPS_PINGBACK_HTACCESS_RULES_START';
    public static $pingback_htaccess_rules_marker_end = '#AIOWPS_PINGBACK_HTACCESS_RULES_END';

    public static $debug_log_block_htaccess_rules_marker_start = '#AIOWPS_DEBUG_LOG_BLOCK_HTACCESS_RULES_START';
    public static $debug_log_block_htaccess_rules_marker_end = '#AIOWPS_DEBUG_LOG_BLOCK_HTACCESS_RULES_END';

    public static $user_agent_blacklist_marker_start = '#AIOWPS_USER_AGENT_BLACKLIST_START';
    public static $user_agent_blacklist_marker_end = '#AIOWPS_USER_AGENT_BLACKLIST_END';

    public static $enable_brute_force_attack_prevention_marker_start = '#AIOWPS_ENABLE_BRUTE_FORCE_PREVENTION_START';
    public static $enable_brute_force_attack_prevention_marker_end = '#AIOWPS_ENABLE_BRUTE_FORCE_PREVENTION_END';

    public static $disable_index_views_marker_start = '#AIOWPS_DISABLE_INDEX_VIEWS_START';
    public static $disable_index_views_marker_end = '#AIOWPS_DISABLE_INDEX_VIEWS_END';

    public static $disable_trace_track_marker_start = '#AIOWPS_DISABLE_TRACE_TRACK_START';
    public static $disable_trace_track_marker_end = '#AIOWPS_DISABLE_TRACE_TRACK_END';

    public static $forbid_proxy_comments_marker_start = '#AIOWPS_FORBID_PROXY_COMMENTS_START';
    public static $forbid_proxy_comments_marker_end = '#AIOWPS_FORBID_PROXY_COMMENTS_END';

    public static $deny_bad_query_strings_marker_start = '#AIOWPS_DENY_BAD_QUERY_STRINGS_START';
    public static $deny_bad_query_strings_marker_end = '#AIOWPS_DENY_BAD_QUERY_STRINGS_END';

    public static $advanced_char_string_filter_marker_start = '#AIOWPS_ADVANCED_CHAR_STRING_FILTER_START';
    public static $advanced_char_string_filter_marker_end = '#AIOWPS_ADVANCED_CHAR_STRING_FILTER_END';

    public static $five_g_blacklist_marker_start = '#AIOWPS_FIVE_G_BLACKLIST_START';
    public static $five_g_blacklist_marker_end = '#AIOWPS_FIVE_G_BLACKLIST_END';

    public static $six_g_blacklist_marker_start = '#AIOWPS_SIX_G_BLACKLIST_START';
    public static $six_g_blacklist_marker_end = '#AIOWPS_SIX_G_BLACKLIST_END';

    public static $block_spambots_marker_start = '#AIOWPS_BLOCK_SPAMBOTS_START';
    public static $block_spambots_marker_end = '#AIOWPS_BLOCK_SPAMBOTS_END';

    public static $enable_login_whitelist_marker_start = '#AIOWPS_LOGIN_WHITELIST_START';
    public static $enable_login_whitelist_marker_end = '#AIOWPS_LOGIN_WHITELIST_END';

    public static $prevent_image_hotlinks_marker_start = '#AIOWPS_PREVENT_IMAGE_HOTLINKS_START';
    public static $prevent_image_hotlinks_marker_end = '#AIOWPS_PREVENT_IMAGE_HOTLINKS_END';

    public static $custom_rules_marker_start = '#AIOWPS_CUSTOM_RULES_START';
    public static $custom_rules_marker_end = '#AIOWPS_CUSTOM_RULES_END';

    // TODO - enter more markers as new .htaccess features are added

    function __construct()
    {
        //NOP
    }


    /**
     * Write all active rules to .htaccess file.
     *
     * @return boolean True on success, false on failure.
     */
    static function write_to_htaccess()
    {
        global $aio_wp_security;
        //figure out what server is being used
        if (AIOWPSecurity_Utility::get_server_type() == -1) {
            $aio_wp_security->debug_logger->log_debug("Unable to write to .htaccess - server type not supported!", 4);
            return false; //unable to write to the file
        }

        //clean up old rules first
        if (AIOWPSecurity_Utility_Htaccess::delete_from_htaccess() == -1) {
            $aio_wp_security->debug_logger->log_debug("Delete operation of .htaccess file failed!", 4);
            return false; //unable to write to the file
        }

        $htaccess = ABSPATH . '.htaccess';

        if (!$f = @fopen($htaccess, 'a+')) {
            @chmod($htaccess, 0644);
            if (!$f = @fopen($htaccess, 'a+')) {
                $aio_wp_security->debug_logger->log_debug("chmod operation on .htaccess failed!", 4);
                return false;
            }
        }
        AIOWPSecurity_Utility_File::backup_and_rename_htaccess($htaccess); //TODO - we dont want to continually be backing up the htaccess file
        @ini_set('auto_detect_line_endings', true);
        $ht = explode(PHP_EOL, implode('', file($htaccess))); //parse each line of file into array

        $rules = AIOWPSecurity_Utility_Htaccess::getrules();

        $rulesarray = explode(PHP_EOL, $rules);
        $rulesarray = apply_filters('aiowps_htaccess_rules_before_writing', $rulesarray);
        $contents = array_merge($rulesarray, $ht);

        if (!$f = @fopen($htaccess, 'w+')) {
            $aio_wp_security->debug_logger->log_debug("Write operation on .htaccess failed!", 4);
            return false; //we can't write to the file
        }

        $blank = false;

        //write each line to file
        foreach ($contents as $insertline) {
            if (trim($insertline) == '') {
                if ($blank == false) {
                    fwrite($f, PHP_EOL . trim($insertline));
                }
                $blank = true;
            } else {
                $blank = false;
                fwrite($f, PHP_EOL . trim($insertline));
            }
        }
        @fclose($f);
        return true; //success
    }

    /*
     * This function will delete the code which has been added to the .htaccess file by this plugin
     * It will try to find the comment markers "# BEGIN All In One WP Security" and "# END All In One WP Security" and delete contents in between
     */
    static function delete_from_htaccess($section = 'All In One WP Security')
    {
        //TODO
        $htaccess = ABSPATH . '.htaccess';

        @ini_set('auto_detect_line_endings', true);
        if (!file_exists($htaccess)) {
            $ht = @fopen($htaccess, 'a+');
            @fclose($ht);
        }
        $ht_contents = explode(PHP_EOL, implode('', file($htaccess))); //parse each line of file into array
        if ($ht_contents) { //as long as there are lines in the file
            $state = true;
            if (!$f = @fopen($htaccess, 'w+')) {
                @chmod($htaccess, 0644);
                if (!$f = @fopen($htaccess, 'w+')) {
                    return -1;
                }
            }

            foreach ($ht_contents as $n => $markerline) { //for each line in the file
                if (strpos($markerline, '# BEGIN ' . $section) !== false) { //if we're at the beginning of the section
                    $state = false;
                }
                if ($state == true) { //as long as we're not in the section keep writing
                    fwrite($f, trim($markerline) . PHP_EOL);
                }
                if (strpos($markerline, '# END ' . $section) !== false) { //see if we're at the end of the section
                    $state = true;
                }
            }
            @fclose($f);
            return 1;
        }
        return 1;
    }

    static function getrules()
    {
        $rules = "";
        $rules .= AIOWPSecurity_Utility_Htaccess::getrules_block_wp_file_access();
        $rules .= AIOWPSecurity_Utility_Htaccess::getrules_basic_htaccess();
        $rules .= AIOWPSecurity_Utility_Htaccess::getrules_pingback_htaccess();
        $rules .= AIOWPSecurity_Utility_Htaccess::getrules_block_debug_log_access_htaccess();
        $rules .= AIOWPSecurity_Utility_Htaccess::getrules_disable_index_views();
        $rules .= AIOWPSecurity_Utility_Htaccess::getrules_blacklist();
        $rules .= AIOWPSecurity_Utility_Htaccess::getrules_disable_trace_and_track();
        $rules .= AIOWPSecurity_Utility_Htaccess::getrules_forbid_proxy_comment_posting();
        $rules .= AIOWPSecurity_Utility_Htaccess::getrules_deny_bad_query_strings();
        $rules .= AIOWPSecurity_Utility_Htaccess::getrules_advanced_character_string_filter();
        $rules .= AIOWPSecurity_Utility_Htaccess::getrules_6g_blacklist();
        $rules .= AIOWPSecurity_Utility_Htaccess::getrules_5g_blacklist();
        $rules .= AIOWPSecurity_Utility_Htaccess::getrules_enable_brute_force_prevention();
        $rules .= AIOWPSecurity_Utility_Htaccess::getrules_block_spambots();
        $rules .= AIOWPSecurity_Utility_Htaccess::getrules_enable_login_whitelist();
        $rules .= AIOWPSecurity_Utility_Htaccess::prevent_image_hotlinks();
        $rules .= AIOWPSecurity_Utility_Htaccess::getrules_custom_rules();
        //TODO: The following utility functions are ready to use when we write the menu pages for these features

        //Add more functions for features as needed
        //$rules .= AIOWPSecurity_Utility_Htaccess::getrules_somefeature();

        //Add outer markers if we have rules
        if ($rules != '') {
            $rules = "# BEGIN All In One WP Security" . PHP_EOL . $rules . "# END All In One WP Security" . PHP_EOL;
        }

        return $rules;
    }

    /*
     * This function will write rules to prevent people from accessing the following files:
     * readme.html, license.txt and wp-config-sample.php.
     */
    static function getrules_block_wp_file_access()
    {
        global $aio_wp_security;
        $rules = '';
        if ($aio_wp_security->configs->get_value('aiowps_prevent_default_wp_file_access') == '1') {
            $rules .= AIOWPSecurity_Utility_Htaccess::$prevent_wp_file_access_marker_start . PHP_EOL; //Add feature marker start
            $rules .= self::create_apache2_access_denied_rule('license.txt');
            $rules .= self::create_apache2_access_denied_rule('wp-config-sample.php');
            $rules .= self::create_apache2_access_denied_rule('readme.html');
            $rules .= AIOWPSecurity_Utility_Htaccess::$prevent_wp_file_access_marker_end . PHP_EOL; //Add feature marker end
        }

        return $rules;
    }

    static function getrules_blacklist()
    {
        global $aio_wp_security;
        // Are we on Apache or LiteSpeed webserver?
        $aiowps_server = AIOWPSecurity_Utility::get_server_type();
        $apache_or_litespeed = $aiowps_server == 'apache' || $aiowps_server == 'litespeed';
        //
        $rules = '';
        if ($aio_wp_security->configs->get_value('aiowps_enable_blacklisting') == '1') {
            // Let's do the list of blacklisted IPs first
            $hosts = AIOWPSecurity_Utility::explode_trim_filter_empty($aio_wp_security->configs->get_value('aiowps_banned_ip_addresses'));
            // Filter out duplicate lines, add netmask to IP addresses
            $ips_with_netmask = self::add_netmask(array_unique($hosts));

            if ( !empty($ips_with_netmask) ) {
                $rules .= AIOWPSecurity_Utility_Htaccess::$ip_blacklist_marker_start . PHP_EOL; //Add feature marker start

                if ( $apache_or_litespeed ) {
                    // Apache or LiteSpeed webserver
                    // Apache 2.2 and older
                    $rules .= "<IfModule !mod_authz_core.c>" . PHP_EOL;
                    $rules .= "Order allow,deny" . PHP_EOL;
                    $rules .= "Allow from all" . PHP_EOL;
                    foreach ($ips_with_netmask as $ip_with_netmask) {
                        $rules .= "Deny from " . $ip_with_netmask . PHP_EOL;
                    }
                    $rules .= "</IfModule>" . PHP_EOL;
                    // Apache 2.3 and newer
                    $rules .= "<IfModule mod_authz_core.c>" . PHP_EOL;
                    $rules .= "<RequireAll>" . PHP_EOL;
                    $rules .= "Require all granted" . PHP_EOL;
                    foreach ($ips_with_netmask as $ip_with_netmask) {
                        $rules .= "Require not ip " . $ip_with_netmask . PHP_EOL;
                    }
                    $rules .= "</RequireAll>" . PHP_EOL;
                    $rules .= "</IfModule>" . PHP_EOL;
                }
                else {
                    // Nginx webserver
                    foreach ($ips_with_netmask as $ip_with_netmask) {
                        $rules .= "\tdeny " . $ip_with_netmask . ";" . PHP_EOL;
                    }
                }

                $rules .= AIOWPSecurity_Utility_Htaccess::$ip_blacklist_marker_end . PHP_EOL; //Add feature marker end
            }

            //Now let's do the user agent list
            $user_agents = explode(PHP_EOL, $aio_wp_security->configs->get_value('aiowps_banned_user_agents'));
            if (!empty($user_agents) && !(sizeof($user_agents) == 1 && trim($user_agents[0]) == '')) {
                if ( $apache_or_litespeed ) {
                    $rules .= AIOWPSecurity_Utility_Htaccess::$user_agent_blacklist_marker_start . PHP_EOL; //Add feature marker start
                    //Start mod_rewrite rules
                    $rules .= "<IfModule mod_rewrite.c>" . PHP_EOL . "RewriteEngine On" . PHP_EOL . PHP_EOL;
                    $count = 1;
                    foreach ($user_agents as $agent) {
                        $agent_escaped = quotemeta($agent);
                        $pattern = '/\s/'; //Find spaces in the string
                        $replacement = '\s'; //Replace spaces with \s so apache can understand
                        $agent_sanitized = preg_replace($pattern, $replacement, $agent_escaped);

                        $rules .= "RewriteCond %{HTTP_USER_AGENT} ^" . trim($agent_sanitized);
                        if ($count < sizeof($user_agents)) {
                            $rules .= " [NC,OR]" . PHP_EOL;
                            $count++;
                        } else {
                            $rules .= " [NC]" . PHP_EOL;
                        }

                    }
                    $rules .= "RewriteRule ^(.*)$ - [F,L]" . PHP_EOL . PHP_EOL;
                    // End mod_rewrite rules
                    $rules .= "</IfModule>" . PHP_EOL;
                    $rules .= AIOWPSecurity_Utility_Htaccess::$user_agent_blacklist_marker_end . PHP_EOL; //Add feature marker end
                } else {
                    $count = 1;
                    $alist = '';
                    foreach ($user_agents as $agent) {
                        $alist .= trim($agent);
                        if ($count < sizeof($user_agents)) {
                            $alist .= '|';
                            $count++;
                        }
                    }
                    $rules .= "\tif (\$http_user_agent ~* " . $alist . ") { return 403; }" . PHP_EOL;
                }
            }
        }

        return implode(PHP_EOL, array_diff(explode(PHP_EOL, $rules), array('Deny from ', 'Deny from')));
    }

    /*
     * TODO - info
     */
    static function getrules_basic_htaccess()
    {
        global $aio_wp_security;

        $rules = '';
        if ($aio_wp_security->configs->get_value('aiowps_enable_basic_firewall') == '1') {
            $rules .= AIOWPSecurity_Utility_Htaccess::$basic_htaccess_rules_marker_start . PHP_EOL; //Add feature marker start
            //protect the htaccess file - this is done by default with apache config file but we are including it here for good measure
            $rules .= self::create_apache2_access_denied_rule('.htaccess');

            //disable the server signature
            $rules .= 'ServerSignature Off' . PHP_EOL;

            //limit file uploads to 10mb
            $rules .= 'LimitRequestBody 10240000' . PHP_EOL;

            // protect wpconfig.php.
            $rules .= self::create_apache2_access_denied_rule('wp-config.php');

            $rules .= AIOWPSecurity_Utility_Htaccess::$basic_htaccess_rules_marker_end . PHP_EOL; //Add feature marker end
        }
        return $rules;
    }

    static function getrules_pingback_htaccess()
    {
        global $aio_wp_security;

        $rules = '';
        if ($aio_wp_security->configs->get_value('aiowps_enable_pingback_firewall') == '1') {
            $rules .= AIOWPSecurity_Utility_Htaccess::$pingback_htaccess_rules_marker_start . PHP_EOL; //Add feature marker start
            $rules .= self::create_apache2_access_denied_rule('xmlrpc.php');
            $rules .= AIOWPSecurity_Utility_Htaccess::$pingback_htaccess_rules_marker_end . PHP_EOL; //Add feature marker end
        }
        return $rules;
    }

    static function getrules_block_debug_log_access_htaccess()
    {
        global $aio_wp_security;

        $rules = '';
        if ($aio_wp_security->configs->get_value('aiowps_block_debug_log_file_access') == '1') {
            $rules .= AIOWPSecurity_Utility_Htaccess::$debug_log_block_htaccess_rules_marker_start . PHP_EOL; //Add feature marker start
            $rules .= self::create_apache2_access_denied_rule('debug.log');
            $rules .= AIOWPSecurity_Utility_Htaccess::$debug_log_block_htaccess_rules_marker_end . PHP_EOL; //Add feature marker end
        }
        return $rules;
    }

    /*
     * This function will write some drectives to block all people who do not have a cookie 
     * when trying to access the WP login page
     */
    static function getrules_enable_brute_force_prevention()
    {
        global $aio_wp_security;
        $rules = '';
        if ($aio_wp_security->configs->get_value('aiowps_enable_brute_force_attack_prevention') == '1') {
            $cookie_name = $aio_wp_security->configs->get_value('aiowps_brute_force_secret_word');
            $test_cookie_name = $aio_wp_security->configs->get_value('aiowps_cookie_brute_test');
            $redirect_url = $aio_wp_security->configs->get_value('aiowps_cookie_based_brute_force_redirect_url');
            $rules .= AIOWPSecurity_Utility_Htaccess::$enable_brute_force_attack_prevention_marker_start . PHP_EOL; //Add feature marker start
            $rules .= 'RewriteEngine On' . PHP_EOL;
            $rules .= 'RewriteCond %{REQUEST_URI} (wp-admin|wp-login)' . PHP_EOL;// If URI contains wp-admin or wp-login
            if ($aio_wp_security->configs->get_value('aiowps_brute_force_attack_prevention_ajax_exception') == '1') {
                $rules .= 'RewriteCond %{REQUEST_URI} !(wp-admin/admin-ajax.php)' . PHP_EOL; // To allow ajax requests through
            }
            if ($aio_wp_security->configs->get_value('aiowps_brute_force_attack_prevention_pw_protected_exception') == '1') {
                $rules .= 'RewriteCond %{QUERY_STRING} !(action\=postpass)' . PHP_EOL; // Possible workaround for people usign the password protected page/post feature
            }
            $rules .= 'RewriteCond %{HTTP_COOKIE} !' . $cookie_name . '= [NC]' . PHP_EOL;
            $rules .= 'RewriteCond %{HTTP_COOKIE} !' . $test_cookie_name . '= [NC]' . PHP_EOL;
            $rules .= 'RewriteRule .* ' . $redirect_url . ' [L]' . PHP_EOL;
            $rules .= AIOWPSecurity_Utility_Htaccess::$enable_brute_force_attack_prevention_marker_end . PHP_EOL; //Add feature marker end
        }

        return $rules;
    }


    /*
     * This function will write some directives to allow IPs in the whitelist to access wp-login.php or wp-admin
     * The function also handles the following special cases:
     * 1) If the rename login feature is being used: for this scenario instead of protecting wp-login.php we must protect the special page slug
     * 2) If the rename login feature is being used AND non permalink URL structure: for this case need to use mod_rewrite because we must check QUERY_STRING 
     */
    static function getrules_enable_login_whitelist()
    {
        global $aio_wp_security;
        $rules = '';

        if ($aio_wp_security->configs->get_value('aiowps_enable_whitelisting') == '1') {
            $site_url = AIOWPSEC_WP_URL;
            $parse_url = parse_url($site_url);
            $hostname = $parse_url['host'];
            $host_ip = gethostbyname($hostname);
            $special_case = false;
            $rules .= AIOWPSecurity_Utility_Htaccess::$enable_login_whitelist_marker_start . PHP_EOL; //Add feature marker start
            //If the rename login page feature is active, we will need to adjust the directives
            if ($aio_wp_security->configs->get_value('aiowps_enable_rename_login_page') == '1') {
                $secret_slug = $aio_wp_security->configs->get_value('aiowps_login_page_slug');
                if (!get_option('permalink_structure')) {
                    //standard url structure is being used - ie, non permalinks
                    $special_case = true;
                    $rules .= '<IfModule mod_rewrite.c>' . PHP_EOL;
                    $rules .= 'RewriteEngine on' . PHP_EOL;
                    $rules .= 'RewriteCond %{QUERY_STRING} ^' . $secret_slug . '$' . PHP_EOL;
                    $rules .= 'RewriteCond %{REMOTE_ADDR} !^' . preg_quote($host_ip) . '[OR]' . PHP_EOL;
                } else {
                    $slug = preg_quote($secret_slug); //escape any applicable chars
                    $rules .= '<FilesMatch "^(' . $slug . ')">' . PHP_EOL;
                }
            } else {
                $rules .= '<FilesMatch "^(wp-login\.php)">' . PHP_EOL;
            }
            if (!$special_case) {
                $rules .= 'Order Allow,Deny' . PHP_EOL;
                $rules .= 'Allow from ' . $hostname . PHP_EOL;
                $rules .= 'Allow from ' . $host_ip . PHP_EOL;
            }

            //Let's get list of whitelisted IPs
            $hosts = explode(PHP_EOL, $aio_wp_security->configs->get_value('aiowps_allowed_ip_addresses'));
            if (!empty($hosts) && !(sizeof($hosts) == 1 && trim($hosts[0]) == '')) {
                $phosts = array();
                $num_hosts = count($hosts);
                $i = 0;
                foreach ($hosts as $host) {
                    $host = trim($host);
                    $or_string = ($i == $num_hosts - 1) ? '' : '[OR]'; //Add an [OR] clause for all except the last condition

                    if (!in_array($host, $phosts)) {
                        if (strstr($host, '*')) {
                            $parts = array_reverse(explode('.', $host));
                            $netmask = 32;
                            foreach ($parts as $part) {
                                if (strstr(trim($part), '*')) {
                                    $netmask = $netmask - 8;

                                }
                            }
                            //*****Bug Fix ******
                            //Seems that netmask does not work when using the following type of directive, ie,
                            //RewriteCond %{REMOTE_ADDR} !^203\.87\.121\.0/24

                            //The following works:
                            //RewriteCond %{REMOTE_ADDR} !^203\.87\.121\.

                            if($special_case){
                                $dhost = trim(str_replace('*', '', implode('.', array_reverse($parts)),$count));
                                if($count > 1){
                                    //means that we will have consecutive periods in the string and we must remove all except one - eg: 45.12..
                                    $dhost = rtrim($dhost, '.');
                                    $dhost = $dhost . '.';
                                }
                            }else{
                                $dhost = trim( str_replace('*', '0', implode( '.', array_reverse( $parts ) ) ) . '/' . $netmask );
                            }
                            if (strlen($dhost) > 4) {
                                if ($special_case) {
                                    $dhost = preg_quote($dhost); //escape any applicable chars
                                    $trule = 'RewriteCond %{REMOTE_ADDR} !^' . $dhost . $or_string . PHP_EOL;
                                    if (trim($trule) != 'RewriteCond %{REMOTE_ADDR}!=') {
                                        $rules .= $trule;
                                    }
                                } else {
                                    $trule = 'Allow from ' . $dhost . PHP_EOL;
                                    if (trim($trule) != 'Allow from') {
                                        $rules .= $trule;
                                    }
                                }
                            }
                        } else {
                            $dhost = trim($host);
                            //ipv6 - for now we will support only whole ipv6 addresses, NOT ranges
                            if (strpos($dhost, ':') !== false) {
                                //possible ipv6 addr
                                $res = WP_Http::is_ip_address($dhost);
                                if (FALSE === $res) {
                                    continue;
                                }
                            }
                            if (strlen($dhost) > 4 || $res == '6') {
                                if ($special_case) {
                                    $dhost = preg_quote($dhost); //escape any applicable chars
                                    $rules .= 'RewriteCond %{REMOTE_ADDR} !^' . $dhost . $or_string . PHP_EOL;
                                } else {
                                    $rules .= 'Allow from ' . $dhost . PHP_EOL;
                                }

                            }
                        }
                    }
                    $phosts[] = $host;
                    $i++;
                }
            }

            if ($special_case) {
                $rules .= 'RewriteRule .* http://127.0.0.1 [L]' . PHP_EOL;
                $rules .= '</IfModule>' . PHP_EOL;
            } else {
                $rules .= '</FilesMatch>' . PHP_EOL;
            }
            $rules .= AIOWPSecurity_Utility_Htaccess::$enable_login_whitelist_marker_end . PHP_EOL; //Add feature marker end
        }

        return $rules;
    }

    /*
     * This function will disable directory listings for all directories, add this line to the
     * site’s root .htaccess file.
     * NOTE: AllowOverride must be enabled in the httpd.conf file for this to work!
     */
    static function getrules_disable_index_views()
    {
        global $aio_wp_security;
        $rules = '';
        if ($aio_wp_security->configs->get_value('aiowps_disable_index_views') == '1') {
            $rules .= AIOWPSecurity_Utility_Htaccess::$disable_index_views_marker_start . PHP_EOL; //Add feature marker start
            $rules .= 'Options -Indexes' . PHP_EOL;
            $rules .= AIOWPSecurity_Utility_Htaccess::$disable_index_views_marker_end . PHP_EOL; //Add feature marker end
        }

        return $rules;
    }

    /*
     * This function will write rules to disable trace and track.
     * HTTP Trace attack (XST) can be used to return header requests 
     * and grab cookies and other information and is used along with 
     * a cross site scripting attacks (XSS)
     */
    static function getrules_disable_trace_and_track()
    {
        global $aio_wp_security;
        $rules = '';
        if ($aio_wp_security->configs->get_value('aiowps_disable_trace_and_track') == '1') {
            $rules .= AIOWPSecurity_Utility_Htaccess::$disable_trace_track_marker_start . PHP_EOL; //Add feature marker start
            $rules .= '<IfModule mod_rewrite.c>' . PHP_EOL;
            $rules .= 'RewriteEngine On' . PHP_EOL;
            $rules .= 'RewriteCond %{REQUEST_METHOD} ^(TRACE|TRACK)' . PHP_EOL;
            $rules .= 'RewriteRule .* - [F]' . PHP_EOL;
            $rules .= '</IfModule>' . PHP_EOL;
            $rules .= AIOWPSecurity_Utility_Htaccess::$disable_trace_track_marker_end . PHP_EOL; //Add feature marker end
        }

        return $rules;
    }

    /*
     * This function will write rules to prevent proxy comment posting.
     * This will deny any requests that use a proxy server when posting 
     * to comments eliminating some spam and proxy requests.
     * Thanks go to the helpful info and suggestions from perishablepress.com and Thomas O. (https://wordpress.org/support/topic/high-server-cpu-with-proxy-login)
     */
    static function getrules_forbid_proxy_comment_posting()
    {
        global $aio_wp_security;
        $rules = '';
        if ($aio_wp_security->configs->get_value('aiowps_forbid_proxy_comments') == '1') {
            $rules .= AIOWPSecurity_Utility_Htaccess::$forbid_proxy_comments_marker_start . PHP_EOL; //Add feature marker start
            $rules .= '<IfModule mod_rewrite.c>' . PHP_EOL;
            $rules .= 'RewriteEngine On' . PHP_EOL;
            $rules .= 'RewriteCond %{REQUEST_METHOD} ^POST' . PHP_EOL;
            $rules .= 'RewriteCond %{HTTP:VIA} !^$ [OR]' . PHP_EOL;
            $rules .= 'RewriteCond %{HTTP:FORWARDED} !^$ [OR]' . PHP_EOL;
            $rules .= 'RewriteCond %{HTTP:USERAGENT_VIA} !^$ [OR]' . PHP_EOL;
            $rules .= 'RewriteCond %{HTTP:X_FORWARDED_FOR} !^$ [OR]' . PHP_EOL;
            $rules .= 'RewriteCond %{HTTP:X_FORWARDED_HOST} !^$ [OR]' . PHP_EOL;
            $rules .= 'RewriteCond %{HTTP:PROXY_CONNECTION} !^$ [OR]' . PHP_EOL;
            $rules .= 'RewriteCond %{HTTP:XPROXY_CONNECTION} !^$ [OR]' . PHP_EOL;
            $rules .= 'RewriteCond %{HTTP:HTTP_PC_REMOTE_ADDR} !^$ [OR]' . PHP_EOL;
            $rules .= 'RewriteCond %{HTTP:HTTP_CLIENT_IP} !^$' . PHP_EOL;
            $rules .= 'RewriteRule wp-comments-post\.php - [F]' . PHP_EOL;
            $rules .= '</IfModule>' . PHP_EOL;
            $rules .= AIOWPSecurity_Utility_Htaccess::$forbid_proxy_comments_marker_end . PHP_EOL; //Add feature marker end
        }

        return $rules;
    }

    /*
     * This function will write rules to prevent malicious string attacks on your site using XSS.
     * NOTE: Some of these strings might be used for plugins or themes and doing so will disable the functionality. 
     * This script is from perishablepress and is fairly safe to use and should not break anything important
     */
    //TODO - the currently commented out rules (see function below) break the site - need to investigate why or if we can tweak the rules a bit
    static function getrules_deny_bad_query_strings()
    {
        global $aio_wp_security;
        $rules = '';
        if ($aio_wp_security->configs->get_value('aiowps_deny_bad_query_strings') == '1') {
            $rules .= AIOWPSecurity_Utility_Htaccess::$deny_bad_query_strings_marker_start . PHP_EOL; //Add feature marker start
            $rules .= '<IfModule mod_rewrite.c>' . PHP_EOL;
            $rules .= 'RewriteEngine On' . PHP_EOL;
            //$rules .= 'RewriteCond %{QUERY_STRING} ../    [NC,OR]' . PHP_EOL;
            //$rules .= 'RewriteCond %{QUERY_STRING} boot.ini [NC,OR]' . PHP_EOL;
            //$rules .= 'RewriteCond %{QUERY_STRING} tag=     [NC,OR]' . PHP_EOL;
            $rules .= 'RewriteCond %{QUERY_STRING} ftp:     [NC,OR]' . PHP_EOL;
            $rules .= 'RewriteCond %{QUERY_STRING} http:    [NC,OR]' . PHP_EOL;
            $rules .= 'RewriteCond %{QUERY_STRING} https:   [NC,OR]' . PHP_EOL;
            $rules .= 'RewriteCond %{QUERY_STRING} mosConfig [NC,OR]' . PHP_EOL;
            //$rules .= 'RewriteCond %{QUERY_STRING} ^.*([|]|(|)||\'|"|;|?|*).* [NC,OR]' . PHP_EOL;
            //$rules .= 'RewriteCond %{QUERY_STRING} ^.*(%22|%27|%3C|%3E|%5C|%7B|%7C).* [NC,OR]' . PHP_EOL;
            //$rules .= 'RewriteCond %{QUERY_STRING} ^.*(%0|%A|%B|%C|%D|%E|%F|127.0).* [NC,OR]' . PHP_EOL;
            $rules .= 'RewriteCond %{QUERY_STRING} ^.*(globals|encode|localhost|loopback).* [NC,OR]' . PHP_EOL;
            $rules .= 'RewriteCond %{QUERY_STRING} (\;|\'|\"|%22).*(request|insert|union|declare|drop) [NC]' . PHP_EOL;
            $rules .= 'RewriteRule ^(.*)$ - [F,L]' . PHP_EOL;
            $rules .= '</IfModule>' . PHP_EOL;
            $rules .= AIOWPSecurity_Utility_Htaccess::$deny_bad_query_strings_marker_end . PHP_EOL; //Add feature marker end
        }

        return $rules;
    }

    /*
     * This function will write rules to produce an advanced character string filter to prevent malicious string attacks from Cross Site Scripting (XSS)
     * NOTE: Some of these strings might be used for plugins or themes and doing so will disable the functionality. 
     * This script is from perishablepress and is fairly safe to use and should not break anything important
     */
    //TODO - the rules below break the site - need to investigate why or if we can tweak the rules a bit
    //RedirectMatch 403 ^
    //RedirectMatch 403 $
    //RedirectMatch 403 |
    //RedirectMatch 403 ..
    //Redirectmatch 403 select(
    //Redirectmatch 403 convert(
    //RedirectMatch 403 .inc
    //RedirectMatch 403 include.
    //
    // The "@" sign is often used in filenames of retina-ready images like
    // "logo@2x.jpg", therefore it has been removed from the list.
    //RedirectMatch 403 \@

    static function getrules_advanced_character_string_filter()
    {
        global $aio_wp_security;
        $rules = '';
        if ($aio_wp_security->configs->get_value('aiowps_advanced_char_string_filter') == '1') {
            $rules .= AIOWPSecurity_Utility_Htaccess::$advanced_char_string_filter_marker_start . PHP_EOL; //Add feature marker start

            $rules .= '<IfModule mod_alias.c>
                        RedirectMatch 403 \,
                        RedirectMatch 403 \:
                        RedirectMatch 403 \;
                        RedirectMatch 403 \=
                        RedirectMatch 403 \[
                        RedirectMatch 403 \]
                        RedirectMatch 403 \^
                        RedirectMatch 403 \`
                        RedirectMatch 403 \{
                        RedirectMatch 403 \}
                        RedirectMatch 403 \~
                        RedirectMatch 403 \"
                        RedirectMatch 403 \$
                        RedirectMatch 403 \<
                        RedirectMatch 403 \>
                        RedirectMatch 403 \|
                        RedirectMatch 403 \.\.
                        RedirectMatch 403 \%0
                        RedirectMatch 403 \%A
                        RedirectMatch 403 \%B
                        RedirectMatch 403 \%C
                        RedirectMatch 403 \%D
                        RedirectMatch 403 \%E
                        RedirectMatch 403 \%F
                        RedirectMatch 403 \%22
                        RedirectMatch 403 \%27
                        RedirectMatch 403 \%28
                        RedirectMatch 403 \%29
                        RedirectMatch 403 \%3C
                        RedirectMatch 403 \%3E
                        RedirectMatch 403 \%3F
                        RedirectMatch 403 \%5B
                        RedirectMatch 403 \%5C
                        RedirectMatch 403 \%5D
                        RedirectMatch 403 \%7B
                        RedirectMatch 403 \%7C
                        RedirectMatch 403 \%7D
                        # COMMON PATTERNS
                        Redirectmatch 403 \_vpi
                        RedirectMatch 403 \.inc
                        Redirectmatch 403 xAou6
                        Redirectmatch 403 db\_name
                        Redirectmatch 403 select\(
                        Redirectmatch 403 convert\(
                        Redirectmatch 403 \/query\/
                        RedirectMatch 403 ImpEvData
                        Redirectmatch 403 \.XMLHTTP
                        Redirectmatch 403 proxydeny
                        RedirectMatch 403 function\.
                        Redirectmatch 403 remoteFile
                        Redirectmatch 403 servername
                        Redirectmatch 403 \&rptmode\=
                        Redirectmatch 403 sys\_cpanel
                        RedirectMatch 403 db\_connect
                        RedirectMatch 403 doeditconfig
                        RedirectMatch 403 check\_proxy
                        Redirectmatch 403 system\_user
                        Redirectmatch 403 \/\(null\)\/
                        Redirectmatch 403 clientrequest
                        Redirectmatch 403 option\_value
                        RedirectMatch 403 ref\.outcontrol
                        # SPECIFIC EXPLOITS
                        RedirectMatch 403 errors\.
                        RedirectMatch 403 config\.
                        RedirectMatch 403 include\.
                        RedirectMatch 403 display\.
                        RedirectMatch 403 register\.
                        Redirectmatch 403 password\.
                        RedirectMatch 403 maincore\.
                        RedirectMatch 403 authorize\.
                        Redirectmatch 403 macromates\.
                        RedirectMatch 403 head\_auth\.
                        RedirectMatch 403 submit\_links\.
                        RedirectMatch 403 change\_action\.
                        Redirectmatch 403 com\_facileforms\/
                        RedirectMatch 403 admin\_db\_utilities\.
                        RedirectMatch 403 admin\.webring\.docs\.
                        Redirectmatch 403 Table\/Latest\/index\.
                        </IfModule>' . PHP_EOL;
            $rules .= AIOWPSecurity_Utility_Htaccess::$advanced_char_string_filter_marker_end . PHP_EOL; //Add feature marker end
        }

        return $rules;
    }

    /*
     * This function contains the rules for the 5G blacklist produced by Jeff Starr from perishablepress.com
     * NOTE: Since Jeff regularly updates and evolves his blacklist rules, ie, 5G->6G->7G.... we will update this function to reflect the latest blacklist release
     */


    static function getrules_5g_blacklist()
    {
        global $aio_wp_security;
        $rules = '';
        if ($aio_wp_security->configs->get_value('aiowps_enable_5g_firewall') == '1') {
            $rules .= AIOWPSecurity_Utility_Htaccess::$five_g_blacklist_marker_start . PHP_EOL; //Add feature marker start

            $rules .= '# 5G BLACKLIST/FIREWALL (2013)
                        # @ http://perishablepress.com/5g-blacklist-2013/

                        # 5G:[QUERY STRINGS]
                        <IfModule mod_rewrite.c>
                                RewriteEngine On
                                RewriteBase /
                                RewriteCond %{QUERY_STRING} (\"|%22).*(<|>|%3) [NC,OR]
                                RewriteCond %{QUERY_STRING} (javascript:).*(\;) [NC,OR]
                                RewriteCond %{QUERY_STRING} (<|%3C).*script.*(>|%3) [NC,OR]
                                RewriteCond %{QUERY_STRING} (\\\|\.\./|`|=\'$|=%27$) [NC,OR]
                                RewriteCond %{QUERY_STRING} (\;|\'|\"|%22).*(union|select|insert|drop|update|md5|benchmark|or|and|if) [NC,OR]
                                RewriteCond %{QUERY_STRING} (base64_encode|localhost|mosconfig) [NC,OR]
                                RewriteCond %{QUERY_STRING} (boot\.ini|echo.*kae|etc/passwd) [NC,OR]
                                RewriteCond %{QUERY_STRING} (GLOBALS|REQUEST)(=|\[|%) [NC]
                                RewriteRule .* - [F]
                        </IfModule>

                        # 5G:[USER AGENTS]
                        <IfModule mod_setenvif.c>
                                # SetEnvIfNoCase User-Agent ^$ keep_out
                                SetEnvIfNoCase User-Agent (binlar|casper|cmsworldmap|comodo|diavol|dotbot|feedfinder|flicky|ia_archiver|jakarta|kmccrew|nutch|planetwork|purebot|pycurl|skygrid|sucker|turnit|vikspider|zmeu) keep_out
                                <limit GET POST PUT>
                                        Order Allow,Deny
                                        Allow from all
                                        Deny from env=keep_out
                                </limit>
                        </IfModule>

                        # 5G:[REQUEST STRINGS]
                        <IfModule mod_alias.c>
                                RedirectMatch 403 (https?|ftp|php)\://
                                RedirectMatch 403 /(https?|ima|ucp)/
                                RedirectMatch 403 /(Permanent|Better)$
                                RedirectMatch 403 (\=\\\\\\\'|\=\\\%27|/\\\\\\\'/?|\)\.css\()$
                                RedirectMatch 403 (\,|\)\+|/\,/|\{0\}|\(/\(|\.\.\.|\+\+\+|\||\\\\\"\\\\\")
                                RedirectMatch 403 \.(cgi|asp|aspx|cfg|dll|exe|jsp|mdb|sql|ini|rar)$
                                RedirectMatch 403 /(contac|fpw|install|pingserver|register)\.php$
                                RedirectMatch 403 (base64|crossdomain|localhost|wwwroot|e107\_)
                                RedirectMatch 403 (eval\(|\_vti\_|\(null\)|echo.*kae|config\.xml)
                                RedirectMatch 403 \.well\-known/host\-meta
                                RedirectMatch 403 /function\.array\-rand
                                RedirectMatch 403 \)\;\$\(this\)\.html\(
                                RedirectMatch 403 proc/self/environ
                                RedirectMatch 403 msnbot\.htm\)\.\_
                                RedirectMatch 403 /ref\.outcontrol
                                RedirectMatch 403 com\_cropimage
                                RedirectMatch 403 indonesia\.htm
                                RedirectMatch 403 \{\$itemURL\}
                                RedirectMatch 403 function\(\)
                                RedirectMatch 403 labels\.rdf
                                RedirectMatch 403 /playing.php
                                RedirectMatch 403 muieblackcat
                        </IfModule>

                        # 5G:[REQUEST METHOD]
                        <ifModule mod_rewrite.c>
                                RewriteCond %{REQUEST_METHOD} ^(TRACE|TRACK)
                                RewriteRule .* - [F]
                        </IfModule>' . PHP_EOL;
            $rules .= AIOWPSecurity_Utility_Htaccess::$five_g_blacklist_marker_end . PHP_EOL; //Add feature marker end
        }

        return $rules;
    }

    /*
     * This function contains the rules for the 6G blacklist produced by Jeff Starr:
	 * https://perishablepress.com/6g/
     */
    static function getrules_6g_blacklist()
    {
        global $aio_wp_security;
        $rules = '';
        if ($aio_wp_security->configs->get_value('aiowps_enable_6g_firewall') == '1') {
            $rules .= AIOWPSecurity_Utility_Htaccess::$six_g_blacklist_marker_start . PHP_EOL; //Add feature marker start

            $rules .= '# 6G FIREWALL/BLACKLIST
                        # @ https://perishablepress.com/6g/

                        # 6G:[QUERY STRINGS]
                        <IfModule mod_rewrite.c>
                                RewriteEngine On
                                RewriteCond %{QUERY_STRING} (eval\() [NC,OR]
                                RewriteCond %{QUERY_STRING} (127\.0\.0\.1) [NC,OR]
                                RewriteCond %{QUERY_STRING} ([a-z0-9]{2000,}) [NC,OR]
                                RewriteCond %{QUERY_STRING} (javascript:)(.*)(;) [NC,OR]
                                RewriteCond %{QUERY_STRING} (base64_encode)(.*)(\() [NC,OR]
                                RewriteCond %{QUERY_STRING} (GLOBALS|REQUEST)(=|\[|%) [NC,OR]
                                RewriteCond %{QUERY_STRING} (<|%3C)(.*)script(.*)(>|%3) [NC,OR]
                                RewriteCond %{QUERY_STRING} (\\|\.\.\.|\.\./|~|`|<|>|\|) [NC,OR]
                                RewriteCond %{QUERY_STRING} (boot\.ini|etc/passwd|self/environ) [NC,OR]
                                RewriteCond %{QUERY_STRING} (thumbs?(_editor|open)?|tim(thumb)?)\.php [NC,OR]
                                RewriteCond %{QUERY_STRING} (\'|\")(.*)(drop|insert|md5|select|union) [NC]
                                RewriteRule .* - [F]
                        </IfModule>

                        # 6G:[REQUEST METHOD]
                        <IfModule mod_rewrite.c>
                                RewriteCond %{REQUEST_METHOD} ^(connect|debug|move|put|trace|track) [NC]
                                RewriteRule .* - [F]
                        </IfModule>

                        # 6G:[REFERRERS]
                        <IfModule mod_rewrite.c>
                                RewriteCond %{HTTP_REFERER} ([a-z0-9]{2000,}) [NC,OR]
                                RewriteCond %{HTTP_REFERER} (semalt.com|todaperfeita) [NC]
                                RewriteRule .* - [F]
                        </IfModule>

                        # 6G:[REQUEST STRINGS]
                        <IfModule mod_alias.c>
                                RedirectMatch 403 (?i)([a-z0-9]{2000,})
                                RedirectMatch 403 (?i)(https?|ftp|php):/
                                RedirectMatch 403 (?i)(base64_encode)(.*)(\()
                                RedirectMatch 403 (?i)(=\\\'|=\\%27|/\\\'/?)\.
                                RedirectMatch 403 (?i)/(\$(\&)?|\*|\"|\.|,|&|&amp;?)/?$
                                RedirectMatch 403 (?i)(\{0\}|\(/\(|\.\.\.|\+\+\+|\\\"\\\")
                                RedirectMatch 403 (?i)(~|`|<|>|:|;|,|%|\\|\s|\{|\}|\[|\]|\|)
                                RedirectMatch 403 (?i)/(=|\$&|_mm|cgi-|etc/passwd|muieblack)
                                RedirectMatch 403 (?i)(&pws=0|_vti_|\(null\)|\{\$itemURL\}|echo(.*)kae|etc/passwd|eval\(|self/environ)
                                RedirectMatch 403 (?i)\.(aspx?|bash|bak?|cfg|cgi|dll|exe|git|hg|ini|jsp|log|mdb|out|sql|svn|swp|tar|rar|rdf)$
                                RedirectMatch 403 (?i)/(^$|(wp-)?config|mobiquo|phpinfo|shell|sqlpatch|thumb|thumb_editor|thumbopen|timthumb|webshell)\.php
                        </IfModule>

                        # 6G:[USER AGENTS]
                        <IfModule mod_setenvif.c>
                                SetEnvIfNoCase User-Agent ([a-z0-9]{2000,}) bad_bot
                                SetEnvIfNoCase User-Agent (archive.org|binlar|casper|checkpriv|choppy|clshttp|cmsworld|diavol|dotbot|extract|feedfinder|flicky|g00g1e|harvest|heritrix|httrack|kmccrew|loader|miner|nikto|nutch|planetwork|postrank|purebot|pycurl|python|seekerspider|siclab|skygrid|sqlmap|sucker|turnit|vikspider|winhttp|xxxyy|youda|zmeu|zune) bad_bot

                                # Apache < 2.3
                                <IfModule !mod_authz_core.c>
                                        Order Allow,Deny
                                        Allow from all
                                        Deny from env=bad_bot
                                </IfModule>

                                # Apache >= 2.3
                                <IfModule mod_authz_core.c>
                                        <RequireAll>
                                                Require all Granted
                                                Require not env bad_bot
                                        </RequireAll>
                                </IfModule>
                        </IfModule>' . PHP_EOL;
            $rules .= AIOWPSecurity_Utility_Htaccess::$six_g_blacklist_marker_end . PHP_EOL; //Add feature marker end
        }

        return $rules;
    }

    /*
     * This function will write some directives to block all comments which do not originate from the blog's domain
     * OR if the user agent is empty. All blocked requests will be redirected to 127.0.0.1
     */
    static function getrules_block_spambots()
    {
        global $aio_wp_security;
        $rules = '';
        if ($aio_wp_security->configs->get_value('aiowps_enable_spambot_blocking') == '1') {
            $url_string = AIOWPSecurity_Utility_Htaccess::return_regularized_url(AIOWPSEC_WP_HOME_URL);
            if ($url_string == FALSE) {
                $url_string = AIOWPSEC_WP_HOME_URL;
            }
            $rules .= AIOWPSecurity_Utility_Htaccess::$block_spambots_marker_start . PHP_EOL; //Add feature marker start
            $rules .= '<IfModule mod_rewrite.c>' . PHP_EOL;
            $rules .= 'RewriteEngine On' . PHP_EOL;
            $rules .= 'RewriteCond %{REQUEST_METHOD} POST' . PHP_EOL;
            $rules .= 'RewriteCond %{REQUEST_URI} ^(.*)?wp-comments-post\.php(.*)$' . PHP_EOL;
            $rules .= 'RewriteCond %{HTTP_REFERER} !^' . $url_string . ' [NC,OR]' . PHP_EOL;
            $rules .= 'RewriteCond %{HTTP_USER_AGENT} ^$' . PHP_EOL;
            $rules .= 'RewriteRule .* http://127.0.0.1 [L]' . PHP_EOL;
            $rules .= '</IfModule>' . PHP_EOL;
            $rules .= AIOWPSecurity_Utility_Htaccess::$block_spambots_marker_end . PHP_EOL; //Add feature marker end
        }

        return $rules;
    }

    /*
     * This function will write some directives to prevent image hotlinking
     */
    static function prevent_image_hotlinks()
    {
        global $aio_wp_security;
        $rules = '';
        if ($aio_wp_security->configs->get_value('aiowps_prevent_hotlinking') == '1') {
            $url_string = AIOWPSecurity_Utility_Htaccess::return_regularized_url(AIOWPSEC_WP_HOME_URL);
            if ($url_string == FALSE) {
                $url_string = AIOWPSEC_WP_HOME_URL;
            }
            $rules .= AIOWPSecurity_Utility_Htaccess::$prevent_image_hotlinks_marker_start . PHP_EOL; //Add feature marker start
            $rules .= '<IfModule mod_rewrite.c>' . PHP_EOL;
            $rules .= 'RewriteEngine On' . PHP_EOL;
            $rules .= 'RewriteCond %{HTTP_REFERER} !^$' . PHP_EOL;
            $rules .= 'RewriteCond %{REQUEST_FILENAME} -f' . PHP_EOL;
            $rules .= 'RewriteCond %{REQUEST_FILENAME} \.(gif|jpe?g?|png)$ [NC]' . PHP_EOL;
            $rules .= 'RewriteCond %{HTTP_REFERER} !^' . $url_string . ' [NC]' . PHP_EOL;
            $rules .= 'RewriteRule \.(gif|jpe?g?|png)$ - [F,NC,L]' . PHP_EOL;
            $rules .= '</IfModule>' . PHP_EOL;
            $rules .= AIOWPSecurity_Utility_Htaccess::$prevent_image_hotlinks_marker_end . PHP_EOL; //Add feature marker end
        }

        return $rules;
    }

    /**
     * This function will write any custom htaccess rules into the server's .htaccess file
     * @return string
     */
    static function getrules_custom_rules()
    {
        global $aio_wp_security;
        $rules = '';
        if ($aio_wp_security->configs->get_value('aiowps_enable_custom_rules') == '1') {
            $custom_rules = $aio_wp_security->configs->get_value('aiowps_custom_rules');
            $rules .= AIOWPSecurity_Utility_Htaccess::$custom_rules_marker_start . PHP_EOL; //Add feature marker start
            $rules .= $custom_rules . PHP_EOL;
            $rules .= AIOWPSecurity_Utility_Htaccess::$custom_rules_marker_end . PHP_EOL; //Add feature marker end
        }

        return $rules;
    }


    /*
     * This function will do a quick check to see if a file's contents are actually .htaccess specific.
     * At the moment it will look for the following tag somewhere in the file - "# BEGIN WordPress"
     * If it finds the tag it will deem the file as being .htaccess specific.
     * This was written to supplement the .htaccess restore functionality
     */

    static function check_if_htaccess_contents($file)
    {
        $is_htaccess = false;
        $file_contents = file_get_contents($file);
        if ($file_contents === FALSE || strlen($file_contents) == 0) {
            return -1;
        }

        if ((strpos($file_contents, '# BEGIN WordPress') !== false) || (strpos($file_contents, '# BEGIN') !== false)) {
            $is_htaccess = true; //It appears that we have some sort of .htacces file
        } else {
            //see if we're at the end of the section
            $is_htaccess = false;
        }

        if ($is_htaccess) {
            return 1;
        } else {
            return -1;
        }
    }

    /*
     * This function will take a URL string and convert it to a form useful for using in htaccess rules.
     * Example: If URL passed to function = "http://www.mysite.com"
     * Result = "http(s)?://(.*)?mysite\.com"
     */
    static function return_regularized_url($url)
    {
        if (filter_var($url, FILTER_VALIDATE_URL)) {
            $xyz = explode('.', $url);
            $y = '';
            if (count($xyz) > 1) {
                $j = 1;
                foreach ($xyz as $x) {
                    if (strpos($x, 'www') !== false) {
                        $y .= str_replace('www', '(.*)?', $x);
                    } else if ($j == 1) {
                        $y .= $x;
                    } else if ($j > 1) {
                        $y .= '\.' . $x;
                    }
                    $j++;
                }
                //Now replace the "http" with "http(s)?" to cover both secure and non-secure
                if (strpos($y, 'https') !== false) {
                    $y = str_replace('https', 'http(s)?', $y);
                }else if (strpos($y, 'http') !== false) {
                    $y = str_replace('http', 'http(s)?', $y);
                }
                return $y;
            } else {
                return $url;
            }
        } else {
            return FALSE;
        }
    }

    /**
     * Returns a string with <Files $filename> directive that contains rules
     * to effectively block access to any file that has basename matching
     * $filename under Apache webserver.
     *
     * @link http://httpd.apache.org/docs/current/mod/core.html#files
     *
     * @param string $filename
     * @return string
     */
    protected static function create_apache2_access_denied_rule($filename) {
        return <<<END
<Files $filename>
<IfModule mod_authz_core.c>
    Require all denied
</IfModule>
<IfModule !mod_authz_core.c>
    Order deny,allow
    Deny from all
</IfModule>
</Files>

END;
        // Keep the empty line at the end of heredoc string,
        // otherwise the string will not end with end-of-line character!
    }


    /**
     * Convert an array of optionally asterisk-masked or partial IPv4 addresses
     * into network/netmask notation. Netmask value for a "full" IP is not
     * added (see example below)
     *
     * Example:
     * In: array('1.2.3.4', '5.6', '7.8.9.*')
     * Out: array('1.2.3.4', '5.6.0.0/16', '7.8.9.0/24')
     *
     * Simple validation is performed:
     * In: array('1.2.3.4.5', 'abc', '1.2.xyz.4')
     * Out: array()
     *
     * Simple sanitization is performed:
     * In: array('6.7.*.9')
     * Out: array('6.7.0.0/16')
     *
     * @param array $ips
     * @return array
     */
    protected static function add_netmask($ips) {

        $output = array();

        foreach ( $ips as $ip ) {

            $parts = explode('.', $ip);

            // Skip any IP that is empty, has more parts than expected or has
            // a non-numeric first part.
            if ( empty($parts) || (count($parts) > 4) || !is_numeric($parts[0]) ) {
                continue;
            }

            $ip_out = array( $parts[0] );
            $netmask = 8;

            for ( $i = 1, $force_zero = false; ($i < 4) && $ip_out; $i++ ) {
                if ( $force_zero || !isset($parts[$i]) || ($parts[$i] === '') || ($parts[$i] === '*') ) {
                    $ip_out[$i] = '0';
                    $force_zero = true; // Forces all subsequent parts to be a zero
                }
                else if ( is_numeric($parts[$i]) ) {
                    $ip_out[$i] = $parts[$i];
                    $netmask += 8;
                }
                else {
                    // Invalid IP part detected, invalidate entire IP
                    $ip_out = false;
                }
            }

            if ( $ip_out ) {
                // Glue IP back together, add netmask if IP denotes a subnet, store for output.
                $output[] = implode('.', $ip_out) . (($netmask < 32) ? ('/' . $netmask) : '');
            }
        }

        return $output;
    }
}