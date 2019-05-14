<?php

class AIOWPSecurity_Feature_Item_Manager
{
    var $feature_items;
    var $total_points = 0;
    var $total_achievable_points = 0;
    
    var $feature_point_1 = "5";
    var $feature_point_2 = "10";
    var $feature_point_3 = "15";
    var $feature_point_4 = "20";
    var $sec_level_basic = "1";
    var $sec_level_inter = "2";
    var $sec_level_advanced = "3";
    var $feature_active = "active";
    var $feature_inactive = "inactive";
    var $feature_partial = "partial";
        
    function __construct(){
        
    }
    
    function initialize_features()
    {
        $this->feature_items = array();
        //Settings Menu Features
        //WP Generator Meta
        $this->feature_items[] = new AIOWPSecurity_Feature_Item("wp-generator-meta-tag", __("Remove WP Generator Meta Tag", "all-in-one-wp-security-and-firewall"), $this->feature_point_1, $this->sec_level_basic);
        
        //Prevent Image Hotlinks
        $this->feature_items[] = new AIOWPSecurity_Feature_Item("prevent-hotlinking", __("Prevent Image Hotlinking", "all-in-one-wp-security-and-firewall"), $this->feature_point_2, $this->sec_level_basic);

        //User Accounts Menu Features
        //Change Admin Username
        $this->feature_items[] = new AIOWPSecurity_Feature_Item("user-accounts-change-admin-user", __("Change Admin Username", "all-in-one-wp-security-and-firewall"), $this->feature_point_3, $this->sec_level_basic);
        //Change Display Name
        $this->feature_items[] = new AIOWPSecurity_Feature_Item("user-accounts-display-name", __("Change Display Name", "all-in-one-wp-security-and-firewall"), $this->feature_point_1, $this->sec_level_basic);
        
        //User Login Menu Features
        //Locking Lockdown
        $this->feature_items[] = new AIOWPSecurity_Feature_Item("user-login-login-lockdown", __("Login Lockdown", "all-in-one-wp-security-and-firewall"), $this->feature_point_4, $this->sec_level_basic);
        //Login Captcha
        $this->feature_items[] = new AIOWPSecurity_Feature_Item("user-login-captcha", __("Login Captcha", "all-in-one-wp-security-and-firewall"), $this->feature_point_4, $this->sec_level_basic);
        $this->feature_items[] = new AIOWPSecurity_Feature_Item("custom-login-captcha", __("Custom Login Captcha", "all-in-one-wp-security-and-firewall"), $this->feature_point_4, $this->sec_level_basic);
        $this->feature_items[] = new AIOWPSecurity_Feature_Item("woo-login-captcha", __("Woo Login Captcha", "all-in-one-wp-security-and-firewall"), $this->feature_point_2, $this->sec_level_basic);
        $this->feature_items[] = new AIOWPSecurity_Feature_Item("woo-lostpassword-captcha", __("Woo Lost Password Captcha", "all-in-one-wp-security-and-firewall"), $this->feature_point_2, $this->sec_level_basic);
        $this->feature_items[] = new AIOWPSecurity_Feature_Item("woo-register-captcha", __("Woo Register Captcha", "all-in-one-wp-security-and-firewall"), $this->feature_point_2, $this->sec_level_basic);
        //Lost Password Captcha
        $this->feature_items[] = new AIOWPSecurity_Feature_Item("lost-password-captcha", __("Lost Password Captcha", "all-in-one-wp-security-and-firewall"), $this->feature_point_2, $this->sec_level_basic);
        //Login whitelisting
        $this->feature_items[] = new AIOWPSecurity_Feature_Item("whitelist-manager-ip-login-whitelisting", __("Login IP Whitelisting", "all-in-one-wp-security-and-firewall"), $this->feature_point_3, $this->sec_level_inter);
        //Force Logout
        $this->feature_items[] = new AIOWPSecurity_Feature_Item("user-login-force-logout", __("Force Logout", "all-in-one-wp-security-and-firewall"), $this->feature_point_1, $this->sec_level_basic);

        //User Registration
        //Manually approve registrations
        $this->feature_items[] = new AIOWPSecurity_Feature_Item("manually-approve-registrations", __("Registration Approval", "all-in-one-wp-security-and-firewall"), $this->feature_point_4, $this->sec_level_basic);
        //Registration Captcha
        $this->feature_items[] = new AIOWPSecurity_Feature_Item("user-registration-captcha", __("Registration Captcha", "all-in-one-wp-security-and-firewall"), $this->feature_point_4, $this->sec_level_basic);
        //Registration Honeypot
        $this->feature_items[] = new AIOWPSecurity_Feature_Item("registration-honeypot", __("Enable Registration Honeypot", "all-in-one-wp-security-and-firewall"), $this->feature_point_2, $this->sec_level_inter);
        
        //Database Security Menu Features
        //DB Prefix
        $this->feature_items[] = new AIOWPSecurity_Feature_Item("db-security-db-prefix", __("DB Prefix", "all-in-one-wp-security-and-firewall"), $this->feature_point_2, $this->sec_level_inter);
        //DB Backup
        $this->feature_items[] = new AIOWPSecurity_Feature_Item("db-security-db-backup", __("DB Backup", "all-in-one-wp-security-and-firewall"), $this->feature_point_4, $this->sec_level_basic);
        
        //File System Security Menu Features
        //File Permissions
        $this->feature_items[] = new AIOWPSecurity_Feature_Item("filesystem-file-permissions", __("File Permissions", "all-in-one-wp-security-and-firewall"), $this->feature_point_4, $this->sec_level_basic);
        //PHP File Editing
        $this->feature_items[] = new AIOWPSecurity_Feature_Item("filesystem-file-editing", __("File Editing", "all-in-one-wp-security-and-firewall"), $this->feature_point_2, $this->sec_level_basic);
        //Prevent Access WP Install Files
        $this->feature_items[] = new AIOWPSecurity_Feature_Item("block-wp-files-access", __("WordPress Files Access", "all-in-one-wp-security-and-firewall"), $this->feature_point_2, $this->sec_level_basic);
        
        //Blacklist Manager Menu Features
        //IP and user agent blacklisting
        $this->feature_items[] = new AIOWPSecurity_Feature_Item("blacklist-manager-ip-user-agent-blacklisting", __("IP and User Agent Blacklisting", "all-in-one-wp-security-and-firewall"), $this->feature_point_3, $this->sec_level_advanced);
        
        //Firewall Menu Features
        //Basic firewall
        $this->feature_items[] = new AIOWPSecurity_Feature_Item("firewall-basic-rules", __("Enable Basic Firewall", "all-in-one-wp-security-and-firewall"), $this->feature_point_3, $this->sec_level_basic);
        $this->feature_items[] = new AIOWPSecurity_Feature_Item("firewall-pingback-rules", __("Enable Pingback Vulnerability Protection", "all-in-one-wp-security-and-firewall"), $this->feature_point_3, $this->sec_level_basic);
        $this->feature_items[] = new AIOWPSecurity_Feature_Item("firewall-block-debug-file-access", __("Block Accesss to Debug Log File", "all-in-one-wp-security-and-firewall"), $this->feature_point_2, $this->sec_level_inter);
        $this->feature_items[] = new AIOWPSecurity_Feature_Item("firewall-enable-404-blocking", __("Enable IP blocking for 404 detection", "all-in-one-wp-security-and-firewall"), $this->feature_point_1, $this->sec_level_inter);

        //Brute Force Menu Features
        //Rename Login page
        $this->feature_items[] = new AIOWPSecurity_Feature_Item("bf-rename-login-page", __("Enable Rename Login Page", "all-in-one-wp-security-and-firewall"), $this->feature_point_2, $this->sec_level_inter);
        //Login Honeypot
        $this->feature_items[] = new AIOWPSecurity_Feature_Item("login-honeypot", __("Enable Login Honeypot", "all-in-one-wp-security-and-firewall"), $this->feature_point_2, $this->sec_level_inter);
        
        //Additional and Advanced firewall
        $this->feature_items[] = new AIOWPSecurity_Feature_Item("firewall-enable-brute-force-attack-prevention", __("Enable Brute Force Attack Prevention", "all-in-one-wp-security-and-firewall"), $this->feature_point_4, $this->sec_level_advanced);
        $this->feature_items[] = new AIOWPSecurity_Feature_Item("firewall-disable-index-views", __("Disable Index Views", "all-in-one-wp-security-and-firewall"), $this->feature_point_1, $this->sec_level_inter);
        $this->feature_items[] = new AIOWPSecurity_Feature_Item("firewall-disable-trace-track", __("Disable Trace and Track", "all-in-one-wp-security-and-firewall"), $this->feature_point_2, $this->sec_level_advanced);
        $this->feature_items[] = new AIOWPSecurity_Feature_Item("firewall-forbid-proxy-comments", __("Forbid Proxy Comments", "all-in-one-wp-security-and-firewall"), $this->feature_point_2, $this->sec_level_advanced);
        $this->feature_items[] = new AIOWPSecurity_Feature_Item("firewall-deny-bad-queries", __("Deny Bad Queries", "all-in-one-wp-security-and-firewall"), $this->feature_point_3, $this->sec_level_advanced);
        $this->feature_items[] = new AIOWPSecurity_Feature_Item("firewall-advanced-character-string-filter", __("Advanced Character String Filter", "all-in-one-wp-security-and-firewall"), $this->feature_point_3, $this->sec_level_advanced);
        $this->feature_items[] = new AIOWPSecurity_Feature_Item("firewall-enable-5g-6g-blacklist", __("5G/6G Blacklist", "all-in-one-wp-security-and-firewall"), $this->feature_point_4, $this->sec_level_advanced);
        $this->feature_items[] = new AIOWPSecurity_Feature_Item("firewall-block-fake-googlebots", __("Block Fake Googlebots", "all-in-one-wp-security-and-firewall"), $this->feature_point_1, $this->sec_level_advanced);
        //SPAM Prevention
        $this->feature_items[] = new AIOWPSecurity_Feature_Item("block-spambots", __("Block Spambots", "all-in-one-wp-security-and-firewall"), $this->feature_point_2, $this->sec_level_basic);
        //Comment Captcha
        $this->feature_items[] = new AIOWPSecurity_Feature_Item("comment-form-captcha", __("Comment Captcha", "all-in-one-wp-security-and-firewall"), $this->feature_point_4, $this->sec_level_basic);
        //BuddyPress Registration Captcha
        $this->feature_items[] = new AIOWPSecurity_Feature_Item("bp-register-captcha", __("BuddyPress Registration Captcha", "all-in-one-wp-security-and-firewall"), $this->feature_point_1, $this->sec_level_basic);
        //BBPress new topic Captcha
        $this->feature_items[] = new AIOWPSecurity_Feature_Item("bbp-new-topic-captcha", __("BBPress New Topic Captcha", "all-in-one-wp-security-and-firewall"), $this->feature_point_1, $this->sec_level_basic);
        
        //Filescan
        //File change detection
        $this->feature_items[] = new AIOWPSecurity_Feature_Item("scan-file-change-detection", __("File Change Detection", "all-in-one-wp-security-and-firewall"), $this->feature_point_4, $this->sec_level_inter);

    }
    
    function get_feature_item_by_id($feature_id)
    {
        foreach($this->feature_items as $item)
        {
            if($item->feature_id == $feature_id)
            {
                return $item;
            }
        }
        return "";
    }
    
    function output_feature_details_badge($feature_id)
    {
        $cau_feature_item = $this->get_feature_item_by_id($feature_id);
        $cau_security_level = $cau_feature_item->security_level;
        $cau_security_points = $cau_feature_item->item_points;
        $cau_your_points = 0;
        if($cau_feature_item->feature_status == $this->feature_active){
            $cau_your_points = $cau_security_points;
        }
        $level_str = $cau_feature_item->get_security_level_string($cau_security_level);
        ?>
        <div class="aiowps_feature_details_badge">
                <div class="aiowps_feature_details_badge_difficulty" title="Feature Difficulty">
                    <span class="aiowps_feature_details_badge_difficulty_text"><?php _e($level_str, 'all-in-one-wp-security-and-firewall'); ?></span>
                </div>
                <div class="aiowps_feature_details_badge_points" title="Security Points">
                    <span class="aiowps_feature_details_badge_points_text"><?php echo $cau_your_points .'/'. $cau_security_points; ?></span>
                </div>
        </div>
        <?php
    }
    
    function check_feature_status_and_recalculate_points()
    {
        $this->check_and_set_feature_status();
        $this->calculate_total_points();
    }
    
    function check_and_set_feature_status()
    {
        foreach($this->feature_items as $item)
        {
            if($item->feature_id == "wp-generator-meta-tag")
            {
                $this->check_remove_wp_generator_meta_feature($item);
            }            

            if($item->feature_id == "prevent-hotlinking")
            {
                $this->check_prevent_hotlinking_feature($item);
            }            

            if($item->feature_id == "user-accounts-change-admin-user")
            {
                $this->check_user_accounts_change_admin_user_feature($item);
            }
            if($item->feature_id == "user-accounts-display-name")
            {
                $this->check_user_accounts_display_name_feature($item);
            }

            if($item->feature_id == "db-security-db-prefix")
            {
                $this->check_db_security_db_prefix_feature($item);
            }
            if($item->feature_id == "db-security-db-backup")
            {
                $this->check_db_security_db_backup_feature($item);
            }

            if($item->feature_id == "user-login-login-lockdown")
            {
                $this->check_login_lockdown_feature($item);
            }
            if($item->feature_id == "user-login-captcha")
            {
                $this->check_login_captcha_feature($item);
            }
            if($item->feature_id == "custom-login-captcha")
            {
                $this->check_custom_login_captcha_feature($item);
            }
            if($item->feature_id == "woo-login-captcha")
            {
                $this->check_woo_login_captcha_feature($item);
            }
            if($item->feature_id == "woo-lostpassword-captcha")
            {
                $this->check_woo_lostpassword_captcha_feature($item);
            }
            if($item->feature_id == "woo-register-captcha")
            {
                $this->check_woo_register_captcha_feature($item);
            }
            if($item->feature_id == "lost-password-captcha")
            {
                $this->check_lost_password_captcha_feature($item);
            }
            if($item->feature_id == "comment-form-captcha")
            {
                $this->check_comment_captcha_feature($item);
            }
            if($item->feature_id == "bp-register-captcha")
            {
                $this->check_bp_register_captcha_feature($item);
            }
            if($item->feature_id == "bbp-new-topic-captcha")
            {
                $this->check_bbp_new_topic_captcha_feature($item);
            }
            if($item->feature_id == "whitelist-manager-ip-login-whitelisting")
            {
                $this->check_login_whitelist_feature($item);
            }
            if($item->feature_id == "user-login-force-logout")
            {
                $this->check_force_logout_feature($item);
            }
            
            if($item->feature_id == "manually-approve-registrations")
            {
                $this->check_registration_approval_feature($item);
            }
            if($item->feature_id == "user-registration-captcha")
            {
                $this->check_registration_captcha_feature($item);
            }
            if($item->feature_id == "registration-honeypot")
            {
                $this->check_enable_registration_honeypot_feature($item);
            }
            
            if($item->feature_id == "filesystem-file-permissions")
            {
                $this->check_filesystem_permissions_feature($item);
            }            
            if($item->feature_id == "filesystem-file-editing")
            {
                $this->check_filesystem_file_editing_feature($item);
            }            
            if($item->feature_id == "block-wp-files-access")
            {
                $this->check_block_wp_files_access_feature($item);
            }            

            if($item->feature_id == "blacklist-manager-ip-user-agent-blacklisting")
            {
                $this->check_enable_ip_useragent_blacklist_feature($item);
            }
            
            if($item->feature_id == "firewall-basic-rules")
            {
                $this->check_enable_basic_firewall_feature($item);
            }
            
            if($item->feature_id == "firewall-pingback-rules")
            {
                $this->check_enable_pingback_firewall_feature($item);
            }

            if($item->feature_id == "firewall-block-debug-file-access")
            {
                $this->check_debug_file_access_block_firewall_feature($item);
            }
            
            if($item->feature_id == "firewall-enable-404-blocking")
            {
                $this->check_enable_404_blocking_feature($item);
            }
            
            if($item->feature_id == "firewall-enable-brute-force-attack-prevention")
            {
                $this->check_enable_bfap_firewall_feature($item);
            }
            if($item->feature_id == "firewall-disable-index-views")
            {
                $this->check_disable_index_views_firewall_feature($item);
            }
            if($item->feature_id == "firewall-disable-trace-track")
            {
                $this->check_disable_trace_track_firewall_feature($item);
            }
            if($item->feature_id == "firewall-forbid-proxy-comments")
            {
                $this->check_forbid_proxy_comments_firewall_feature($item);
            }
            if($item->feature_id == "firewall-deny-bad-queries")
            {
                $this->check_deny_bad_queries_firewall_feature($item);
            }
            if($item->feature_id == "firewall-advanced-character-string-filter")
            {
                $this->check_advanced_char_string_filter_firewall_feature($item);
            }
            if($item->feature_id == "firewall-enable-5g-6g-blacklist")
            {
                $this->check_enable_5G_6G_blacklist_firewall_feature($item);
            }
            if($item->feature_id == "firewall-block-fake-googlebots")
            {
                $this->check_block_fake_googlebots_firewall_feature($item);
            }
            
            if($item->feature_id == "bf-rename-login-page")
            {
                $this->check_enable_rename_login_page_feature($item);
            }
            
            if($item->feature_id == "login-honeypot")
            {
                $this->check_enable_login_honeypot_feature($item);
            }

            if($item->feature_id == "block-spambots")
            {
                $this->check_enable_block_spambots_feature($item);
            }
            
            if($item->feature_id == "scan-file-change-detection")
            {
                $this->check_enable_fcd_scan_feature($item);
            }
            
        }
    }
    
    function calculate_total_points()
    {
        foreach($this->feature_items as $item)
        {
            if($item->feature_status == "active")
            {
                $this->total_points = $this->total_points + intval($item->item_points);
            }
        }
    }
    
    function get_total_site_points()
    {
        return $this->total_points;
    }
    
    function get_total_achievable_points()
    {
        foreach($this->feature_items as $item)
        {
            $this->total_achievable_points = $this->total_achievable_points + intval($item->item_points);
        }
        return $this->total_achievable_points;
    }
    
    function check_remove_wp_generator_meta_feature($item)
    {
        global $aio_wp_security;
        if ($aio_wp_security->configs->get_value('aiowps_remove_wp_generator_meta_info') == '1') {
            $item->set_feature_status($this->feature_active);
        }
        else
        {
            $item->set_feature_status($this->feature_inactive);
        }
    }

    function check_prevent_hotlinking_feature($item)
    {
        global $aio_wp_security;
        if ($aio_wp_security->configs->get_value('aiowps_prevent_hotlinking') == '1') {
            $item->set_feature_status($this->feature_active);
        }
        else
        {
            $item->set_feature_status($this->feature_inactive);
        }
    }

    function check_user_accounts_change_admin_user_feature($item)
    {
        if (AIOWPSecurity_Utility::check_user_exists('admin')) {
             $item->set_feature_status($this->feature_inactive);
        }
        else
        {
            $item->set_feature_status($this->feature_active);
        }
    }
   
    function check_user_accounts_display_name_feature($item)
    {
        if (AIOWPSecurity_Utility::check_identical_login_and_nick_names()) {
             $item->set_feature_status($this->feature_inactive);
        }
        else
        {
            $item->set_feature_status($this->feature_active);
        }
    }

    function check_login_lockdown_feature($item)
        {
        global $aio_wp_security;
        if ($aio_wp_security->configs->get_value('aiowps_enable_login_lockdown') == '1') {
            $item->set_feature_status($this->feature_active);
        }
        else
        {
            $item->set_feature_status($this->feature_inactive);
        }
    }
    
    function check_login_captcha_feature($item)
    {
        global $aio_wp_security;
        if ($aio_wp_security->configs->get_value('aiowps_enable_login_captcha') == '1') {
            $item->set_feature_status($this->feature_active);
        }
        else
        {
            $item->set_feature_status($this->feature_inactive);
        }
    }

    function check_custom_login_captcha_feature($item)
    {
        global $aio_wp_security;
        if ($aio_wp_security->configs->get_value('aiowps_enable_custom_login_captcha') == '1') {
            $item->set_feature_status($this->feature_active);
        }
        else
        {
            $item->set_feature_status($this->feature_inactive);
        }
    }

    function check_woo_login_captcha_feature($item)
    {
        global $aio_wp_security;
        if ($aio_wp_security->configs->get_value('aiowps_enable_woo_login_captcha') == '1') {
            $item->set_feature_status($this->feature_active);
        }
        else
        {
            $item->set_feature_status($this->feature_inactive);
        }
    }

    function check_woo_lostpassword_captcha_feature($item)
    {
        global $aio_wp_security;
        if ($aio_wp_security->configs->get_value('aiowps_enable_woo_lostpassword_captcha') == '1') {
            $item->set_feature_status($this->feature_active);
        }
        else
        {
            $item->set_feature_status($this->feature_inactive);
        }
    }
    
    function check_woo_register_captcha_feature($item)
    {
        global $aio_wp_security;
        if ($aio_wp_security->configs->get_value('aiowps_enable_woo_register_captcha') == '1') {
            $item->set_feature_status($this->feature_active);
        }
        else
        {
            $item->set_feature_status($this->feature_inactive);
        }
    }

    function check_lost_password_captcha_feature($item)
    {
        global $aio_wp_security;
        if ($aio_wp_security->configs->get_value('aiowps_enable_lost_password_captcha') == '1') {
            $item->set_feature_status($this->feature_active);
        }
        else
        {
            $item->set_feature_status($this->feature_inactive);
        }
    }

    function check_comment_captcha_feature($item)
    {
        global $aio_wp_security;
        if ($aio_wp_security->configs->get_value('aiowps_enable_comment_captcha') == '1') {
            $item->set_feature_status($this->feature_active);
        }
        else
        {
            $item->set_feature_status($this->feature_inactive);
        }
    }

    function check_bp_register_captcha_feature($item)
    {
        global $aio_wp_security;
        if ($aio_wp_security->configs->get_value('aiowps_enable_bp_register_captcha') == '1') {
            $item->set_feature_status($this->feature_active);
        }
        else
        {
            $item->set_feature_status($this->feature_inactive);
        }
    }

    function check_bbp_new_topic_captcha_feature($item)
    {
        global $aio_wp_security;
        if ($aio_wp_security->configs->get_value('aiowps_enable_bbp_new_topic_captcha') == '1') {
            $item->set_feature_status($this->feature_active);
        }
        else
        {
            $item->set_feature_status($this->feature_inactive);
        }
    }
    
    function check_login_whitelist_feature($item)
    {
        global $aio_wp_security;
        if ($aio_wp_security->configs->get_value('aiowps_enable_whitelisting') == '1') {
            $item->set_feature_status($this->feature_active);
        }
        else
        {
            $item->set_feature_status($this->feature_inactive);
        }
    }

    function check_force_logout_feature($item)
    {
        global $aio_wp_security;
        if ($aio_wp_security->configs->get_value('aiowps_enable_forced_logout') == '1') {
            $item->set_feature_status($this->feature_active);
        }
        else
        {
            $item->set_feature_status($this->feature_inactive);
        }
    }
    
    function check_registration_approval_feature($item)
    {
        global $aio_wp_security;
        if ($aio_wp_security->configs->get_value('aiowps_enable_manual_registration_approval') == '1') {
            $item->set_feature_status($this->feature_active);
        }
        else
        {
            $item->set_feature_status($this->feature_inactive);
        }
    }
    
    function check_registration_captcha_feature($item)
    {
        global $aio_wp_security;
        if ($aio_wp_security->configs->get_value('aiowps_enable_registration_page_captcha') == '1') {
            $item->set_feature_status($this->feature_active);
        }
        else
        {
            $item->set_feature_status($this->feature_inactive);
        }
    }
    
    function check_enable_registration_honeypot_feature($item)
    {
        global $aio_wp_security;
        if ($aio_wp_security->configs->get_value('aiowps_enable_registration_honeypot') == '1') {
            $item->set_feature_status($this->feature_active);
        }
        else
        {
            $item->set_feature_status($this->feature_inactive);
        }
    }
    
    function check_db_security_db_prefix_feature($item)
    {
        global $wpdb;
        if ($wpdb->prefix == 'wp_') {
             $item->set_feature_status($this->feature_inactive);
        }
        else
        {
            $item->set_feature_status($this->feature_active);
        }
    }
    
    function check_db_security_db_backup_feature($item)
    {
        global $aio_wp_security;
        if ($aio_wp_security->configs->get_value('aiowps_enable_automated_backups') == '1') {
            $item->set_feature_status($this->feature_active);
        }
        else
        {
            $item->set_feature_status($this->feature_inactive);
        }
    }

    function check_filesystem_permissions_feature($item)
    {
        //TODO
        $is_secure = 1;
        $util = new AIOWPSecurity_Utility_File;
        $files_dirs_to_check = $util->files_and_dirs_to_check;
        foreach ($files_dirs_to_check as $file_or_dir)
        {
            $actual_perm = AIOWPSecurity_Utility_File::get_file_permission($file_or_dir['path']);
            $is_secure = $is_secure*AIOWPSecurity_Utility_File::is_file_permission_secure($file_or_dir['permissions'], $actual_perm);
        }
        
        //Only if all of the files' permissions are deemed secure give this a thumbs up
        if ($is_secure == 1)
        {
            $item->set_feature_status($this->feature_active);
        }
        else 
        {
            $item->set_feature_status($this->feature_inactive);
        }
    }

    function check_filesystem_file_editing_feature($item)
    {
        global $aio_wp_security;
        if ($aio_wp_security->configs->get_value('aiowps_disable_file_editing') == '1') {
            $item->set_feature_status($this->feature_active);
        }
        else
        {
            $item->set_feature_status($this->feature_inactive);
        }
    }

    function check_block_wp_files_access_feature($item)
    {
        global $aio_wp_security;
        if ($aio_wp_security->configs->get_value('aiowps_prevent_default_wp_file_access') == '1') {
            $item->set_feature_status($this->feature_active);
        }
        else
        {
            $item->set_feature_status($this->feature_inactive);
        }
    }
    
    function check_enable_ip_useragent_blacklist_feature($item)
    {
        global $aio_wp_security;
        if ($aio_wp_security->configs->get_value('aiowps_enable_blacklisting') == '1') {
            $item->set_feature_status($this->feature_active);
        }
        else
        {
            $item->set_feature_status($this->feature_inactive);
        }
    }
    
    function check_enable_basic_firewall_feature($item)
    {
        global $aio_wp_security;
        if ($aio_wp_security->configs->get_value('aiowps_enable_basic_firewall') == '1') {
            $item->set_feature_status($this->feature_active);
        }
        else
        {
            $item->set_feature_status($this->feature_inactive);
        }
    }

    function check_enable_pingback_firewall_feature($item)
    {
        global $aio_wp_security;
        if ($aio_wp_security->configs->get_value('aiowps_enable_pingback_firewall') == '1') {
            $item->set_feature_status($this->feature_active);
        }
        else
        {
            $item->set_feature_status($this->feature_inactive);
        }
    }

    function check_debug_file_access_block_firewall_feature($item)
    {
        global $aio_wp_security;
        if ($aio_wp_security->configs->get_value('aiowps_block_debug_log_file_access') == '1') {
            $item->set_feature_status($this->feature_active);
        }
        else
        {
            $item->set_feature_status($this->feature_inactive);
        }
    }    
    
    function check_disable_trace_track_firewall_feature($item)
    {
        global $aio_wp_security;
        if ($aio_wp_security->configs->get_value('aiowps_disable_trace_and_track') == '1') {
            $item->set_feature_status($this->feature_active);
        }
        else
        {
            $item->set_feature_status($this->feature_inactive);
        }
    }

    function check_disable_index_views_firewall_feature($item)
    {
        global $aio_wp_security;
        if ($aio_wp_security->configs->get_value('aiowps_disable_index_views') == '1') {
            $item->set_feature_status($this->feature_active);
        }
        else
        {
            $item->set_feature_status($this->feature_inactive);
        }
    }

    function check_enable_bfap_firewall_feature($item)
    {
        global $aio_wp_security;
        if ($aio_wp_security->configs->get_value('aiowps_enable_brute_force_attack_prevention') == '1') {
            $item->set_feature_status($this->feature_active);
        }
        else
        {
            $item->set_feature_status($this->feature_inactive);
        }
    }

    function check_forbid_proxy_comments_firewall_feature($item)
    {
        global $aio_wp_security;
        if ($aio_wp_security->configs->get_value('aiowps_forbid_proxy_comments') == '1') {
            $item->set_feature_status($this->feature_active);
        }
        else
        {
            $item->set_feature_status($this->feature_inactive);
        }
    }

    function check_deny_bad_queries_firewall_feature($item)
    {
        global $aio_wp_security;
        if ($aio_wp_security->configs->get_value('aiowps_deny_bad_query_strings') == '1') {
            $item->set_feature_status($this->feature_active);
        }
        else
        {
            $item->set_feature_status($this->feature_inactive);
        }
    }

    function check_advanced_char_string_filter_firewall_feature($item)
    {
        global $aio_wp_security;
        if ($aio_wp_security->configs->get_value('aiowps_advanced_char_string_filter') == '1') {
            $item->set_feature_status($this->feature_active);
        }
        else
        {
            $item->set_feature_status($this->feature_inactive);
        }
    }

    function check_enable_5G_6G_blacklist_firewall_feature($item)
    {
        global $aio_wp_security;
        if ($aio_wp_security->configs->get_value('aiowps_enable_5g_firewall') == '1') {
            $item->set_feature_status($this->feature_active);
        }
        else if ($aio_wp_security->configs->get_value('aiowps_enable_6g_firewall') == '1') {
            $item->set_feature_status($this->feature_active);
        }
        else
        {
            $item->set_feature_status($this->feature_inactive);
        }
    }

    function check_block_fake_googlebots_firewall_feature($item)
    {
        global $aio_wp_security;
        if ($aio_wp_security->configs->get_value('aiowps_block_fake_googlebots') == '1') {
            $item->set_feature_status($this->feature_active);
        }
        else
        {
            $item->set_feature_status($this->feature_inactive);
        }
    }

    function check_enable_404_blocking_feature($item)
    {
        global $aio_wp_security;
        if ($aio_wp_security->configs->get_value('aiowps_enable_404_IP_lockout') == '1') {
            $item->set_feature_status($this->feature_active);
        }
        else
        {
            $item->set_feature_status($this->feature_inactive);
        }
    }
    
    function check_enable_rename_login_page_feature($item)
    {
        global $aio_wp_security;
        if ($aio_wp_security->configs->get_value('aiowps_enable_rename_login_page') == '1') {
            $item->set_feature_status($this->feature_active);
        }
        else
        {
            $item->set_feature_status($this->feature_inactive);
        }
    }

    function check_enable_login_honeypot_feature($item)
    {
        global $aio_wp_security;
        if ($aio_wp_security->configs->get_value('aiowps_enable_login_honeypot') == '1') {
            $item->set_feature_status($this->feature_active);
        }
        else
        {
            $item->set_feature_status($this->feature_inactive);
        }
    }

    function check_enable_block_spambots_feature($item)
    {
        global $aio_wp_security;
        if ($aio_wp_security->configs->get_value('aiowps_enable_spambot_blocking') == '1') {
            $item->set_feature_status($this->feature_active);
        }
        else
        {
            $item->set_feature_status($this->feature_inactive);
        }
    }
    
    function check_enable_fcd_scan_feature($item)
    {
        global $aio_wp_security;
        if ($aio_wp_security->configs->get_value('aiowps_enable_automated_fcd_scan') == '1') {
            $item->set_feature_status($this->feature_active);
        }
        else
        {
            $item->set_feature_status($this->feature_inactive);
        }
    }
    
}