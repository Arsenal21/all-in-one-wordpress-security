<?php
if(!defined('ABSPATH')){
    exit;//Exit if accessed directly
}

class AIOWPSecurity_Configure_Settings
{    
    function __construct(){
        
    }
    
    static function set_default_settings()
    {
        global $aio_wp_security;
        $blog_email_address = get_bloginfo('admin_email'); //Get the blog admin email address - we will use as the default value

        //Debug
        $aio_wp_security->configs->set_value('aiowps_enable_debug','');//Checkbox

        //WP Generator Meta Tag feature
        $aio_wp_security->configs->set_value('aiowps_remove_wp_generator_meta_info','');//Checkbox
        
        //Prevent Image Hotlinks
        $aio_wp_security->configs->set_value('aiowps_prevent_hotlinking','');//Checkbox
        //General Settings Page

        //User password feature
        
        //Lockdown feature
        $aio_wp_security->configs->set_value('aiowps_enable_login_lockdown','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_allow_unlock_requests','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_max_login_attempts','3');
        $aio_wp_security->configs->set_value('aiowps_retry_time_period','5');
        $aio_wp_security->configs->set_value('aiowps_lockout_time_length','60');
        $aio_wp_security->configs->set_value('aiowps_set_generic_login_msg','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_enable_email_notify','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_email_address',$blog_email_address);//text field
        $aio_wp_security->configs->set_value('aiowps_enable_forced_logout','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_logout_time_period','60');
        $aio_wp_security->configs->set_value('aiowps_enable_invalid_username_lockdown','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_instantly_lockout_specific_usernames', array()); // Textarea (list of strings)
        $aio_wp_security->configs->set_value('aiowps_unlock_request_secret_key',AIOWPSecurity_Utility::generate_alpha_numeric_random_string(20));//Hidden secret value which will be used to do some unlock request processing. This will be assigned a random string generated when lockdown settings saved
        $aio_wp_security->configs->set_value('aiowps_lockdown_enable_whitelisting','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_lockdown_allowed_ip_addresses','');

        //Captcha feature
        $aio_wp_security->configs->set_value('aiowps_enable_login_captcha','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_enable_custom_login_captcha','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_enable_woo_login_captcha','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_enable_woo_register_captcha','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_enable_lost_password_captcha','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_captcha_secret_key',AIOWPSecurity_Utility::generate_alpha_numeric_random_string(20));//Hidden secret value which will be used to do some captcha processing. This will be assigned a random string generated when captcha settings saved

        //Login Whitelist feature
        $aio_wp_security->configs->set_value('aiowps_enable_whitelisting','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_allowed_ip_addresses','');

        //User registration
        $aio_wp_security->configs->set_value('aiowps_enable_manual_registration_approval','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_enable_registration_page_captcha','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_enable_registration_honeypot','');//Checkbox
        
        //DB Security feature
        //$aio_wp_security->configs->set_value('aiowps_new_manual_db_pefix',''); //text field
        $aio_wp_security->configs->set_value('aiowps_enable_random_prefix','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_enable_automated_backups','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_db_backup_frequency','4');
        $aio_wp_security->configs->set_value('aiowps_db_backup_interval','2'); //Dropdown box where (0,1,2) => (hours,days,weeks)
        $aio_wp_security->configs->set_value('aiowps_backup_files_stored','2');
        $aio_wp_security->configs->set_value('aiowps_send_backup_email_address','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_backup_email_address',$blog_email_address);
        
        //Filesystem Security feature
        $aio_wp_security->configs->set_value('aiowps_disable_file_editing','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_prevent_default_wp_file_access','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_system_log_file','error_log');

        //Blacklist feature
        $aio_wp_security->configs->set_value('aiowps_enable_blacklisting','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_banned_ip_addresses','');

        //Firewall features
        $aio_wp_security->configs->set_value('aiowps_enable_basic_firewall','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_enable_pingback_firewall','');//Checkbox - blocks all access to XMLRPC
        $aio_wp_security->configs->set_value('aiowps_disable_xmlrpc_pingback_methods','');//Checkbox - Disables only pingback methods in XMLRPC functionality
        $aio_wp_security->configs->set_value('aiowps_block_debug_log_file_access','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_disable_index_views','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_disable_trace_and_track','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_forbid_proxy_comments','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_deny_bad_query_strings','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_advanced_char_string_filter','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_enable_5g_firewall','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_enable_6g_firewall','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_enable_custom_rules','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_place_custom_rules_at_top','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_custom_rules','');
        
        //404 detection
        $aio_wp_security->configs->set_value('aiowps_enable_404_logging','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_enable_404_IP_lockout','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_404_lockout_time_length','60');
        $aio_wp_security->configs->set_value('aiowps_404_lock_redirect_url','http://127.0.0.1');

        //Brute Force features
        $aio_wp_security->configs->set_value('aiowps_enable_rename_login_page','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_enable_login_honeypot','');//Checkbox

        $aio_wp_security->configs->set_value('aiowps_enable_brute_force_attack_prevention','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_brute_force_secret_word','');
        $aio_wp_security->configs->set_value('aiowps_cookie_brute_test','');
        $aio_wp_security->configs->set_value('aiowps_cookie_based_brute_force_redirect_url','http://127.0.0.1');
        $aio_wp_security->configs->set_value('aiowps_brute_force_attack_prevention_pw_protected_exception','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_brute_force_attack_prevention_ajax_exception','');//Checkbox

        //Maintenance menu - Visitor lockout feature
        $aio_wp_security->configs->set_value('aiowps_site_lockout','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_site_lockout_msg','');//Text area/msg box

        //SPAM Prevention menu
        $aio_wp_security->configs->set_value('aiowps_enable_spambot_blocking','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_enable_comment_captcha','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_enable_autoblock_spam_ip','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_spam_ip_min_comments_block','');
        $aio_wp_security->configs->set_value('aiowps_enable_bp_register_captcha','');
        $aio_wp_security->configs->set_value('aiowps_enable_bbp_new_topic_captcha','');//Checkbox
        
        //Filescan features
        //File change detection feature
        $aio_wp_security->configs->set_value('aiowps_enable_automated_fcd_scan','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_fcd_scan_frequency','4');
        $aio_wp_security->configs->set_value('aiowps_fcd_scan_interval','2'); //Dropdown box where (0,1,2) => (hours,days,weeks)
        $aio_wp_security->configs->set_value('aiowps_fcd_exclude_filetypes','');
        $aio_wp_security->configs->set_value('aiowps_fcd_exclude_files','');
        $aio_wp_security->configs->set_value('aiowps_send_fcd_scan_email','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_fcd_scan_email_address',$blog_email_address);
        $aio_wp_security->configs->set_value('aiowps_fcds_change_detected', FALSE); //used to display a global alert on site when file change detected

        //Misc Options
        //Copy protection feature
        $aio_wp_security->configs->set_value('aiowps_copy_protection','');//Checkbox
        //Prevent others from dislaying your site in iframe
        $aio_wp_security->configs->set_value('aiowps_prevent_site_display_inside_frame','');//Checkbox
       //Prevent users enumeration
        $aio_wp_security->configs->set_value('aiowps_prevent_users_enumeration','');//Checkbox

       //REST API Security
        $aio_wp_security->configs->set_value('aiowps_disallow_unauthorized_rest_requests','');//Checkbox
        
        //IP retrieval setting
        $aio_wp_security->configs->set_value('aiowps_ip_retrieve_method','0');//default is $_SERVER['REMOTE_ADDR']
                
        //TODO - keep adding default options for any fields that require it
        
        //Save it
        $aio_wp_security->configs->save_config();
    }
    
    static function add_option_values()
    {
        global $aio_wp_security;
        $blog_email_address = get_bloginfo('admin_email'); //Get the blog admin email address - we will use as the default value

        //Debug
        $aio_wp_security->configs->add_value('aiowps_enable_debug','');//Checkbox

        //WP Generator Meta Tag feature
        $aio_wp_security->configs->add_value('aiowps_remove_wp_generator_meta_info','');//Checkbox
        
        //Prevent Image Hotlinks
        $aio_wp_security->configs->add_value('aiowps_prevent_hotlinking','');//Checkbox
        
        //General Settings Page
        
        //User password feature
        
        //Lockdown feature
        $aio_wp_security->configs->add_value('aiowps_enable_login_lockdown','');//Checkbox
        $aio_wp_security->configs->add_value('aiowps_allow_unlock_requests','');//Checkbox
        $aio_wp_security->configs->add_value('aiowps_max_login_attempts','3');
        $aio_wp_security->configs->add_value('aiowps_retry_time_period','5');
        $aio_wp_security->configs->add_value('aiowps_lockout_time_length','60');
        $aio_wp_security->configs->add_value('aiowps_set_generic_login_msg','');//Checkbox
        $aio_wp_security->configs->add_value('aiowps_enable_email_notify','');//Checkbox
        $aio_wp_security->configs->add_value('aiowps_email_address',$blog_email_address);//text field
        $aio_wp_security->configs->add_value('aiowps_enable_forced_logout','');//Checkbox
        $aio_wp_security->configs->add_value('aiowps_logout_time_period','60');
        $aio_wp_security->configs->add_value('aiowps_enable_invalid_username_lockdown','');//Checkbox
        $aio_wp_security->configs->add_value('aiowps_instantly_lockout_specific_usernames', array()); // Textarea (list of strings)
        $aio_wp_security->configs->add_value('aiowps_unlock_request_secret_key',AIOWPSecurity_Utility::generate_alpha_numeric_random_string(20));//Hidden secret value which will be used to do some unlock request processing. This will be assigned a random string generated when lockdown settings saved
        $aio_wp_security->configs->add_value('aiowps_lockdown_enable_whitelisting','');//Checkbox
        $aio_wp_security->configs->add_value('aiowps_lockdown_allowed_ip_addresses','');
        
        //Login Whitelist feature
        $aio_wp_security->configs->add_value('aiowps_enable_whitelisting','');//Checkbox
        $aio_wp_security->configs->add_value('aiowps_allowed_ip_addresses','');
        //Captcha feature
        $aio_wp_security->configs->add_value('aiowps_enable_login_captcha','');//Checkbox
        $aio_wp_security->configs->add_value('aiowps_enable_custom_login_captcha','');//Checkbox
        $aio_wp_security->configs->add_value('aiowps_enable_woo_login_captcha','');//Checkbox
        $aio_wp_security->configs->add_value('aiowps_enable_woo_register_captcha','');//Checkbox
        $aio_wp_security->configs->add_value('aiowps_captcha_secret_key',AIOWPSecurity_Utility::generate_alpha_numeric_random_string(20));//Hidden secret value which will be used to do some captcha processing. This will be assigned a random string generated when captcha settings saved

        //User registration
        $aio_wp_security->configs->add_value('aiowps_enable_manual_registration_approval','');//Checkbox
        $aio_wp_security->configs->add_value('aiowps_enable_registration_page_captcha','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_enable_registration_honeypot','');//Checkbox
       
        //DB Security feature
        //$aio_wp_security->configs->add_value('aiowps_new_manual_db_pefix',''); //text field
        $aio_wp_security->configs->add_value('aiowps_enable_random_prefix','');//Checkbox
        $aio_wp_security->configs->add_value('aiowps_enable_automated_backups','');//Checkbox
        $aio_wp_security->configs->add_value('aiowps_db_backup_frequency','4');
        $aio_wp_security->configs->add_value('aiowps_db_backup_interval','2'); //Dropdown box where (0,1,2) => (hours,days,weeks)
        $aio_wp_security->configs->add_value('aiowps_backup_files_stored','2');
        $aio_wp_security->configs->add_value('aiowps_send_backup_email_address','');//Checkbox
        $aio_wp_security->configs->add_value('aiowps_backup_email_address',$blog_email_address);
        
        //Filesystem Security feature
        $aio_wp_security->configs->add_value('aiowps_disable_file_editing','');//Checkbox
        $aio_wp_security->configs->add_value('aiowps_prevent_default_wp_file_access','');//Checkbox
        $aio_wp_security->configs->add_value('aiowps_system_log_file','error_log');


        //Blacklist feature
        $aio_wp_security->configs->add_value('aiowps_enable_blacklisting','');//Checkbox
        $aio_wp_security->configs->add_value('aiowps_banned_ip_addresses','');

        //Firewall features
        $aio_wp_security->configs->add_value('aiowps_enable_basic_firewall','');//Checkbox
        $aio_wp_security->configs->add_value('aiowps_enable_pingback_firewall','');//Checkbox - blocks all access to XMLRPC
        $aio_wp_security->configs->add_value('aiowps_disable_xmlrpc_pingback_methods','');//Checkbox - Disables only pingback methods in XMLRPC functionality
        $aio_wp_security->configs->add_value('aiowps_block_debug_log_file_access','');//Checkbox
        $aio_wp_security->configs->add_value('aiowps_disable_index_views','');//Checkbox
        $aio_wp_security->configs->add_value('aiowps_disable_trace_and_track','');//Checkbox
        $aio_wp_security->configs->add_value('aiowps_forbid_proxy_comments','');//Checkbox
        $aio_wp_security->configs->add_value('aiowps_deny_bad_query_strings','');//Checkbox
        $aio_wp_security->configs->add_value('aiowps_advanced_char_string_filter','');//Checkbox
        $aio_wp_security->configs->add_value('aiowps_enable_5g_firewall','');//Checkbox
        $aio_wp_security->configs->add_value('aiowps_enable_6g_firewall','');//Checkbox
        $aio_wp_security->configs->add_value('aiowps_enable_custom_rules','');//Checkbox
        $aio_wp_security->configs->add_value('aiowps_place_custom_rules_at_top','');//Checkbox
        $aio_wp_security->configs->add_value('aiowps_custom_rules','');

        //404 detection
        $aio_wp_security->configs->add_value('aiowps_enable_404_logging','');//Checkbox
        $aio_wp_security->configs->add_value('aiowps_enable_404_IP_lockout','');//Checkbox
        $aio_wp_security->configs->add_value('aiowps_404_lockout_time_length','60');
        $aio_wp_security->configs->add_value('aiowps_404_lock_redirect_url','http://127.0.0.1');
        
        //Brute Force features
        $aio_wp_security->configs->add_value('aiowps_enable_rename_login_page','');//Checkbox
        $aio_wp_security->configs->add_value('aiowps_enable_login_honeypot','');//Checkbox
        
        $aio_wp_security->configs->add_value('aiowps_enable_brute_force_attack_prevention','');//Checkbox
        $aio_wp_security->configs->add_value('aiowps_brute_force_secret_word','');
        $aio_wp_security->configs->add_value('aiowps_cookie_brute_test','');
        $aio_wp_security->configs->add_value('aiowps_cookie_based_brute_force_redirect_url','http://127.0.0.1');
        $aio_wp_security->configs->add_value('aiowps_brute_force_attack_prevention_pw_protected_exception','');//Checkbox
        $aio_wp_security->configs->add_value('aiowps_brute_force_attack_prevention_ajax_exception','');//Checkbox
        
        //Maintenance menu - Visitor lockout feature
        $aio_wp_security->configs->add_value('aiowps_site_lockout','');//Checkbox
        $aio_wp_security->configs->add_value('aiowps_site_lockout_msg','');//Text area/msg box

        //SPAM Prevention menu
        $aio_wp_security->configs->add_value('aiowps_enable_spambot_blocking','');//Checkbox
        $aio_wp_security->configs->add_value('aiowps_enable_comment_captcha','');//Checkbox
        $aio_wp_security->configs->add_value('aiowps_enable_autoblock_spam_ip','');//Checkbox
        $aio_wp_security->configs->add_value('aiowps_spam_ip_min_comments_block','');
        $aio_wp_security->configs->add_value('aiowps_enable_bp_register_captcha','');
        $aio_wp_security->configs->add_value('aiowps_enable_bbp_new_topic_captcha','');//Checkbox


        //Filescan features
        //File change detection feature
        $aio_wp_security->configs->add_value('aiowps_enable_automated_fcd_scan','');//Checkbox
        $aio_wp_security->configs->add_value('aiowps_fcd_scan_frequency','4');
        $aio_wp_security->configs->add_value('aiowps_fcd_scan_interval','2'); //Dropdown box where (0,1,2) => (hours,days,weeks)
        $aio_wp_security->configs->add_value('aiowps_fcd_exclude_filetypes','');
        $aio_wp_security->configs->add_value('aiowps_fcd_exclude_files','');
        $aio_wp_security->configs->add_value('aiowps_send_fcd_scan_email','');//Checkbox
        $aio_wp_security->configs->add_value('aiowps_fcd_scan_email_address',$blog_email_address);
        $aio_wp_security->configs->add_value('aiowps_fcds_change_detected',FALSE); //used to display a global alert on site when file change detected
        
        //Misc Options
        //Copy protection feature
        $aio_wp_security->configs->add_value('aiowps_copy_protection','');//Checkbox
        //Prevent others from dislaying your site in iframe
        $aio_wp_security->configs->add_value('aiowps_prevent_site_display_inside_frame','');//Checkbox
        //Prevent users enumeration
        $aio_wp_security->configs->add_value('aiowps_prevent_users_enumeration','');//Checkbox

       //REST API Security
        $aio_wp_security->configs->add_value('aiowps_disallow_unauthorized_rest_requests','');//Checkbox
        
        //IP retrieval setting
        $aio_wp_security->configs->add_value('aiowps_ip_retrieve_method','0');//default is $_SERVER['REMOTE_ADDR']
        
        //TODO - keep adding default options for any fields that require it
        
        //Save it
        $aio_wp_security->configs->save_config();
    }

    static function turn_off_all_security_features()
    {
        global $aio_wp_security;
        AIOWPSecurity_Configure_Settings::set_default_settings();
        
        //Refresh the .htaccess file based on the new settings
        $res = AIOWPSecurity_Utility_Htaccess::write_to_htaccess();
        if( !$res )
        {
            $aio_wp_security->debug_logger->log_debug(__METHOD__ . " - Could not write to the .htaccess file. Please check the file permissions.",4);
        }
    }
    
    static function turn_off_all_firewall_rules()
    {
        global $aio_wp_security;
        $aio_wp_security->configs->set_value('aiowps_enable_blacklisting','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_enable_whitelisting','');//Checkbox
        
        $aio_wp_security->configs->set_value('aiowps_enable_basic_firewall','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_enable_pingback_firewall','');//Checkbox - blocks all access to XMLRPC
        $aio_wp_security->configs->set_value('aiowps_disable_xmlrpc_pingback_methods','');//Checkbox - Disables only pingback methods in XMLRPC functionality
        $aio_wp_security->configs->set_value('aiowps_block_debug_log_file_access','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_disable_index_views','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_disable_trace_and_track','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_forbid_proxy_comments','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_deny_bad_query_strings','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_advanced_char_string_filter','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_enable_5g_firewall','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_enable_6g_firewall','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_enable_brute_force_attack_prevention','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_enable_custom_rules','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_place_custom_rules_at_top','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_custom_rules','');

        $aio_wp_security->configs->set_value('aiowps_prevent_default_wp_file_access','');//Checkbox
        
        $aio_wp_security->configs->set_value('aiowps_enable_spambot_blocking','');//Checkbox
        
        //404 detection
        $aio_wp_security->configs->set_value('aiowps_enable_404_logging','');//Checkbox
        $aio_wp_security->configs->set_value('aiowps_enable_404_IP_lockout','');//Checkbox
        
        //Prevent Image Hotlinks
        $aio_wp_security->configs->set_value('aiowps_prevent_hotlinking','');//Checkbox
        
        $aio_wp_security->configs->save_config();
        
        //Refresh the .htaccess file based on the new settings
        $res = AIOWPSecurity_Utility_Htaccess::write_to_htaccess();

        if( !$res )
        {
            $aio_wp_security->debug_logger->log_debug(__METHOD__ . " - Could not write to the .htaccess file. Please check the file permissions.",4);
        }
    }

}
