<?php
/* 
 * Inits the admin dashboard side of things.
 * Main admin file which loads all settings panels and sets up admin menus. 
 */
if(!defined('ABSPATH')){
    exit;//Exit if accessed directly
}

class AIOWPSecurity_Admin_Init
{
    var $main_menu_page;
    var $dashboard_menu;
    var $settings_menu;
    var $user_accounts_menu;
    var $user_login_menu;
    var $user_registration_menu;
    var $db_security_menu;
    var $filesystem_menu;
    var $blacklist_menu;
    var $firewall_menu;
    var $brute_force_menu;
    var $maintenance_menu;
    var $spam_menu;
    var $filescan_menu;
    var $misc_menu;

    function __construct() {
        //This class is only initialized if is_admin() is true
        $this->admin_includes();
        add_action('admin_menu', array(&$this, 'create_admin_menus'));
        //handle CSV download
        add_action('admin_init', array(&$this, 'aiowps_csv_download'));

        //make sure we are on our plugin's menu pages
        if (isset($_GET['page']) && strpos($_GET['page'], AIOWPSEC_MENU_SLUG_PREFIX) !== false) {
            add_action('admin_print_scripts', array(&$this, 'admin_menu_page_scripts'));
            add_action('admin_print_styles', array(&$this, 'admin_menu_page_styles'));
            add_action('init', array(&$this, 'init_hook_handler_for_admin_side'));
        }
    }

    private function aiowps_output_csv($items, $export_keys, $filename='data.csv') {
        header("Content-Type: text/csv; charset=utf-8");
        header("Content-Disposition: attachment; filename=".$filename);
        header("Pragma: no-cache");
        header("Expires: 0");
        $output = fopen('php://output', 'w'); //open output stream

        fputcsv($output, $export_keys); //let's put column names first

        foreach ($items as $item) {
            unset($csv_line);
            foreach ($export_keys as $key => $value) {
                if (isset($item[$key])) {
                    $csv_line[] = $item[$key];
                }
            }
            fputcsv($output, $csv_line);
        }
    }

    function aiowps_csv_download() {
        global $aio_wp_security;
        if (isset($_POST['aiowpsec_export_acct_activity_logs_to_csv'])) { //Export account activity logs
            $nonce = $_REQUEST['_wpnonce'];
            if (!wp_verify_nonce($nonce, 'aiowpsec-export-acct-activity-logs-to-csv-nonce')) {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed for export account activity logs to CSV!", 4);
                die(__('Nonce check failed for export account activity logs to CSV!', 'all-in-one-wp-security-and-firewall'));
            }
            include_once 'wp-security-list-acct-activity.php';
            $acct_activity_list = new AIOWPSecurity_List_Account_Activity();
            $acct_activity_list->prepare_items(true);
            //Let's build a list of items we want to export and give them readable names
            $export_keys = array(
                'user_id' => 'User ID',
                'user_login' => 'Username',
                'login_date' => 'Login Date',
                'logout_date' => 'Logout Date',
                'login_ip' => 'IP'
            );
            $this->aiowps_output_csv($acct_activity_list->items, $export_keys, 'account_activity_logs.csv');
            exit();
        }
        if (isset($_POST['aiowps_export_failed_login_records_to_csv'])) {//Export failed login records
            $nonce = $_REQUEST['_wpnonce'];
            if (!wp_verify_nonce($nonce, 'aiowpsec-export-failed-login-records-to-csv-nonce')) {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed for export failed login records to CSV!", 4);
                die(__('Nonce check failed for export failed login records to CSV!', 'all-in-one-wp-security-and-firewall'));
            }
            include_once 'wp-security-list-login-fails.php';
            $failed_login_list = new AIOWPSecurity_List_Login_Failed_Attempts();
            $failed_login_list->prepare_items(true);
            $export_keys = array(
                'login_attempt_ip' => 'Login IP Range',
                'user_id' => 'User ID',
                'user_login' => 'Username',
                'failed_login_date' => 'Date',
            );
            $this->aiowps_output_csv($failed_login_list->items, $export_keys, 'failed_login_records.csv');
            exit();
        }
        if (isset($_POST['aiowps_export_404_event_logs_to_csv'])) {//Export 404 event logs
            $nonce = $_REQUEST['_wpnonce'];
            if (!wp_verify_nonce($nonce, 'aiowpsec-export-404-event-logs-to-csv-nonce')) {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed for export 404 event logs to CSV!", 4);
                die(__('Nonce check failed for export 404 event logs to CSV!', 'all-in-one-wp-security-and-firewall'));
            }
            include_once 'wp-security-list-404.php'; //For rendering the AIOWPSecurity_List_Table in tab1
            $event_list_404 = new AIOWPSecurity_List_404(); //For rendering the AIOWPSecurity_List_Table in tab1
            $event_list_404->prepare_items(true);
            $export_keys = array(
                'id' => 'Id',
                'event_type' => 'Event Type',
                'ip_or_host' => 'IP Address',
                'url' => 'Attempted URL',
                'referer_info' => 'Referer',
                'event_date' => 'Date',
                'status' => 'Lock Status',
            );
            $this->aiowps_output_csv($event_list_404->items, $export_keys, '404_event_logs.csv');
            exit();
        }
    }

    function admin_includes()
    {
        include_once('wp-security-admin-menu.php');
    }

    function admin_menu_page_scripts() 
    {
        wp_enqueue_script('jquery');
        wp_enqueue_script('postbox');
        wp_enqueue_script('dashboard');
        wp_enqueue_script('thickbox');
        wp_enqueue_script('media-upload');
        wp_register_script('aiowpsec-admin-js', AIO_WP_SECURITY_URL. '/js/wp-security-admin-script.js', array('jquery'));
        wp_enqueue_script('aiowpsec-admin-js');
        wp_register_script('aiowpsec-pw-tool-js', AIO_WP_SECURITY_URL. '/js/password-strength-tool.js', array('jquery')); // We will enqueue this in the user acct menu class
    }
    
    function admin_menu_page_styles() 
    {
        wp_enqueue_style('dashboard');
        wp_enqueue_style('thickbox');
        wp_enqueue_style('global');
        wp_enqueue_style('wp-admin');
        wp_enqueue_style('aiowpsec-admin-css', AIO_WP_SECURITY_URL. '/css/wp-security-admin-styles.css');
    }
    
    function init_hook_handler_for_admin_side()
    {
        $this->aiowps_media_uploader_modification();
        $this->initialize_feature_manager();
        $this->do_other_admin_side_init_tasks();
    }

    function aiowps_media_uploader_modification()
    {
        //For changing button text inside media uploader (thickbox)
        global $pagenow;
        if ('media-upload.php' == $pagenow || 'async-upload.php' == $pagenow)
        {
            // Here we will customize the 'Insert into Post' Button text inside Thickbox
            add_filter( 'gettext', array($this, 'aiowps_media_uploader_replace_thickbox_text'), 1, 2);
        }
    }

    function aiowps_media_uploader_replace_thickbox_text($translated_text, $text)
    {
        if ('Insert into Post' == $text)
        {
            $referer = strpos(wp_get_referer(), 'aiowpsec');
            if ($referer != '')
            {
                return ('Select File');
            }
        }
        return $translated_text;
    }

    function initialize_feature_manager()
    {
        $aiowps_feature_mgr  = new AIOWPSecurity_Feature_Item_Manager();
        $aiowps_feature_mgr->initialize_features();
        $aiowps_feature_mgr->check_and_set_feature_status();
        $aiowps_feature_mgr->calculate_total_points(); 
        $GLOBALS['aiowps_feature_mgr'] = $aiowps_feature_mgr;
    }
    
    function do_other_admin_side_init_tasks()
    {
        global $aio_wp_security;
        
        //***New Feature improvement for Cookie Based Brute Force Protection***//
        //The old "test cookie" used to be too easy to guess because someone could just read the code and get the value. 
        //So now we will drop a more secure test cookie using a 10 digit random string

        if($aio_wp_security->configs->get_value('aiowps_enable_brute_force_attack_prevention')=='1'){
            // This code is for users who had this feature saved using an older release. This will drop the new more secure test cookie to the browser and will write it to the .htaccess file too
            $test_cookie = $aio_wp_security->configs->get_value('aiowps_cookie_brute_test');
            if(empty($test_cookie)){
                $random_suffix = AIOWPSecurity_Utility::generate_alpha_numeric_random_string(10);
                $test_cookie_name = 'aiowps_cookie_test_'.$random_suffix;
                $aio_wp_security->configs->set_value('aiowps_cookie_brute_test',$test_cookie_name);
                $aio_wp_security->configs->save_config();//save the value
                AIOWPSecurity_Utility::set_cookie_value($test_cookie_name, "1");

                //Write this new cookie to the .htaccess file
                $res = AIOWPSecurity_Utility_Htaccess::write_to_htaccess();
                if( !$res ){
                    $aio_wp_security->debug_logger->log_debug("Error writing new test cookie with random suffix to .htaccess file!",4);
                }

            }
        }
        //For cookie test form submission case
        if (isset($_GET['page']) && $_GET['page'] == AIOWPSEC_BRUTE_FORCE_MENU_SLUG && isset($_GET['tab']) && $_GET['tab'] == 'tab2')
        {
            global $aio_wp_security;
            if(isset($_POST['aiowps_do_cookie_test_for_bfla'])){
                $random_suffix = AIOWPSecurity_Utility::generate_alpha_numeric_random_string(10);
                $test_cookie_name = 'aiowps_cookie_test_'.$random_suffix;
                $aio_wp_security->configs->set_value('aiowps_cookie_brute_test',$test_cookie_name);
                $aio_wp_security->configs->save_config();//save the value
                AIOWPSecurity_Utility::set_cookie_value($test_cookie_name, "1");
                $cur_url = "admin.php?page=".AIOWPSEC_BRUTE_FORCE_MENU_SLUG."&tab=tab2";
                $redirect_url = AIOWPSecurity_Utility::add_query_data_to_url($cur_url, 'aiowps_cookie_test', "1");
                AIOWPSecurity_Utility::redirect_to_url($redirect_url);
            }
            
            if(isset($_POST['aiowps_enable_brute_force_attack_prevention']))//Enabling the BFLA feature so drop the cookie again
            {
                $brute_force_feature_secret_word = sanitize_text_field($_POST['aiowps_brute_force_secret_word']);
                if(empty($brute_force_feature_secret_word)){
                    $brute_force_feature_secret_word = "aiowps_secret";
                }
                AIOWPSecurity_Utility::set_cookie_value($brute_force_feature_secret_word, "1");
            }

            if(isset($_REQUEST['aiowps_cookie_test']))
            {
                $test_cookie = $aio_wp_security->configs->get_value('aiowps_cookie_brute_test');
                $cookie_val = AIOWPSecurity_Utility::get_cookie_value($test_cookie);
                if(empty($cookie_val))
                {
                    $aio_wp_security->configs->set_value('aiowps_cookie_test_success','');
                }
                else
                {
                    $aio_wp_security->configs->set_value('aiowps_cookie_test_success','1');
                }
                $aio_wp_security->configs->save_config();//save the value
            }
        }

        if(isset($_POST['aiowps_save_wp_config']))//the wp-config backup operation
        {
            $nonce=$_REQUEST['_wpnonce'];
            if (!wp_verify_nonce($nonce, 'aiowpsec-save-wp-config-nonce'))
            {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed on wp_config file save!",4);
                die("Nonce check failed on wp_config file save!");
            }
            $wp_config_path = AIOWPSecurity_Utility_File::get_wp_config_file_path();
            $result = AIOWPSecurity_Utility_File::backup_and_rename_wp_config($wp_config_path); //Backup the wp_config.php file
            AIOWPSecurity_Utility_File::download_a_file_option1($wp_config_path, "wp-config-backup.txt");
        }
        
        //Handle export settings
        if(isset($_POST['aiowps_export_settings']))//Do form submission tasks
        {
            $nonce=$_REQUEST['_wpnonce'];
            if (!wp_verify_nonce($nonce, 'aiowpsec-export-settings-nonce'))
            {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed on export AIOWPS settings!",4);
                die("Nonce check failed on export AIOWPS settings!");
            }
            $config_data = get_option('aio_wp_security_configs');
            $output = json_encode($config_data);
            AIOWPSecurity_Utility_File::download_content_to_a_file($output);            
        }
        
    }
    
    function create_admin_menus()
    {
        $menu_icon_url = AIO_WP_SECURITY_URL.'/images/plugin-icon.png';
        $this->main_menu_page = add_menu_page(__('WP Security', 'all-in-one-wp-security-and-firewall'), __('WP Security', 'all-in-one-wp-security-and-firewall'), AIOWPSEC_MANAGEMENT_PERMISSION, AIOWPSEC_MAIN_MENU_SLUG , array(&$this, 'handle_dashboard_menu_rendering'), $menu_icon_url);
        add_submenu_page(AIOWPSEC_MAIN_MENU_SLUG, __('Dashboard', 'all-in-one-wp-security-and-firewall'),  __('Dashboard', 'all-in-one-wp-security-and-firewall') , AIOWPSEC_MANAGEMENT_PERMISSION, AIOWPSEC_MAIN_MENU_SLUG, array(&$this, 'handle_dashboard_menu_rendering'));
        add_submenu_page(AIOWPSEC_MAIN_MENU_SLUG, __('Settings', 'all-in-one-wp-security-and-firewall'),  __('Settings', 'all-in-one-wp-security-and-firewall') , AIOWPSEC_MANAGEMENT_PERMISSION, AIOWPSEC_SETTINGS_MENU_SLUG, array(&$this, 'handle_settings_menu_rendering'));
        add_submenu_page(AIOWPSEC_MAIN_MENU_SLUG, __('User Accounts', 'all-in-one-wp-security-and-firewall'),  __('User Accounts', 'all-in-one-wp-security-and-firewall') , AIOWPSEC_MANAGEMENT_PERMISSION, AIOWPSEC_USER_ACCOUNTS_MENU_SLUG, array(&$this, 'handle_user_accounts_menu_rendering'));
        add_submenu_page(AIOWPSEC_MAIN_MENU_SLUG, __('User Login', 'all-in-one-wp-security-and-firewall'),  __('User Login', 'all-in-one-wp-security-and-firewall') , AIOWPSEC_MANAGEMENT_PERMISSION, AIOWPSEC_USER_LOGIN_MENU_SLUG, array(&$this, 'handle_user_login_menu_rendering'));
        add_submenu_page(AIOWPSEC_MAIN_MENU_SLUG, __('User Registration', 'all-in-one-wp-security-and-firewall'),  __('User Registration', 'all-in-one-wp-security-and-firewall') , AIOWPSEC_MANAGEMENT_PERMISSION, AIOWPSEC_USER_REGISTRATION_MENU_SLUG, array(&$this, 'handle_user_registration_menu_rendering'));
        add_submenu_page(AIOWPSEC_MAIN_MENU_SLUG, __('Database Security', 'all-in-one-wp-security-and-firewall'),  __('Database Security', 'all-in-one-wp-security-and-firewall') , AIOWPSEC_MANAGEMENT_PERMISSION, AIOWPSEC_DB_SEC_MENU_SLUG, array(&$this, 'handle_database_menu_rendering'));
        if (AIOWPSecurity_Utility::is_multisite_install() && get_current_blog_id() != 1){
            //Suppress the Filesystem Security menu if site is a multi site AND not the main site
        }else{
            add_submenu_page(AIOWPSEC_MAIN_MENU_SLUG, __('Filesystem Security', 'all-in-one-wp-security-and-firewall'),  __('Filesystem Security', 'all-in-one-wp-security-and-firewall') , AIOWPSEC_MANAGEMENT_PERMISSION, AIOWPSEC_FILESYSTEM_MENU_SLUG, array(&$this, 'handle_filesystem_menu_rendering'));
        }
        if (AIOWPSecurity_Utility::is_multisite_install() && get_current_blog_id() != 1){
            //Suppress the Blacklist Manager menu if site is a multi site AND not the main site
        }else{
            add_submenu_page(AIOWPSEC_MAIN_MENU_SLUG, __('Blacklist Manager', 'all-in-one-wp-security-and-firewall'),  __('Blacklist Manager', 'all-in-one-wp-security-and-firewall') , AIOWPSEC_MANAGEMENT_PERMISSION, AIOWPSEC_BLACKLIST_MENU_SLUG, array(&$this, 'handle_blacklist_menu_rendering'));
        }
        if (AIOWPSecurity_Utility::is_multisite_install() && get_current_blog_id() != 1){
            //Suppress the firewall menu if site is a multi site AND not the main site
        }else{
            add_submenu_page(AIOWPSEC_MAIN_MENU_SLUG, __('Firewall', 'all-in-one-wp-security-and-firewall'),  __('Firewall', 'all-in-one-wp-security-and-firewall') , AIOWPSEC_MANAGEMENT_PERMISSION, AIOWPSEC_FIREWALL_MENU_SLUG, array(&$this, 'handle_firewall_menu_rendering'));
        }
        add_submenu_page(AIOWPSEC_MAIN_MENU_SLUG, __('Brute Force', 'all-in-one-wp-security-and-firewall'),  __('Brute Force', 'all-in-one-wp-security-and-firewall') , AIOWPSEC_MANAGEMENT_PERMISSION, AIOWPSEC_BRUTE_FORCE_MENU_SLUG, array(&$this, 'handle_brute_force_menu_rendering'));
        add_submenu_page(AIOWPSEC_MAIN_MENU_SLUG, __('SPAM Prevention', 'all-in-one-wp-security-and-firewall'),  __('SPAM Prevention', 'all-in-one-wp-security-and-firewall') , AIOWPSEC_MANAGEMENT_PERMISSION, AIOWPSEC_SPAM_MENU_SLUG, array(&$this, 'handle_spam_menu_rendering'));
        if (AIOWPSecurity_Utility::is_multisite_install() && get_current_blog_id() != 1){
            //Suppress the filescan menu if site is a multi site AND not the main site
        }else{
            add_submenu_page(AIOWPSEC_MAIN_MENU_SLUG, __('Scanner', 'all-in-one-wp-security-and-firewall'),  __('Scanner', 'all-in-one-wp-security-and-firewall') , AIOWPSEC_MANAGEMENT_PERMISSION, AIOWPSEC_FILESCAN_MENU_SLUG, array(&$this, 'handle_filescan_menu_rendering'));
        }
        add_submenu_page(AIOWPSEC_MAIN_MENU_SLUG, __('Maintenance', 'all-in-one-wp-security-and-firewall'),  __('Maintenance', 'all-in-one-wp-security-and-firewall') , AIOWPSEC_MANAGEMENT_PERMISSION, AIOWPSEC_MAINTENANCE_MENU_SLUG, array(&$this, 'handle_maintenance_menu_rendering'));
        add_submenu_page(AIOWPSEC_MAIN_MENU_SLUG, __('Miscellaneous', 'all-in-one-wp-security-and-firewall'),  __('Miscellaneous', 'all-in-one-wp-security-and-firewall') , AIOWPSEC_MANAGEMENT_PERMISSION, AIOWPSEC_MISC_MENU_SLUG, array(&$this, 'handle_misc_menu_rendering'));
        do_action('aiowpsecurity_admin_menu_created');
    }
        
    function handle_dashboard_menu_rendering()
    {
        include_once('wp-security-dashboard-menu.php');
        $this->dashboard_menu = new AIOWPSecurity_Dashboard_Menu();
    }

    function handle_settings_menu_rendering()
    {
        include_once('wp-security-settings-menu.php');
        $this->settings_menu = new AIOWPSecurity_Settings_Menu();
        
    }
    
    function handle_user_accounts_menu_rendering()
    {
        include_once('wp-security-user-accounts-menu.php');
        $this->user_accounts_menu = new AIOWPSecurity_User_Accounts_Menu();
    }
    
    function handle_user_login_menu_rendering()
    {
        include_once('wp-security-user-login-menu.php');
        $this->user_login_menu = new AIOWPSecurity_User_Login_Menu();
    }
    
    function handle_user_registration_menu_rendering()
    {
        include_once('wp-security-user-registration-menu.php');
        $this->user_registration_menu = new AIOWPSecurity_User_Registration_Menu();
    }

    function handle_database_menu_rendering()
    {
        include_once('wp-security-database-menu.php');
        $this->db_security_menu = new AIOWPSecurity_Database_Menu();
    }

    function handle_filesystem_menu_rendering()
    {
        include_once('wp-security-filesystem-menu.php');
        $this->filesystem_menu = new AIOWPSecurity_Filesystem_Menu();
    }

    function handle_blacklist_menu_rendering()
    {
        include_once('wp-security-blacklist-menu.php');
        $this->blacklist_menu = new AIOWPSecurity_Blacklist_Menu();
    }

    function handle_firewall_menu_rendering()
    {
        include_once('wp-security-firewall-menu.php');
        $this->firewall_menu = new AIOWPSecurity_Firewall_Menu();
    }
    
    function handle_brute_force_menu_rendering()
    {
        include_once('wp-security-brute-force-menu.php');
        $this->brute_force_menu = new AIOWPSecurity_Brute_Force_Menu();
    }

    function handle_maintenance_menu_rendering()
    {
        include_once('wp-security-maintenance-menu.php');
        $this->maintenance_menu = new AIOWPSecurity_Maintenance_Menu();
    }
    
    function handle_spam_menu_rendering()
    {
        include_once('wp-security-spam-menu.php');
        $this->spam_menu = new AIOWPSecurity_Spam_Menu();
    }
    
    function handle_filescan_menu_rendering()
    {
        include_once('wp-security-filescan-menu.php');
        $this->filescan_menu = new AIOWPSecurity_Filescan_Menu();
    }
    
    function handle_misc_menu_rendering()
    {
        include_once('wp-security-misc-options-menu.php');
        $this->misc_menu = new AIOWPSecurity_Misc_Options_Menu();
    }
    
}//End of class

