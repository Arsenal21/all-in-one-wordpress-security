<?php
if(!defined('ABSPATH')){
    exit;//Exit if accessed directly
}

class AIOWPSecurity_General_Init_Tasks
{
    function __construct(){
        // Do init time tasks
        global $aio_wp_security;
        
        if ($aio_wp_security->configs->get_value('aiowps_disable_xmlrpc_pingback_methods') == '1') {
            add_filter( 'xmlrpc_methods', array(&$this, 'aiowps_disable_xmlrpc_pingback_methods') );
            add_filter( 'wp_headers', array(&$this, 'aiowps_remove_x_pingback_header') );
        }

        add_action( 'permalink_structure_changed', array(&$this, 'refresh_firewall_rules' ), 10, 2);

        // Check permanent block list and block if applicable (ie, do PHP blocking)
        AIOWPSecurity_Blocking::check_visitor_ip_and_perform_blocking();

        if ($aio_wp_security->configs->get_value('aiowps_enable_autoblock_spam_ip') == '1') {
            add_action( 'comment_post', array(&$this, 'spam_detect_process_comment_post' ), 10, 2); //this hook gets fired just after comment is saved to DB
            add_action( 'transition_comment_status', array(&$this, 'process_transition_comment_status' ), 10, 3); //this hook gets fired when a comment's status changes
        }

        if ($aio_wp_security->configs->get_value('aiowps_enable_rename_login_page') == '1') {
            add_action( 'widgets_init', array(&$this, 'remove_standard_wp_meta_widget' ));
            add_filter( 'retrieve_password_message', array(&$this, 'decode_reset_pw_msg'), 10, 4); //Fix for non decoded html entities in password reset link
        }

        add_action('admin_notices', array(&$this,'reapply_htaccess_rules_notice'));
        if(isset($_REQUEST['aiowps_reapply_htaccess'])){
            if(strip_tags($_REQUEST['aiowps_reapply_htaccess']) == 1){
                include_once ('wp-security-installer.php');
                if(AIOWPSecurity_Installer::reactivation_tasks()){
		    $aio_wp_security->debug_logger->log_debug("The AIOWPS .htaccess rules were successfully re-inserted!");
		    $_SESSION['reapply_htaccess_rules_action_result'] = '1';//Success indicator. 
		    // Can't echo to the screen here. It will create an header already sent error.
                }else{
		    $aio_wp_security->debug_logger->log_debug("AIOWPS encountered an error when trying to write to your .htaccess file. Please check the logs.", 5);
		    $_SESSION['reapply_htaccess_rules_action_result'] = '2';//fail indicator.
		    // Can't echo to the screen here. It will create an header already sent error.
                }
                
            }elseif(strip_tags($_REQUEST['aiowps_reapply_htaccess']) == 2){
                // Don't re-write the rules and just delete the temp config item
                delete_option('aiowps_temp_configs');
            }
        }
        
        if($aio_wp_security->configs->get_value('aiowps_prevent_site_display_inside_frame') == '1'){
            send_frame_options_header(); //send X-Frame-Options: SAMEORIGIN in HTTP header
        }

        if($aio_wp_security->configs->get_value('aiowps_remove_wp_generator_meta_info') == '1'){
            add_filter('the_generator', array(&$this,'remove_wp_generator_meta_info'));
            add_filter('style_loader_src', array(&$this,'remove_wp_css_js_meta_info'));
            add_filter('script_loader_src', array(&$this,'remove_wp_css_js_meta_info'));
        }
        
        // For the cookie based brute force prevention feature
        if($aio_wp_security->configs->get_value('aiowps_enable_brute_force_attack_prevention') == 1){
            $bfcf_secret_word = $aio_wp_security->configs->get_value('aiowps_brute_force_secret_word');
            if(isset($_GET[$bfcf_secret_word])){
                // If URL contains secret word in query param then set cookie and then redirect to the login page
                AIOWPSecurity_Utility::set_cookie_value($bfcf_secret_word, "1");
                AIOWPSecurity_Utility::redirect_to_url(AIOWPSEC_WP_URL."/wp-admin");
            }
        }
        
        // Stop users enumeration feature
        if( $aio_wp_security->configs->get_value('aiowps_prevent_users_enumeration') == 1) {
            include_once(AIO_WP_SECURITY_PATH.'/other-includes/wp-security-stop-users-enumeration.php');
        }
        
        // REST API security
        if( $aio_wp_security->configs->get_value('aiowps_disallow_unauthorized_rest_requests') == 1) {
            add_action('rest_api_init', array(&$this, 'check_rest_api_requests'), 10 ,1);
        }
        
        // For user unlock request feature
        if(isset($_POST['aiowps_unlock_request']) || isset($_POST['aiowps_wp_submit_unlock_request'])){
            nocache_headers();            
            remove_action('wp_head','head_addons',7);
            include_once(AIO_WP_SECURITY_PATH.'/other-includes/wp-security-unlock-request.php');
            exit();
        }
        
        if(isset($_GET['aiowps_auth_key'])){
            //If URL contains unlock key in query param then process the request
            $unlock_key = sanitize_text_field($_GET['aiowps_auth_key']);
            AIOWPSecurity_User_Login::process_unlock_request($unlock_key);
        }

        // For honeypot feature
        if(isset($_POST['aio_special_field'])){
            $special_field_value = sanitize_text_field($_POST['aio_special_field']);
            if(!empty($special_field_value)){
                //This means a robot has submitted the login form!
                //Redirect back to its localhost
                AIOWPSecurity_Utility::redirect_to_url('http://127.0.0.1');
            }
        }
        
        // For 404 IP lockout feature
        if($aio_wp_security->configs->get_value('aiowps_enable_404_IP_lockout') == '1'){
            if (!is_user_logged_in() || !current_user_can('administrator')) {
                $this->do_404_lockout_tasks();
            }
        }


        // For login captcha feature
        if($aio_wp_security->configs->get_value('aiowps_enable_login_captcha') == '1'){
            if (!is_user_logged_in()) {
                add_action('login_form', array(&$this, 'insert_captcha_question_form'));
            }
        }

        // For woo form captcha features
        if($aio_wp_security->configs->get_value('aiowps_enable_woo_login_captcha') == '1') {
            if (!is_user_logged_in()) {
                add_action('woocommerce_login_form', array(&$this, 'insert_captcha_question_form'));
            }
            if(isset($_POST['woocommerce-login-nonce'])) {
                add_filter('woocommerce_process_login_errors', array(&$this, 'aiowps_validate_woo_login_or_reg_captcha'), 10, 3);
            }
        }

        if($aio_wp_security->configs->get_value('aiowps_enable_woo_register_captcha') == '1') {
            if(!is_user_logged_in()) {
                add_action('woocommerce_register_form', array(&$this, 'insert_captcha_question_form'));
            }
            
            if(isset($_POST['woocommerce-register-nonce'])) {
                add_filter('woocommerce_process_registration_errors', array(&$this, 'aiowps_validate_woo_login_or_reg_captcha'), 10, 3);
            }
        }
        
        if($aio_wp_security->configs->get_value('aiowps_enable_woo_lostpassword_captcha') == '1') {
            if(!is_user_logged_in()) {
                add_action('woocommerce_lostpassword_form', array(&$this, 'insert_captcha_question_form'));
            }
            if(isset($_POST['woocommerce-lost-password-nonce'])) {
                add_action('lostpassword_post', array(&$this, 'process_woo_lost_password_form_post'));
            }
        }

        // For bbpress new topic form captcha
        if($aio_wp_security->configs->get_value('aiowps_enable_bbp_new_topic_captcha') == '1'){
            if (!is_user_logged_in()) {
                add_action('bbp_theme_before_topic_form_submit_wrapper', array(&$this, 'insert_captcha_question_form'));
            }
        }
        
        // For custom login form captcha feature, ie, when wp_login_form() function is used to generate login form
        if($aio_wp_security->configs->get_value('aiowps_enable_custom_login_captcha') == '1'){
            if (!is_user_logged_in()) {
                add_filter( 'login_form_middle', array(&$this, 'insert_captcha_custom_login'), 10, 2); //For cases where the WP wp_login_form() function is used
            }
        }

        // For honeypot feature
        if($aio_wp_security->configs->get_value('aiowps_enable_login_honeypot') == '1'){
            if (!is_user_logged_in()) {
                add_action('login_form', array(&$this, 'insert_honeypot_hidden_field'));
            }
        }
 
        // For registration honeypot feature
        if($aio_wp_security->configs->get_value('aiowps_enable_registration_honeypot') == '1'){
            if (!is_user_logged_in()) {
                add_action('register_form', array(&$this, 'insert_honeypot_hidden_field'));
            }
        }
        
        // For lost password captcha feature
        if($aio_wp_security->configs->get_value('aiowps_enable_lost_password_captcha') == '1'){
            if (!is_user_logged_in()) {
                add_action('lostpassword_form', array(&$this, 'insert_captcha_question_form'));
                add_action('lostpassword_post', array(&$this, 'process_lost_password_form_post'));
            }
        }

        // For registration manual approval feature
        if($aio_wp_security->configs->get_value('aiowps_enable_manual_registration_approval') == '1'){
            add_filter('wp_login_errors', array(&$this, 'modify_registration_page_messages'),10, 2);
        }
        
        // For registration page captcha feature
        if (AIOWPSecurity_Utility::is_multisite_install()){
            $blog_id = get_current_blog_id();
            switch_to_blog($blog_id);
            if($aio_wp_security->configs->get_value('aiowps_enable_registration_page_captcha') == '1'){
                if (!is_user_logged_in()) {
                    add_action('signup_extra_fields', array(&$this, 'insert_captcha_question_form_multi'));
                    //add_action('preprocess_signup_form', array(&$this, 'process_signup_form_multi'));
                    add_filter( 'wpmu_validate_user_signup', array(&$this, 'process_signup_form_multi') );
                }
            }
            restore_current_blog();
        }else{
            if($aio_wp_security->configs->get_value('aiowps_enable_registration_page_captcha') == '1'){
                if (!is_user_logged_in()) {
                    add_action('register_form', array(&$this, 'insert_captcha_question_form'));
                }
            }
        }

        // For comment captcha feature or custom login form captcha
        if (AIOWPSecurity_Utility::is_multisite_install()){
            $blog_id = get_current_blog_id();
            switch_to_blog($blog_id);
            if($aio_wp_security->configs->get_value('aiowps_enable_comment_captcha') == '1'){
                if (!is_user_logged_in()) {
                    if($aio_wp_security->configs->get_value('aiowps_default_recaptcha')) {
                        add_action('wp_head', array(&$this, 'add_recaptcha_script'));
                    }
                    add_action( 'comment_form_after_fields', array(&$this, 'insert_captcha_question_form'), 1 );
                    add_action( 'comment_form_logged_in_after', array(&$this, 'insert_captcha_question_form'), 1 );
                    add_filter( 'preprocess_comment', array(&$this, 'process_comment_post') );
                }
            }
            restore_current_blog();
        }else{
            if($aio_wp_security->configs->get_value('aiowps_enable_comment_captcha') == '1'){
                if (!is_user_logged_in()) {
                    if($aio_wp_security->configs->get_value('aiowps_default_recaptcha')) {
                        add_action('wp_head', array(&$this, 'add_recaptcha_script'));
                    }
                    add_action( 'comment_form_after_fields', array(&$this, 'insert_captcha_question_form'), 1 );
                    add_action( 'comment_form_logged_in_after', array(&$this, 'insert_captcha_question_form'), 1 );
                    add_filter( 'preprocess_comment', array(&$this, 'process_comment_post') );
                }
            }
        }
        
        // For buddypress registration captcha feature
        if($aio_wp_security->configs->get_value('aiowps_enable_bp_register_captcha') == '1'){
            add_action('bp_account_details_fields', array(&$this, 'insert_captcha_question_form'));
            add_action('bp_signup_validate', array(&$this, 'buddy_press_signup_validate_captcha'));
        }
        
        
        // For feature which displays logged in users
        $aio_wp_security->user_login_obj->update_users_online_transient();
        
        // For block fake googlebots feature
        if($aio_wp_security->configs->get_value('aiowps_block_fake_googlebots') == '1'){
            include_once(AIO_WP_SECURITY_PATH.'/classes/wp-security-bot-protection.php');
            AIOWPSecurity_Fake_Bot_Protection::block_fake_googlebots();
        }
        
        // For 404 event logging
        if($aio_wp_security->configs->get_value('aiowps_enable_404_logging') == '1'){
            add_action('wp_head', array(&$this, 'check_404_event'));
        }

        // Add more tasks that need to be executed at init time
        
    } // end _construct()
    
    function aiowps_disable_xmlrpc_pingback_methods( $methods ) {
       unset( $methods['pingback.ping'] );
       unset( $methods['pingback.extensions.getPingbacks'] );
       return $methods;
    }
    
    function aiowps_remove_x_pingback_header( $headers ) {
       unset( $headers['X-Pingback'] );
       return $headers;
    }

    /**
     * Refreshes the firewall rules in .htaccess file
     * eg: if permalink settings changed and white list enabled
     * @param $old_permalink_structure
     * @param $permalink_structure
     */
    function refresh_firewall_rules($old_permalink_structure, $permalink_structure){
        global $aio_wp_security;
        //If white list enabled need to re-adjust the .htaccess rules
        if ($aio_wp_security->configs->get_value('aiowps_enable_whitelisting') == '1') {
            $write_result = AIOWPSecurity_Utility_Htaccess::write_to_htaccess(); //now let's write to the .htaccess file
            if ( !$write_result )
            {
                $this->show_msg_error(__('The plugin was unable to write to the .htaccess file. Please edit file manually.','all-in-one-wp-security-and-firewall'));
                $aio_wp_security->debug_logger->log_debug("AIOWPSecurity_whitelist_Menu - The plugin was unable to write to the .htaccess file.");
            }
        }
    }

    function spam_detect_process_comment_post($comment_id, $comment_approved)
    {
        if($comment_approved === "spam"){
            $this->block_comment_ip($comment_id);
        }

    }

    function process_transition_comment_status($new_status, $old_status, $comment)
    {
        if($new_status == 'spam'){
            $this->block_comment_ip($comment->comment_ID);
        }

    }

    /**
     * Will check auto-spam blocking settings and will add IP to blocked table accordingly
     * @param $comment_id
     */
    function block_comment_ip($comment_id)
    {
        global $aio_wp_security, $wpdb;
        $comment_obj = get_comment( $comment_id );
        $comment_ip = $comment_obj->comment_author_IP;
        //Get number of spam comments from this IP
        $sql = $wpdb->prepare("SELECT * FROM $wpdb->comments
                WHERE comment_approved = 'spam'
                AND comment_author_IP = %s
                ", $comment_ip);
        $comment_data = $wpdb->get_results($sql, ARRAY_A);
        $spam_count = count($comment_data);
        $min_comment_before_block = $aio_wp_security->configs->get_value('aiowps_spam_ip_min_comments_block');
        if(!empty($min_comment_before_block) && $spam_count >= ($min_comment_before_block - 1)){
            AIOWPSecurity_Blocking::add_ip_to_block_list($comment_ip, 'spam');
        }
    }

    function remove_standard_wp_meta_widget()
    {
        unregister_widget('WP_Widget_Meta');
    }    

    function remove_wp_generator_meta_info()
    {
        return '';
    }

    function remove_wp_css_js_meta_info($src) {
        global $wp_version;
        static $wp_version_hash = null; // Cache hash value for all function calls

        // Replace only version number of assets with WP version
        if ( strpos($src, 'ver=' . $wp_version) !== false ) {
            if ( !$wp_version_hash ) {
                $wp_version_hash = wp_hash($wp_version);
            }
            // Replace version number with computed hash
            $src = add_query_arg('ver', $wp_version_hash, $src);
        }
        return $src;
    }

    function do_404_lockout_tasks(){
        global $aio_wp_security;
        $redirect_url = $aio_wp_security->configs->get_value('aiowps_404_lock_redirect_url'); //This is the redirect URL for blocked users
        
        $visitor_ip = AIOWPSecurity_Utility_IP::get_user_ip_address();
        
        $is_locked = AIOWPSecurity_Utility::check_locked_ip($visitor_ip);
        
        if($is_locked){
            //redirect blocked user to configured URL
            AIOWPSecurity_Utility::redirect_to_url($redirect_url);
        }else{
            //allow through
        }
    }

    /**
     * Renders captcha on form produced by the wp_login_form() function, ie, custom wp login form
     * @global type $aio_wp_security
     * @param type $cust_html_code
     * @param type $args
     * @return string
     */
    function insert_captcha_custom_login($cust_html_code, $args)
    {
        global $aio_wp_security;
        if($aio_wp_security->configs->get_value('aiowps_default_recaptcha')) {
            $site_key = esc_html( $aio_wp_security->configs->get_value('aiowps_recaptcha_site_key') );
            $cap_form = '<div class="g-recaptcha-wrap" style="padding:10px 0 10px 0"><div class="g-recaptcha" data-sitekey="'.$site_key.'"></div></div>';
            $cust_html_code .= $cap_form;
            return $cust_html_code;
        } else {
            $cap_form = '<p class="aiowps-captcha"><label>'.__('Please enter an answer in digits:','all-in-one-wp-security-and-firewall').'</label>';
            $cap_form .= '<div class="aiowps-captcha-equation"><strong>';
            $maths_question_output = $aio_wp_security->captcha_obj->generate_maths_question();
            $cap_form .= $maths_question_output . '</strong></div></p>';

            $cust_html_code .= $cap_form;
            return $cust_html_code;
        }
    }
    
    function insert_captcha_question_form_multi($error)
    {
        global $aio_wp_security;
        $aio_wp_security->captcha_obj->display_captcha_form();
    }
    
    function process_signup_form_multi($result)
    {
        global $aio_wp_security;
        //Check if captcha enabled
        $verify_captcha = $aio_wp_security->captcha_obj->verify_captcha_submit();
        if ( $verify_captcha === false ) {
            // wrong answer was entered
            $result['errors']->add('generic', __('<strong>ERROR</strong>: Your answer was incorrect - please try again.', 'all-in-one-wp-security-and-firewall'));
        }
        return $result;
    }
    
    function insert_captcha_question_form(){
        global $aio_wp_security;
        
        if($aio_wp_security->configs->get_value('aiowps_default_recaptcha')) {
            
            // Woocommerce "my account" page needs special consideration, ie,
            // need to display two Google reCaptcha forms on same page (for login and register forms)
            // For this case we use the "explicit" recaptcha display
            $calling_hook = current_filter();
            $site_key = esc_html( $aio_wp_security->configs->get_value('aiowps_recaptcha_site_key') );
            if ( $calling_hook == 'woocommerce_login_form' || $calling_hook == 'woocommerce_lostpassword_form') {
                echo '<div class="g-recaptcha-wrap" style="padding:10px 0 10px 0"><div id="woo_recaptcha_1" class="g-recaptcha" data-sitekey="'.$site_key.'"></div></div>';
                return;
            }

            if ( $calling_hook == 'woocommerce_register_form' ) {
                echo '<div class="g-recaptcha-wrap" style="padding:10px 0 10px 0"><div id="woo_recaptcha_2" class="g-recaptcha" data-sitekey="'.$site_key.'"></div></div>';
                return;
            }
            
            // For all other forms simply display google recaptcha as per normal
            $aio_wp_security->captcha_obj->display_recaptcha_form();
        } else {
            // display plain maths captcha form
            $aio_wp_security->captcha_obj->display_captcha_form();
        }
        
    }

    function insert_honeypot_hidden_field(){
        $honey_input = '<p style="display: none;"><label>'.__('Enter something special:','all-in-one-wp-security-and-firewall').'</label>';
        $honey_input .= '<input name="aio_special_field" type="text" id="aio_special_field" class="aio_special_field" value="" /></p>';
        echo $honey_input;
    }
    
    function process_comment_post( $comment ) 
    {
        global $aio_wp_security;
        if (is_user_logged_in()) {
                return $comment;
        }

        //Don't process captcha for comment replies inside admin menu
        if (isset( $_REQUEST['action'] ) && $_REQUEST['action'] == 'replyto-comment' &&
        (check_ajax_referer('replyto-comment', '_ajax_nonce', false) || check_ajax_referer('replyto-comment', '_ajax_nonce-replyto-comment', false))) {
            return $comment;
        }

        //Don't do captcha for pingback/trackback
        if ($comment['comment_type'] != '' && $comment['comment_type'] != 'comment' && $comment['comment_type'] != 'review') {
            return $comment;
        }
        
        $verify_captcha = $aio_wp_security->captcha_obj->verify_captcha_submit(); 
        if($verify_captcha === false) {
            //Wrong answer
            wp_die( __('Error: You entered an incorrect CAPTCHA answer. Please go back and try again.', 'all-in-one-wp-security-and-firewall'));
        } else {
            return($comment);
        }
    }
    
    /**
     * Process the main Wordpress account lost password login form post
     * Called by wp hook "lostpassword_post"
     */
    function process_lost_password_form_post() 
    {
        global $aio_wp_security;
        
        // Workaround - the woocommerce lost password form also uses the same "lostpassword_post" hook.
        // We don't want to process woo forms here so ignore if this is a woo lost password $_POST 
        if (!array_key_exists('woocommerce-lost-password-nonce', $_POST)) {
            $verify_captcha = $aio_wp_security->captcha_obj->verify_captcha_submit();
            if ( $verify_captcha === false ) {
                add_filter('allow_password_reset', array(&$this, 'add_lostpassword_captcha_error_msg'));
            }
        }
    }
    
    function add_lostpassword_captcha_error_msg()
    {
        //Insert an error just before the password reset process kicks in
        return new WP_Error('aiowps_captcha_error',__('<strong>ERROR</strong>: Your answer was incorrect - please try again.', 'all-in-one-wp-security-and-firewall'));
    }
    
    function check_404_event()
    {
        if(is_404()){
            //This means a 404 event has occurred - let's log it!
            AIOWPSecurity_Utility::event_logger('404');
        }
        
    }   
    
    function buddy_press_signup_validate_captcha($errors)
    {
        global $bp, $aio_wp_security;
        //Check captcha if required
        $verify_captcha = $aio_wp_security->captcha_obj->verify_captcha_submit();
        if($verify_captcha === false) {
            // wrong answer was entered
            $bp->signup->errors['aiowps-captcha-answer'] = __('Your CAPTCHA answer was incorrect - please try again.', 'all-in-one-wp-security-and-firewall');
        }
        return;
    }
    
    function aiowps_validate_woo_login_or_reg_captcha( $errors, $username, $password ) {
        global $aio_wp_security;
        $locked = $aio_wp_security->user_login_obj->check_locked_user();
        if(!empty($locked)){
            $errors->add('authentication_failed', __('<strong>ERROR</strong>: Your IP address is currently locked please contact the administrator!', 'all-in-one-wp-security-and-firewall'));
            return $errors;
        }

        $verify_captcha = $aio_wp_security->captcha_obj->verify_captcha_submit();
        if($verify_captcha === false) {
            // wrong answer was entered
            $errors->add('authentication_failed', __('<strong>ERROR</strong>: Your answer was incorrect - please try again.', 'all-in-one-wp-security-and-firewall'));
        }        
        return $errors;
        
    }
    
    /**
     * Process the woocommerce lost password login form post
     * Called by wp hook "lostpassword_post"
     */
    function process_woo_lost_password_form_post() 
    {
        global $aio_wp_security;
        
        if(isset($_POST['woocommerce-lost-password-nonce'])) { 
            $verify_captcha = $aio_wp_security->captcha_obj->verify_captcha_submit();
            if ( $verify_captcha === false ) {
                add_filter('allow_password_reset', array(&$this, 'add_lostpassword_captcha_error_msg'));
            }
        }
    }
    
    
    /**
     * Displays a notice message if the plugin was reactivated after being initially deactivated
     * Gives users option of re-applying the aiowps rules which were deleted from the .htaccess after deactivation.
     */
    function reapply_htaccess_rules_notice()
    {
        if (get_option('aiowps_temp_configs') !== FALSE){
            echo '<div class="updated"><p>'.__('Would you like All In One WP Security & Firewall to re-insert the security rules in your .htaccess file which were cleared when you deactivated the plugin?', 'all-in-one-wp-security-and-firewall').'&nbsp;&nbsp;<a href="admin.php?page='.AIOWPSEC_MENU_SLUG_PREFIX.'&aiowps_reapply_htaccess=1" class="button-primary">'.__('Yes', 'all-in-one-wp-security-and-firewall').'</a>&nbsp;&nbsp;<a href="admin.php?page='.AIOWPSEC_MENU_SLUG_PREFIX.'&aiowps_reapply_htaccess=2" class="button-primary">'.__('No', 'all-in-one-wp-security-and-firewall').'</a></p></div>';
        }
    }
    
    //This is a fix for cases when the password reset URL in the email was not decoding all html entities properly
    function decode_reset_pw_msg($message, $key, $user_login, $user_data)
    {
        global $aio_wp_security;
        $message = html_entity_decode($message);
        return $message;
    }
    
    function modify_registration_page_messages($errors, $redirect_to)
    {
        if( isset($_GET['checkemail']) && 'registered' == $_GET['checkemail'] ){
            if(is_wp_error($errors)){
                $errors->remove('registered');
                $pending_approval_msg = __('Your registration is pending approval.', 'all-in-one-wp-security-and-firewall');
                $pending_approval_msg = apply_filters('aiowps_pending_registration_message', $pending_approval_msg);
                $errors->add('registered', $pending_approval_msg, array('registered'=>'message'));
            }
        }
        return $errors;
    }
    
    /*
     * Re-wrote code which checks for REST API requests
     * Below uses the "rest_api_init" action hook to check for REST requests.
     * The code will block "unauthorized" requests whilst allowing genuine requests. 
     * (P. Petreski June 2018)
     */
    function check_rest_api_requests($rest_server_object){
        $rest_user = wp_get_current_user();
        if(empty($rest_user->ID)){
            $error_message = apply_filters('aiowps_rest_api_error_message', __('You are not authorized to perform this action.', 'disable-wp-rest-api'));
            wp_die($error_message); 
        }
    }

    /**
     * Enqueues the Google recaptcha api URL in the wp_head for general pages
     * Caters for scenarios when recaptcha used on wp comments or custom wp login form
     * 
     */
    function add_recaptcha_script()
    {
        // Enqueue the recaptcha api url 
        
        // Do NOT enqueue if this is the main woocommerce account login page because for woocommerce page we "explicitly" render the recaptcha widget
        $is_woo = false;
        
        // We don't want to load for woo account page because we have a special function for this
        if ( function_exists('is_account_page') ) {
            // Check if this a woocommerce account page
            $is_woo = is_account_page(); 
        }
                         
        if ( empty( $is_woo ) ) {
            //only enqueue when not a woocommerce page
            wp_enqueue_script( 'google-recaptcha', 'https://www.google.com/recaptcha/api.js', false );
        } 
    }
}