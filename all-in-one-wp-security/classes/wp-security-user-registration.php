<?php
class AIOWPSecurity_User_Registration
{

    function __construct() 
    {
        global $aio_wp_security;
        add_action('user_register', array(&$this, 'aiowps_user_registration_action_handler'));
        if($aio_wp_security->configs->get_value('aiowps_enable_registration_page_captcha') == '1'){
            add_filter('registration_errors', array(&$this, 'aiowps_validate_registration_with_captcha'), 10, 3);
        }
    }
    

    /*
     * This function will add a special meta string in the users table
     * Meta field name: 'aiowps_account_status'
     * Meta field value: 'pending' 
     */
    function aiowps_user_registration_action_handler($user_id)
    {
        global $wpdb, $aio_wp_security;
        //Check if auto pending new account status feature is enabled
        if ($aio_wp_security->configs->get_value('aiowps_enable_manual_registration_approval') == '1')
        {
            $res = add_user_meta($user_id, 'aiowps_account_status', 'pending');
            if (!$res){
                $aio_wp_security->debug_logger->log_debug("aiowps_user_registration_action_handler: Error adding user meta data: aiowps_account_status",4);
            }
        }
    }

    /*
     * This function will set the special meta string in the usermeta table so that the account becomes active
     * Meta field name: 'aiowps_account_status'
     * Meta field values: 'active', 'pending', etc
     */
    function aiowps_set_user_account_status($user_id, $status)
    {
        global $wpdb, $aio_wp_security;
        $res = update_user_meta($user_id, 'aiowps_account_status', $status);
        if (!$res){
            $aio_wp_security->debug_logger->log_debug("aiowps_set_user_account_status: Error updating user meta data: aiowps_account_status",4);
        }
    }
    
    function aiowps_validate_registration_with_captcha($errors, $sanitized_user_login, $user_email)
    {
        global $aio_wp_security;

        $locked = $aio_wp_security->user_login_obj->check_locked_user();
        if($locked == null){
            //user is not locked continue
        }else{
            $errors->add('authentication_failed', __('<strong>ERROR</strong>: You are not allowed to register because your IP address is currently locked!', 'all-in-one-wp-security-and-firewall'));
            return $errors;
        }
        
        if (array_key_exists('aiowps-captcha-answer', $_POST)) //If the register form with captcha was submitted then do some processing
        {
            isset($_POST['aiowps-captcha-answer'])?$captcha_answer = strip_tags(trim($_POST['aiowps-captcha-answer'])): $captcha_answer = '';
            $captcha_secret_string = $aio_wp_security->configs->get_value('aiowps_captcha_secret_key');
            $submitted_encoded_string = base64_encode($_POST['aiowps-captcha-temp-string'].$captcha_secret_string.$captcha_answer);
            if($submitted_encoded_string !== $_POST['aiowps-captcha-string-info'])
            {
                //This means a wrong answer was entered
                //return new WP_Error('authentication_failed', __('<strong>ERROR</strong>: Your answer was incorrect - please try again.', 'all-in-one-wp-security-and-firewall'));
                $errors->add('authentication_failed', __('<strong>ERROR</strong>: Your answer was incorrect - please try again.', 'all-in-one-wp-security-and-firewall'));
                return $errors;
            }
        }
        return $errors;
    }
    
}