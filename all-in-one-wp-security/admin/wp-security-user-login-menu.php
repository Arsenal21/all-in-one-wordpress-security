<?php

class AIOWPSecurity_User_Login_Menu extends AIOWPSecurity_Admin_Menu
{
    var $menu_page_slug = AIOWPSEC_USER_LOGIN_MENU_SLUG;
    
    /* Specify all the tabs of this menu in the following array */
    var $menu_tabs;
    var $menu_tabs_handler = array(
        'tab1' => 'render_tab1', 
        'tab2' => 'render_tab2',
        'tab3' => 'render_tab3',
        'tab4' => 'render_tab4',
        'tab5' => 'render_tab5',
        );
    
    function __construct() 
    {
        $this->render_menu_page();
    }
    
    function set_menu_tabs() 
    {
        $this->menu_tabs = array(
        'tab1' => __('Login Lockdown', 'all-in-one-wp-security-and-firewall'),
        'tab2' => __('Failed Login Records', 'all-in-one-wp-security-and-firewall'),
        'tab3' => __('Force Logout', 'all-in-one-wp-security-and-firewall'),
        'tab4' => __('Account Activity Logs', 'all-in-one-wp-security-and-firewall'),
        'tab5' => __('Logged In Users', 'all-in-one-wp-security-and-firewall'),
        );
    }

    function get_current_tab() 
    {
        $tab_keys = array_keys($this->menu_tabs);
        $tab = isset( $_GET['tab'] ) ? sanitize_text_field($_GET['tab']) : $tab_keys[0];
        return $tab;
    }

    /*
     * Renders our tabs of this menu as nav items
     */
    function render_menu_tabs() 
    {
        $current_tab = $this->get_current_tab();

        echo '<h2 class="nav-tab-wrapper">';
        foreach ( $this->menu_tabs as $tab_key => $tab_caption ) 
        {
            $active = $current_tab == $tab_key ? 'nav-tab-active' : '';
            echo '<a class="nav-tab ' . $active . '" href="?page=' . $this->menu_page_slug . '&tab=' . $tab_key . '">' . $tab_caption . '</a>';	
        }
        echo '</h2>';
    }
    
    /*
     * The menu rendering goes here
     */
    function render_menu_page() 
    {
        echo '<div class="wrap">';
        echo '<h2>'.__('User Login','all-in-one-wp-security-and-firewall').'</h2>';//Interface title
        $this->set_menu_tabs();
        $tab = $this->get_current_tab();
        $this->render_menu_tabs();
        ?>        
        <div id="poststuff"><div id="post-body">
        <?php  
        //$tab_keys = array_keys($this->menu_tabs);
        call_user_func(array(&$this, $this->menu_tabs_handler[$tab]));
        ?>
        </div></div>
        </div><!-- end of wrap -->
        <?php
    }
    
    function render_tab1() 
    {
        global $aio_wp_security;
        global $aiowps_feature_mgr;
        include_once 'wp-security-list-locked-ip.php'; //For rendering the AIOWPSecurity_List_Table in tab1
        $locked_ip_list = new AIOWPSecurity_List_Locked_IP(); //For rendering the AIOWPSecurity_List_Table in tab1

        if(isset($_POST['aiowps_login_lockdown']))//Do form submission tasks
        {
            $error = '';
            $nonce=$_REQUEST['_wpnonce'];
            if (!wp_verify_nonce($nonce, 'aiowpsec-login-lockdown-nonce'))
            {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed on login lockdown options save!",4);
                die("Nonce check failed on login lockdown options save!");
            }

            $max_login_attempt_val = sanitize_text_field($_POST['aiowps_max_login_attempts']);
            if(!is_numeric($max_login_attempt_val))
            {
                $error .= '<br />'.__('You entered a non numeric value for the max login attempts field. It has been set to the default value.','all-in-one-wp-security-and-firewall');
                $max_login_attempt_val = '3';//Set it to the default value for this field
            }
            
            $login_retry_time_period = sanitize_text_field($_POST['aiowps_retry_time_period']);
            if(!is_numeric($login_retry_time_period))
            {
                $error .= '<br />'.__('You entered a non numeric value for the login retry time period field. It has been set to the default value.','all-in-one-wp-security-and-firewall');
                $login_retry_time_period = '5';//Set it to the default value for this field
            }

            $lockout_time_length = sanitize_text_field($_POST['aiowps_lockout_time_length']);
            if(!is_numeric($lockout_time_length))
            {
                $error .= '<br />'.__('You entered a non numeric value for the lockout time length field. It has been set to the default value.','all-in-one-wp-security-and-firewall');
                $lockout_time_length = '60';//Set it to the default value for this field
            }
            
            $email_address = sanitize_email($_POST['aiowps_email_address']);
            if(!is_email($email_address))
            {
                $error .= '<br />'.__('You have entered an incorrect email address format. It has been set to your WordPress admin email as default.','all-in-one-wp-security-and-firewall');
                $email_address = get_bloginfo('admin_email'); //Set the default value to the blog admin email
            }

            // Instantly lockout specific usernames
            $_ilsu = isset($_POST['aiowps_instantly_lockout_specific_usernames']) ? $_POST['aiowps_instantly_lockout_specific_usernames'] : '';
            // Read into array, sanitize, filter empty and keep only unique usernames.
            $instantly_lockout_specific_usernames
                = array_unique(
                    array_filter(
                        array_map(
                            'sanitize_user',
                            AIOWPSecurity_Utility::explode_trim_filter_empty($_ilsu)
                        ),
                        'strlen'
                    )
                )
            ;

            if($error)
            {
                $this->show_msg_error(__('Attention!','all-in-one-wp-security-and-firewall').$error);
            }

            //Save all the form values to the options
            $random_20_digit_string = AIOWPSecurity_Utility::generate_alpha_numeric_random_string(20); //Generate random 20 char string for use during captcha encode/decode
            $aio_wp_security->configs->set_value('aiowps_unlock_request_secret_key', $random_20_digit_string);
            
            $aio_wp_security->configs->set_value('aiowps_enable_login_lockdown',isset($_POST["aiowps_enable_login_lockdown"])?'1':'');
            $aio_wp_security->configs->set_value('aiowps_allow_unlock_requests',isset($_POST["aiowps_allow_unlock_requests"])?'1':'');
            $aio_wp_security->configs->set_value('aiowps_max_login_attempts',absint($max_login_attempt_val));
            $aio_wp_security->configs->set_value('aiowps_retry_time_period',absint($login_retry_time_period));
            $aio_wp_security->configs->set_value('aiowps_lockout_time_length',absint($lockout_time_length));
            $aio_wp_security->configs->set_value('aiowps_set_generic_login_msg',isset($_POST["aiowps_set_generic_login_msg"])?'1':'');
            $aio_wp_security->configs->set_value('aiowps_enable_invalid_username_lockdown',isset($_POST["aiowps_enable_invalid_username_lockdown"])?'1':'');
            $aio_wp_security->configs->set_value('aiowps_instantly_lockout_specific_usernames', $instantly_lockout_specific_usernames);
            $aio_wp_security->configs->set_value('aiowps_enable_email_notify',isset($_POST["aiowps_enable_email_notify"])?'1':'');
            $aio_wp_security->configs->set_value('aiowps_email_address',$email_address);
            $aio_wp_security->configs->save_config();
            
            //Recalculate points after the feature status/options have been altered
            $aiowps_feature_mgr->check_feature_status_and_recalculate_points();
            
            $this->show_msg_settings_updated();
        }
        
                
        if(isset($_REQUEST['action'])) //Do list table form row action tasks
        {
            if($_REQUEST['action'] == 'delete_blocked_ip'){ //Delete link was clicked for a row in list table
                $locked_ip_list->delete_lockdown_records(strip_tags($_REQUEST['lockdown_id']));
            }
            
            if($_REQUEST['action'] == 'unlock_ip'){ //Unlock link was clicked for a row in list table
                $locked_ip_list->unlock_ip_range(strip_tags($_REQUEST['lockdown_id']));
            }
        }
        
        //login lockdown whitelist settings
        $result = 1;
        if (isset($_POST['aiowps_save_lockdown_whitelist_settings']))
        {
            $nonce=$_REQUEST['_wpnonce'];
            if (!wp_verify_nonce($nonce, 'aiowpsec-lockdown-whitelist-settings-nonce'))
            {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed for save lockdown whitelist settings!",4);
                die(__('Nonce check failed for save lockdown whitelist settings!','aiowpsecurity'));
            }
            
            if (isset($_POST["aiowps_lockdown_enable_whitelisting"]) && empty($_POST['aiowps_lockdown_allowed_ip_addresses']))
            {
                $this->show_msg_error('You must submit at least one IP address!','aiowpsecurity');
            }
            else
            {
                if (!empty($_POST['aiowps_lockdown_allowed_ip_addresses']))
                {
                    $ip_addresses = $_POST['aiowps_lockdown_allowed_ip_addresses'];
                    $ip_list_array = AIOWPSecurity_Utility_IP::create_ip_list_array_from_string_with_newline($ip_addresses);
                    $payload = AIOWPSecurity_Utility_IP::validate_ip_list($ip_list_array, 'whitelist');
                    if($payload[0] == 1){
                        //success case
                        $result = 1;
                        $list = $payload[1];
                        $banned_ip_data = implode(PHP_EOL, $list);
                        $aio_wp_security->configs->set_value('aiowps_lockdown_allowed_ip_addresses',$banned_ip_data);
                        $_POST['aiowps_lockdown_allowed_ip_addresses'] = ''; //Clear the post variable for the banned address list
                    }
                    else{
                        $result = -1;
                        $error_msg = $payload[1][0];
                        $this->show_msg_error($error_msg);
                    }
                }
                else
                {
                    $aio_wp_security->configs->set_value('aiowps_lockdown_allowed_ip_addresses',''); //Clear the IP address config value
                }

                if ($result == 1)
                {
                    $aio_wp_security->configs->set_value('aiowps_lockdown_enable_whitelisting',isset($_POST["aiowps_lockdown_enable_whitelisting"])?'1':'');
                    $aio_wp_security->configs->save_config(); //Save the configuration
                    
                    $this->show_msg_settings_updated();
                }
            }
        }        
        ?>
        <h2><?php _e('Login Lockdown Configuration', 'all-in-one-wp-security-and-firewall')?></h2>
        <div class="aio_blue_box">
            <?php
            $brute_force_login_feature_link = '<a href="admin.php?page='.AIOWPSEC_BRUTE_FORCE_MENU_SLUG.'&tab=tab2">Cookie-Based Brute Force Login Prevention</a>';
            echo '<p>'.__('One of the ways hackers try to compromise sites is via a ', 'all-in-one-wp-security-and-firewall').'<strong>'.__('Brute Force Login Attack', 'all-in-one-wp-security-and-firewall').'</strong>. '.__('This is where attackers use repeated login attempts until they guess the password.', 'all-in-one-wp-security-and-firewall').'
            <br />'.__('Apart from choosing strong passwords, monitoring and blocking IP addresses which are involved in repeated login failures in a short period of time is a very effective way to stop these types of attacks.', 'all-in-one-wp-security-and-firewall').
            '<p>'.sprintf( __('You may also want to checkout our %s feature for another secure way to protect against these types of attacks.', 'all-in-one-wp-security-and-firewall'), $brute_force_login_feature_link).'</p>';
            ?>
        </div>

        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('Login Lockdown Options', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
        <?php
        //Display security info badge
        $aiowps_feature_mgr->output_feature_details_badge("user-login-login-lockdown");
        ?>

        <form action="" method="POST">
        <?php wp_nonce_field('aiowpsec-login-lockdown-nonce'); ?>
        <table class="form-table">
            <tr valign="top">
                <th scope="row"><?php _e('Enable Login Lockdown Feature', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td>
                <input name="aiowps_enable_login_lockdown" type="checkbox"<?php if($aio_wp_security->configs->get_value('aiowps_enable_login_lockdown')=='1') echo ' checked="checked"'; ?> value="1"/>
                <span class="description"><?php _e('Check this if you want to enable the login lockdown feature and apply the settings below', 'all-in-one-wp-security-and-firewall'); ?></span>
                </td>
            </tr>            
            <tr valign="top">
                <th scope="row"><?php _e('Allow Unlock Requests', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td>
                <input name="aiowps_allow_unlock_requests" type="checkbox"<?php if($aio_wp_security->configs->get_value('aiowps_allow_unlock_requests')=='1') echo ' checked="checked"'; ?> value="1"/>
                <span class="description"><?php _e('Check this if you want to allow users to generate an automated unlock request link which will unlock their account', 'all-in-one-wp-security-and-firewall'); ?></span>
                </td>
            </tr>            
            <tr valign="top">
                <th scope="row"><?php _e('Max Login Attempts', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td><input type="text" size="5" name="aiowps_max_login_attempts" value="<?php echo $aio_wp_security->configs->get_value('aiowps_max_login_attempts'); ?>" />
                <span class="description"><?php _e('Set the value for the maximum login retries before IP address is locked out', 'all-in-one-wp-security-and-firewall'); ?></span>
                </td> 
            </tr>
            <tr valign="top">
                <th scope="row"><?php _e('Login Retry Time Period (min)', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td><input type="text" size="5" name="aiowps_retry_time_period" value="<?php echo $aio_wp_security->configs->get_value('aiowps_retry_time_period'); ?>" />
                <span class="description"><?php _e('If the maximum number of failed login attempts for a particular IP address occur within this time period the plugin will lock out that address', 'all-in-one-wp-security-and-firewall'); ?></span>
                </td> 
            </tr>
            <tr valign="top">
                <th scope="row"><?php _e('Time Length of Lockout (min)', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td><input type="text" size="5" name="aiowps_lockout_time_length" value="<?php echo $aio_wp_security->configs->get_value('aiowps_lockout_time_length'); ?>" />
                <span class="description"><?php _e('Set the length of time for which a particular IP address will be prevented from logging in', 'all-in-one-wp-security-and-firewall'); ?></span>
                </td> 
            </tr>
            <tr valign="top">
                <th scope="row"><?php _e('Display Generic Error Message', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td>
                <input name="aiowps_set_generic_login_msg" type="checkbox"<?php if($aio_wp_security->configs->get_value('aiowps_set_generic_login_msg')=='1') echo ' checked="checked"'; ?> value="1"/>
                <span class="description"><?php _e('Check this if you want to show a generic error message when a login attempt fails', 'all-in-one-wp-security-and-firewall'); ?></span>
                </td>
            </tr>
            <tr valign="top">
                <th scope="row"><?php _e('Instantly Lockout Invalid Usernames', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td>
                <input name="aiowps_enable_invalid_username_lockdown" type="checkbox"<?php if($aio_wp_security->configs->get_value('aiowps_enable_invalid_username_lockdown')=='1') echo ' checked="checked"'; ?> value="1"/>
                <span class="description"><?php _e('Check this if you want to instantly lockout login attempts with usernames which do not exist on your system', 'all-in-one-wp-security-and-firewall'); ?></span>
                </td>
            </tr>            
            <tr valign="top">
                <th scope="row"><?php _e('Instantly Lockout Specific Usernames', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td>
                    <?php 
                    $instant_lockout_users_list = $aio_wp_security->configs->get_value('aiowps_instantly_lockout_specific_usernames');
                    if(empty($instant_lockout_users_list)){
                        $instant_lockout_users_list = array();
                    }
                    ?>
                    <textarea name="aiowps_instantly_lockout_specific_usernames" cols="50" rows="5"><?php echo implode(PHP_EOL, $instant_lockout_users_list); ?></textarea><br>
                    <span class="description"><?php _e('Insert one username per line. Existing usernames are not blocked even if present in the list.', 'all-in-one-wp-security-and-firewall'); ?></span>
                </td>
            </tr>
            <tr valign="top">
                <th scope="row"><?php _e('Notify By Email', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td>
                    <input name="aiowps_enable_email_notify" type="checkbox"<?php if($aio_wp_security->configs->get_value('aiowps_enable_email_notify')=='1') echo ' checked="checked"'; ?> value="1"/>
                    <span class="description"><?php _e('Check this if you want to receive an email when someone has been locked out due to maximum failed login attempts', 'all-in-one-wp-security-and-firewall'); ?></span>
                    <br /><input type="text" size="30" name="aiowps_email_address" value="<?php echo $aio_wp_security->configs->get_value('aiowps_email_address'); ?>" />
                    <span class="description"><?php _e('Enter an email address', 'all-in-one-wp-security-and-firewall'); ?></span>
                </td> 
            </tr>
        </table>
        <input type="submit" name="aiowps_login_lockdown" value="<?php _e('Save Settings', 'all-in-one-wp-security-and-firewall')?>" class="button-primary" />
        </form>
        </div></div>
        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('Currently Locked Out IP Address Ranges', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
            <div class="aio_blue_box aio_width_80">
                <?php
                $locked_ips_link = '<a href="admin.php?page='.AIOWPSEC_MAIN_MENU_SLUG.'&tab=tab3">Locked IP Addresses</a>';
                echo '<p>'.sprintf( __('To see a list of all locked IP addresses and ranges go to the %s tab in the dashboard menu.', 'all-in-one-wp-security-and-firewall'), $locked_ips_link).'</p>';
                ?>
            </div>
        </div></div>
        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('Login Lockdown IP Whitelist Settings', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
        <form action="" method="POST">
        <?php wp_nonce_field('aiowpsec-lockdown-whitelist-settings-nonce'); ?>            
        <table class="form-table">
            <tr valign="top">
                <th scope="row"><?php _e('Enable Login Lockdown IP Whitelist', 'all-in-one-wp-security-and-firewall')?>:</th>                
                <td>
                <input name="aiowps_lockdown_enable_whitelisting" type="checkbox"<?php if($aio_wp_security->configs->get_value('aiowps_lockdown_enable_whitelisting')=='1') echo ' checked="checked"'; ?> value="1"/>
                <span class="description"><?php _e('Check this if you want to enable the whitelisting of selected IP addresses specified in the settings below', 'all-in-one-wp-security-and-firewall'); ?></span>
                </td>
            </tr>            
            <tr valign="top">
                <th scope="row"><?php _e('Enter Whitelisted IP Addresses:', 'all-in-one-wp-security-and-firewall')?></th>
                <td>
                    <textarea name="aiowps_lockdown_allowed_ip_addresses" rows="5" cols="50"><?php echo ($result == -1)?htmlspecialchars($_POST['aiowps_lockdown_allowed_ip_addresses']):htmlspecialchars($aio_wp_security->configs->get_value('aiowps_lockdown_allowed_ip_addresses')); ?></textarea>
                    <br />
                    <span class="description"><?php _e('Enter one or more IP addresses or IP ranges you wish to include in your whitelist. The addresses specified here will never be blocked by the login lockdown feature.','all-in-one-wp-security-and-firewall');?></span>
                    <span class="aiowps_more_info_anchor"><span class="aiowps_more_info_toggle_char">+</span><span class="aiowps_more_info_toggle_text"><?php _e('More Info', 'all-in-one-wp-security-and-firewall'); ?></span></span>
                    <div class="aiowps_more_info_body">
                            <?php 
                            echo '<p class="description">'.__('Each IP address must be on a new line.', 'all-in-one-wp-security-and-firewall').'</p>';
                            echo '<p class="description">'.__('To specify an IP range use a wildcard "*" character. Acceptable ways to use wildcards is shown in the examples below:', 'all-in-one-wp-security-and-firewall').'</p>';
                            echo '<p class="description">'.__('Example 1: 195.47.89.*', 'all-in-one-wp-security-and-firewall').'</p>';
                            echo '<p class="description">'.__('Example 2: 195.47.*.*', 'all-in-one-wp-security-and-firewall').'</p>';
                            echo '<p class="description">'.__('Example 3: 195.*.*.*', 'all-in-one-wp-security-and-firewall').'</p>';
                            ?>
                    </div>

                </td>
            </tr>
        </table>
        <input type="submit" name="aiowps_save_lockdown_whitelist_settings" value="<?php _e('Save Settings', 'all-in-one-wp-security-and-firewall')?>" class="button-primary" />
        </form>
        </div></div>
        
        <?php
    }

    function render_tab2()
    {
        global $aio_wp_security, $wpdb;
        if (isset($_POST['aiowps_delete_failed_login_records']))
        {
            $nonce=$_REQUEST['_wpnonce'];
            if (!wp_verify_nonce($nonce, 'aiowpsec-delete-failed-login-records-nonce'))
            {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed for delete all failed login records operation!",4);
                die(__('Nonce check failed for delete all failed login records operation!','all-in-one-wp-security-and-firewall'));
            }
            $failed_logins_table = AIOWPSEC_TBL_FAILED_LOGINS;
            //Delete all records from the failed logins table
            $result = $wpdb->query("truncate $failed_logins_table");
                    
            if ($result === FALSE)
            {
                $aio_wp_security->debug_logger->log_debug("User Login Feature - Delete all failed login records operation failed!",4);
                $this->show_msg_error(__('User Login Feature - Delete all failed login records operation failed!','all-in-one-wp-security-and-firewall'));
            } 
            else
            {
                $this->show_msg_updated(__('All records from the Failed Logins table were deleted successfully!','all-in-one-wp-security-and-firewall'));
            }
        }

        include_once 'wp-security-list-login-fails.php'; //For rendering the AIOWPSecurity_List_Table in tab2
        $failed_login_list = new AIOWPSecurity_List_Login_Failed_Attempts(); //For rendering the AIOWPSecurity_List_Table in tab2
        if(isset($_REQUEST['action'])) //Do row action tasks for list table form for failed logins
        {
            if($_REQUEST['action'] == 'delete_failed_login_rec'){ //Delete link was clicked for a row in list table
                $failed_login_list->delete_login_failed_records(strip_tags($_REQUEST['failed_login_id']));
            }
        }
        ?>
        <div class="aio_blue_box">
            <?php
            echo '<p>'.__('This tab displays the failed login attempts for your site.', 'all-in-one-wp-security-and-firewall').'
            <br />'.__('The information below can be handy if you need to do security investigations because it will show you the IP range, username and ID (if applicable) and the time/date of the failed login attempt.', 'all-in-one-wp-security-and-firewall').'
            </p>';
            ?>
        </div>
        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('Failed Login Records', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
            <?php 
            //Fetch, prepare, sort, and filter our data...
            $failed_login_list->prepare_items();
            //echo "put table of locked entries here"; 
            ?>
            <form id="tables-filter" method="get" onSubmit="return confirm('Are you sure you want to perform this bulk operation on the selected entries?');">
            <!-- For plugins, we also need to ensure that the form posts back to our current page -->
            <input type="hidden" name="page" value="<?php echo esc_attr($_REQUEST['page']); ?>" />
            <input type="hidden" name="tab" value="<?php echo esc_attr($_REQUEST['tab']); ?>" />
            <!-- Now we can render the completed list table -->
            <?php $failed_login_list->display(); ?>
            </form>
        </div></div>
        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('Export to CSV', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
        <form action="" method="POST">
        <?php wp_nonce_field('aiowpsec-export-failed-login-records-to-csv-nonce'); ?>
        <table class="form-table">
            <tr valign="top">
            <span class="description"><?php _e('Click this button if you wish to download this log in CSV format.', 'all-in-one-wp-security-and-firewall'); ?></span>
            </tr>            
        </table>
        <input type="submit" name="aiowps_export_failed_login_records_to_csv" value="<?php _e('Export to CSV', 'all-in-one-wp-security-and-firewall')?>" class="button-primary"/>
        </form>
        </div></div>  
        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('Delete All Failed Login Records', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
        <form action="" method="POST">
        <?php wp_nonce_field('aiowpsec-delete-failed-login-records-nonce'); ?>
        <table class="form-table">
            <tr valign="top">
            <span class="description"><?php _e('Click this button if you wish to delete all failed login records in one go.', 'all-in-one-wp-security-and-firewall'); ?></span>
            </tr>            
        </table>
        <input type="submit" name="aiowps_delete_failed_login_records" value="<?php _e('Delete All Failed Login Records', 'all-in-one-wp-security-and-firewall')?>" class="button-primary" onclick="return confirm('Are you sure you want to delete all records?')"/>
        </form>
        </div></div>

        <?php
    }

    function render_tab3()
    {
        global $aio_wp_security;
        global $aiowps_feature_mgr;
        
        if(isset($_POST['aiowpsec_save_force_logout_settings']))//Do form submission tasks
        {
            $error = '';
            $nonce=$_REQUEST['_wpnonce'];
            if (!wp_verify_nonce($nonce, 'aiowpsec-force-logout-settings-nonce'))
            {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed on force logout options save!",4);
                die("Nonce check failed on force logout options save!");
            }

            $logout_time_period = sanitize_text_field($_POST['aiowps_logout_time_period']);
            if(!is_numeric($logout_time_period))
            {
                $error .= '<br />'.__('You entered a non numeric value for the logout time period field. It has been set to the default value.','all-in-one-wp-security-and-firewall');
                $logout_time_period = '1';//Set it to the default value for this field
            }
            else
            {
                if($logout_time_period < 1){
                    $logout_time_period = '1';
                }
            }

            if($error)
            {
                $this->show_msg_error(__('Attention!','all-in-one-wp-security-and-firewall').$error);
            }

            //Save all the form values to the options
            $aio_wp_security->configs->set_value('aiowps_logout_time_period',absint($logout_time_period));
            $aio_wp_security->configs->set_value('aiowps_enable_forced_logout',isset($_POST["aiowps_enable_forced_logout"])?'1':'');
            $aio_wp_security->configs->save_config();
            
            //Recalculate points after the feature status/options have been altered
            $aiowps_feature_mgr->check_feature_status_and_recalculate_points();
            
            $this->show_msg_settings_updated();
        }
        ?>
        <div class="aio_blue_box">
            <?php
            echo '<p>'.__('Setting an expiry period for your WP administration session is a simple way to protect against unauthorized access to your site from your computer.', 'all-in-one-wp-security-and-firewall').'
            <br />'.__('This feature allows you to specify a time period in minutes after which the admin session will expire and the user will be forced to log back in.', 'all-in-one-wp-security-and-firewall').'
            </p>';
            ?>
        </div>
        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('Force User Logout Options', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
        <?php
        //Display security info badge
        global $aiowps_feature_mgr;
        $aiowps_feature_mgr->output_feature_details_badge("user-login-force-logout");
        ?>

        <form action="" method="POST">
        <?php wp_nonce_field('aiowpsec-force-logout-settings-nonce'); ?>
        <table class="form-table">
            <tr valign="top">
                <th scope="row"><?php _e('Enable Force WP User Logout', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td>
                <input name="aiowps_enable_forced_logout" type="checkbox"<?php if($aio_wp_security->configs->get_value('aiowps_enable_forced_logout')=='1') echo ' checked="checked"'; ?> value="1"/>
                <span class="description"><?php _e('Check this if you want to force a wp user to be logged out after a configured amount of time', 'all-in-one-wp-security-and-firewall'); ?></span>
                </td>
            </tr>            
            <tr valign="top">
                <th scope="row"><?php _e('Logout the WP User After XX Minutes', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td><input type="text" size="5" name="aiowps_logout_time_period" value="<?php echo $aio_wp_security->configs->get_value('aiowps_logout_time_period'); ?>" />
                <span class="description"><?php _e('(Minutes) The user will be forced to log back in after this time period has elapased.', 'all-in-one-wp-security-and-firewall'); ?></span>
                </td> 
            </tr>
        </table>
        <input type="submit" name="aiowpsec_save_force_logout_settings" value="<?php _e('Save Settings', 'all-in-one-wp-security-and-firewall')?>" class="button-primary" />
        </form>
        </div></div>        
        <?php
    }
    
    function render_tab4()
    {
        include_once 'wp-security-list-acct-activity.php'; //For rendering the AIOWPSecurity_List_Table in tab4
        $acct_activity_list = new AIOWPSecurity_List_Account_Activity(); //For rendering the AIOWPSecurity_List_Table in tab2
        if(isset($_REQUEST['action'])) //Do row action tasks for list table form for login activity display
        {
            if($_REQUEST['action'] == 'delete_acct_activity_rec'){ //Delete link was clicked for a row in list table
                $acct_activity_list->delete_login_activity_records(strip_tags($_REQUEST['activity_login_rec']));
            }
        }
        if (isset($_POST['aiowpsec_export_to_csv'])) {
            echo'yo';
            die;
        }
        ?>
        <div class="aio_blue_box">
            <?php
            echo '<p>'.__('This tab displays the activity for accounts registered with your site that have logged in using the WordPress login form.', 'all-in-one-wp-security-and-firewall').'
            <br />'.__('The information below can be handy if you need to do security investigations because it will show you the last 50 recent login events by username, IP address and time/date.', 'all-in-one-wp-security-and-firewall').'
            </p>';
            ?>
        </div>
        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('Account Activity Logs', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
            <?php 
            //Fetch, prepare, sort, and filter our data...
            $acct_activity_list->prepare_items();
            //echo "put table of locked entries here"; 
            ?>
            <form id="tables-filter" method="get" onSubmit="return confirm('Are you sure you want to perform this bulk operation on the selected entries?');">
            <!-- For plugins, we also need to ensure that the form posts back to our current page -->
            <input type="hidden" name="page" value="<?php echo esc_attr($_REQUEST['page']); ?>" />
            <input type="hidden" name="tab" value="<?php echo esc_attr($_REQUEST['tab']); ?>" />
            <!-- Now we can render the completed list table -->
            <?php $acct_activity_list->display(); ?>
            </form>
        </div></div>
        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('Export to CSV', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
        <form action="" method="POST">
        <?php wp_nonce_field('aiowpsec-export-acct-activity-logs-to-csv-nonce'); ?>
        <table class="form-table">
            <tr valign="top">
            <span class="description"><?php _e('Click this button if you wish to download this log in CSV format.', 'all-in-one-wp-security-and-firewall'); ?></span>
            </tr>            
        </table>
        <input type="submit" name="aiowpsec_export_acct_activity_logs_to_csv" value="<?php _e('Export to CSV', 'all-in-one-wp-security-and-firewall')?>" class="button-primary"/>
        </form>
        </div></div>  
        <?php
    }
    
    function render_tab5()
    {
        $logged_in_users = (AIOWPSecurity_Utility::is_multisite_install() ? get_site_transient('users_online') : get_transient('users_online'));
        
        global $aio_wp_security;
        include_once 'wp-security-list-logged-in-users.php'; //For rendering the AIOWPSecurity_List_Table
        $user_list = new AIOWPSecurity_List_Logged_In_Users();
        if(isset($_REQUEST['action'])) //Do row action tasks for list table form for login activity display
        {
            if($_REQUEST['action'] == 'force_user_logout'){ //Force Logout link was clicked for a row in list table
                $user_list->force_user_logout(strip_tags($_REQUEST['logged_in_id']), strip_tags($_REQUEST['ip_address']));
            }
        }
        
        if (isset($_POST['aiowps_refresh_logged_in_user_list']))
        {
            $nonce=$_REQUEST['_wpnonce'];
            if (!wp_verify_nonce($nonce, 'aiowpsec-logged-in-users-nonce'))
            {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed for users logged in list!",4);
                die(__('Nonce check failed for users logged in list!','all-in-one-wp-security-and-firewall'));
            }
            
            $user_list->prepare_items();
        }

        ?>
        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('Refresh Logged In User Data', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
        <form action="" method="POST">
        <?php wp_nonce_field('aiowpsec-logged-in-users-nonce'); ?>
        <input type="submit" name="aiowps_refresh_logged_in_user_list" value="<?php _e('Refresh Data', 'all-in-one-wp-security-and-firewall')?>" class="button-primary" />
        </form>
        </div></div>
        
        <div class="aio_blue_box">
            <?php
            echo '<p>'.__('This tab displays all users who are currently logged into your site.', 'all-in-one-wp-security-and-firewall').'
                <br />'.__('If you suspect there is a user or users who are logged in which should not be, you can block them by inspecting the IP addresses from the data below and adding them to your blacklist.', 'all-in-one-wp-security-and-firewall').'
                <br />'.__('You can also instantly log them out by clicking on the "Force Logout" link when you hover over the row in the User Id column.', 'all-in-one-wp-security-and-firewall').'
            </p>';
            ?>
        </div>
        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('Currently Logged In Users', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
            <?php
            //Fetch, prepare, sort, and filter our data...
            $user_list->prepare_items();
            //echo "put table of locked entries here"; 
            ?>
            <form id="tables-filter" method="get" onSubmit="return confirm('Are you sure you want to perform this bulk operation on the selected entries?');">
            <!-- For plugins, we also need to ensure that the form posts back to our current page -->
            <input type="hidden" name="page" value="<?php echo esc_attr($_REQUEST['page']); ?>" />
            <input type="hidden" name="tab" value="<?php echo esc_attr($_REQUEST['tab']); ?>" />
            <!-- Now we can render the completed list table -->
            <?php $user_list->display(); ?>
            </form>
        </div></div>
        <?php

    }

} //end class