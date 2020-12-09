<?php
if(!defined('ABSPATH')){
    exit;//Exit if accessed directly
}

class AIOWPSecurity_User_Accounts_Menu extends AIOWPSecurity_Admin_Menu
{
    var $menu_page_slug = AIOWPSEC_USER_ACCOUNTS_MENU_SLUG;
    
    /* Specify all the tabs of this menu in the following array */
    var $menu_tabs;
    var $menu_tabs_handler = array(
        'tab1' => 'render_tab1', 
        'tab2' => 'render_tab2',
        'tab3' => 'render_tab3',
        );
    function __construct() 
    {
        $this->render_menu_page();
        
        //Add the JS library for password tool - make sure we are on our password tab
        if (isset($_GET['page']) && strpos($_GET['page'], AIOWPSEC_USER_ACCOUNTS_MENU_SLUG ) !== false) {
            if (isset($_GET['tab']) && $_GET['tab'] == 'tab3'){
                wp_enqueue_script('aiowpsec-pw-tool-js');
            }
        }
    }
    
    function set_menu_tabs() 
    {
        $this->menu_tabs = array(
        'tab1' => __('WP Username', 'all-in-one-wp-security-and-firewall'),
        'tab2' => __('Display Name', 'all-in-one-wp-security-and-firewall'),
        'tab3' => __('Password', 'all-in-one-wp-security-and-firewall')
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
        echo '<h2>'.__('User Accounts','all-in-one-wp-security-and-firewall').'</h2>';//Interface title
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
        if (isset($_POST['aiowps_change_admin_username']))//Do form submission tasks
        {
            echo $this->validate_change_username_form();
        }
        ?>
        <h2><?php _e('Admin User Security', 'all-in-one-wp-security-and-firewall')?></h2>
        <div class="aio_blue_box">
            <?php
            echo '<p>'.__('By default, WordPress sets the administrator username to "admin" at installation time.', 'all-in-one-wp-security-and-firewall').'
            <br />'.__('A lot of hackers try to take advantage of this information by attempting "Brute Force Login Attacks" where they repeatedly try to guess the password by using "admin" for username.', 'all-in-one-wp-security-and-firewall').'
            <br />'.__('From a security perspective, changing the default "admin" user name is one of the first and smartest things you should do on your site.', 'all-in-one-wp-security-and-firewall').'
            <br /><br />'.__('This feature will allow you to change your default "admin" user name to a more secure name of your choosing.', 'all-in-one-wp-security-and-firewall').'
            </p>';
            ?>
        </div>
        
        <?php
        //display a list of all administrator accounts for this site
        $postbox_title = __('List of Administrator Accounts', 'all-in-one-wp-security-and-firewall');
        if (AIOWPSecurity_Utility::is_multisite_install()) { //Multi-site: get admin accounts for current site
          $blog_id = get_current_blog_id();
          $this->postbox($postbox_title, $this->get_all_admin_accounts($blog_id));
        } else {
            $this->postbox($postbox_title, $this->get_all_admin_accounts());
        }
        ?>
        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('Change Admin Username', 'all-in-one-wp-security-and-firewall')?></label></h3>
        <div class="inside">
        <?php
        global $aiowps_feature_mgr;
        $aiowps_feature_mgr->output_feature_details_badge("user-accounts-change-admin-user");
        
        if (AIOWPSecurity_Utility::check_user_exists('admin') || AIOWPSecurity_Utility::check_user_exists('Admin')) 
        {
            echo '<div class="aio_red_box"><p>'.__('Your site currently has an account which uses the default "admin" username. It is highly recommended that you change this name to something else. Use the following field to change the admin username.', 'all-in-one-wp-security-and-firewall').'</p></div>';
            ?>
            <form action="" method="POST">
            <?php wp_nonce_field('aiowpsec-change-admin-nonce'); ?>
            <table class="form-table">
                <tr valign="top">
                    <th scope="row"><label for="NewUserName"> <?php _e('New Admin Username', 'all-in-one-wp-security-and-firewall')?>:</label></th>
                    <td><input type="text" size="16" name="aiowps_new_user_name" />
                    <p class="description"><?php _e('Choose a new username for admin.', 'all-in-one-wp-security-and-firewall'); ?></p>
                    </td> 
                </tr>
            </table>
            <input type="submit" name="aiowps_change_admin_username" value="<?php _e('Change Username', 'all-in-one-wp-security-and-firewall')?>" class="button-primary" />
            <div class="aio_spacer_15"></div>
            <p class="description"><?php _e('NOTE: If you are currently logged in as "admin" you will be automatically logged out after changing your username and will be required to log back in.', 'all-in-one-wp-security-and-firewall')?></p>
            </form>          
            <?php 
        }
        else 
        {
            echo '<div id="aios_message" class="aio_green_box"><p><strong>';
            _e ('No action required! ', 'all-in-one-wp-security-and-firewall');
            echo '</strong><br />';
            _e ('Your site does not have any account which uses the default "admin" username. ', 'all-in-one-wp-security-and-firewall');
            _e ('This is good security practice.', 'all-in-one-wp-security-and-firewall');
            echo '</p></div>';
        }
        ?>
        </div>
        </div>
        <?php
    }
    
    function render_tab2()
    {
        ?>
            <h2><?php _e('Display Name Security', 'all-in-one-wp-security-and-firewall')?></h2>
            <div class="aio_blue_box">
                <?php
                echo '<p>'.__('When you submit a post or answer a comment, WordPress will usually display your "nickname".', 'all-in-one-wp-security-and-firewall').'
                <br />'.__('By default the nickname is set to the login (or user) name of your account.', 'all-in-one-wp-security-and-firewall').'
                <br />'.__('From a security perspective, leaving your nickname the same as your user name is bad practice because it gives a hacker at least half of your account\'s login credentials.', 'all-in-one-wp-security-and-firewall').'
                <br /><br />'.__('Therefore to further tighten your site\'s security you are advised to change your <strong>nickname</strong> and <strong>Display name</strong> to be different from your <strong>Username</strong>.', 'all-in-one-wp-security-and-firewall').'
                </p>';
                ?>
            </div>

            <div class="postbox">
            <h3 class="hndle"><label for="title"><?php _e('Modify Accounts With Identical Login Name & Display Name', 'all-in-one-wp-security-and-firewall')?></label></h3>
            <div class="inside">
            <?php
            global $aiowps_feature_mgr;
            $aiowps_feature_mgr->output_feature_details_badge("user-accounts-display-name");

            //now let's find any accounts which have login name same as display name
            $login_nick_name_accounts = AIOWPSecurity_Utility::check_identical_login_and_nick_names();
            if ($login_nick_name_accounts) {
                echo '<div class="aio_red_box"><p>'.__('Your site currently has the following accounts which have an identical login name and display name.', 'all-in-one-wp-security-and-firewall').'
                         <span class="description">('.__('Click on the link to edit the settings of that particular user account', 'all-in-one-wp-security-and-firewall').'</span></p></div>';
            ?>
                <table class="form-table">
                    <?php 
                    $edit_user_page = get_option('siteurl').'/wp-admin/user-edit.php?user_id=';
                    foreach ($login_nick_name_accounts as $usr){
                        echo '<tr valign="top">';
                       // echo '<th scope="row"><label for="UserID'.$usr['ID'].'"> Login Name: </label></th>';
                        echo '<td><a href="'.$edit_user_page.$usr['ID'].'" target="_blank">'.$usr['user_login'].'</a></td>';
                        echo '</tr>';
                    }
                    ?>
                </table>
        <?php 
            } else {
                echo '<div id="aios_message" class="aio_green_box"><p><strong>'.__('No action required.', 'all-in-one-wp-security-and-firewall').'</strong>
                        <br />'.__('Your site does not have a user account where the display name is identical to the username.', 'all-in-one-wp-security-and-firewall').'</p></div>';
            } 
        ?>
            </div>
            </div>   
        <?php
    }
    
    function render_tab3()
    {
        ?>
            <h2><?php _e('Password Tool', 'all-in-one-wp-security-and-firewall')?></h2>
            <div class="aio_blue_box">
                <?php
                echo '<p>'.__('Poor password selection is one of the most common weak points of many sites and is usually the first thing a hacker will try to exploit when attempting to break into your site.', 'all-in-one-wp-security-and-firewall').'</p>'.
                '<p>'.__('Many people fall into the trap of using a simple word or series of numbers as their password. Such a predictable and simple password would take a competent hacker merely minutes to guess your password by using a simple script which cycles through the easy and most common combinations.', 'all-in-one-wp-security-and-firewall').'</p>'.
                '<p>'.__('The longer and more complex your password is the harder it is for hackers to "crack" because more complex passwords require much greater computing power and time.', 'all-in-one-wp-security-and-firewall').'</p>'.
                '<p>'.__('This section contains a useful password strength tool which you can use to check whether your password is sufficiently strong enough.', 'all-in-one-wp-security-and-firewall').'</p>';
                ?>
            </div>

            <div class="postbox">
            <h3 class="hndle"><label for="title"><?php _e('Password Strength Tool', 'all-in-one-wp-security-and-firewall');?></label></h3>
            <div class="inside">
                <div class="aio_grey_box aio_half_width"><p><?php _e('This password tool uses an algorithm which calculates how long it would take for your password to be cracked using the computing power of an off-the-shelf current model desktop PC with high end processor, graphics card and appropriate password cracking software.', 'all-in-one-wp-security-and-firewall');?></p></div>
                <div class="aiowps_password_tool_field">
                    <input size="40" id="aiowps_password_test" name="aiowps_password_test" type="text" />
                    <div class="description"><?php _e('Start typing a password.', 'all-in-one-wp-security-and-firewall'); ?></div>
                </div>
            <div id="aiowps_pw_tool_main">
                <div class="aiowps_password_crack_info_text"><?php _e('It would take a desktop PC approximately', 'all-in-one-wp-security-and-firewall'); ?>
                <div id="aiowps_password_crack_time_calculation"><?php _e('1 sec', 'all-in-one-wp-security-and-firewall'); ?></div> <?php _e('to crack your password!', 'all-in-one-wp-security-and-firewall'); ?></div>
                <!-- The rotating arrow -->
                <div class="arrowCap"></div>
                <div class="arrow"></div>

                <p class="meterText"><?php _e('Password Strength', 'all-in-one-wp-security-and-firewall'); ?></p>
            </div>
            </div>
            </div>   
        <?php
    }

    function validate_change_username_form() 
    {
        global $wpdb;
        global $aio_wp_security;
        $errors = '';
        $nonce=$_REQUEST['_wpnonce'];
        if (!wp_verify_nonce($nonce, 'aiowpsec-change-admin-nonce'))
        {
            $aio_wp_security->debug_logger->log_debug("Nonce check failed on admin username change operation!",4);
            die(__('Nonce check failed on admin username change operation!','all-in-one-wp-security-and-firewall'));
        }
        if (!empty($_POST['aiowps_new_user_name'])) {
            $new_username = sanitize_text_field($_POST['aiowps_new_user_name']);
            if (validate_username($new_username))
            {
                if (AIOWPSecurity_Utility::check_user_exists($new_username)){
                    $errors .= __('Username ', 'all-in-one-wp-security-and-firewall').$new_username.__(' already exists. Please enter another value. ', 'all-in-one-wp-security-and-firewall');
                } 
                else 
                {
                    //let's check if currently logged in username is 'admin'
                    $user = wp_get_current_user();
                    $user_login = $user->user_login;
                    if (strtolower($user_login) == 'admin'){
                        $username_is_admin = TRUE;
                    } else {
                        $username_is_admin = FALSE;
                    }
                    //Now let's change the username
                    $sql = $wpdb->prepare( "UPDATE `" . $wpdb->users . "` SET user_login = '" . esc_sql($new_username) . "' WHERE user_login=%s", "admin" );
                    $result = $wpdb->query($sql);
                    if (!$result) {
                        //There was an error updating the users table
                        $user_update_error = __('The database update operation of the user account failed!', 'all-in-one-wp-security-and-firewall');
                        //TODO## - add error logging here
                        $return_msg = '<div id="message" class="updated fade"><p>'.$user_update_error.'</p></div>';
                        return $return_msg;
                    }

                    //multisite considerations
                    if ( AIOWPSecurity_Utility::is_multisite_install() ) { //process sitemeta if we're in a multi-site situation
                        $oldAdmins = $wpdb->get_var( "SELECT meta_value FROM `" . $wpdb->sitemeta . "` WHERE meta_key = 'site_admins'" );
                        $newAdmins = str_replace( '5:"admin"', strlen( $new_username ) . ':"' . esc_sql( $new_username ) . '"', $oldAdmins );
                        $wpdb->query( "UPDATE `" . $wpdb->sitemeta . "` SET meta_value = '" . esc_sql( $newAdmins ) . "' WHERE meta_key = 'site_admins'" );
                    }

                    //If user is logged in with username "admin" then log user out and send to login page so they can login again
                    if ($username_is_admin) {
                        //Lets logout the user
                        $aio_wp_security->debug_logger->log_debug("Logging User Out with login ".$user_login. " because they changed their username.");
                        $after_logout_url = AIOWPSecurity_Utility::get_current_page_url();
                        $after_logout_payload = array('redirect_to'=>$after_logout_url, 'msg'=>$aio_wp_security->user_login_obj->key_login_msg.'=admin_user_changed', );
                        //Save some of the logout redirect data to a transient
                        AIOWPSecurity_Utility::is_multisite_install() ? set_site_transient('aiowps_logout_payload', $after_logout_payload, 30 * 60) : set_transient('aiowps_logout_payload', $after_logout_payload, 30 * 60);
                        
                        $logout_url = AIOWPSEC_WP_URL.'?aiowpsec_do_log_out=1';
                        $logout_url = AIOWPSecurity_Utility::add_query_data_to_url($logout_url, 'al_additional_data', '1');
                        AIOWPSecurity_Utility::redirect_to_url($logout_url);
                    }
                }
            } 
            else {//An invalid username was entered
                $errors .= __('You entered an invalid username. Please enter another value. ', 'all-in-one-wp-security-and-firewall');
            }
        } 
        else {//No username value was entered
            $errors .= __('Please enter a value for your username. ', 'all-in-one-wp-security-and-firewall');
        }

        if (strlen($errors)> 0){//We have some validation or other error
            $return_msg = '<div id="message" class="error"><p>' . $errors . '</p></div>';
        } 
        else{
            $return_msg = '<div id="message" class="updated fade"><p>'.__('Username Successfully Changed!', 'all-in-one-wp-security-and-firewall').'</p></div>';
        }
        return $return_msg;
    }
    

    /*
     * This function will retrieve all user accounts which have 'administrator' role and will return html code with results in a table
     */
    function get_all_admin_accounts($blog_id='') {
        //TODO: Have included the "blog_id" variable for future use for cases where people want to search particular blog (eg, multi-site)
        if ($blog_id) {
            $admin_users = get_users('blog_id='.$blog_id.'&orderby=login&role=administrator');
        } else {
            $admin_users = get_users('orderby=login&role=administrator');
        }
        //now let's put the results in an HTML table
        $account_output = "";
        if ($admin_users != NULL) {
            $account_output .= '<table>';
            $account_output .= '<tr><th>'.__('Account Login Name', 'all-in-one-wp-security-and-firewall').'</th></tr>';
            foreach ($admin_users as $entry) {
                $account_output .= '<tr>';
                if (strtolower($entry->user_login) == 'admin') {
                    $account_output .= '<td style="color:red; font-weight: bold;">'.$entry->user_login.'</td>';
                }else {
                    $account_output .= '<td>'.$entry->user_login.'</td>';
                }
                $user_acct_edit_link = admin_url('user-edit.php?user_id=' . $entry->ID);
                $account_output .= '<td><a href="'.$user_acct_edit_link.'" target="_blank">'.__('Edit User', 'all-in-one-wp-security-and-firewall').'</a></td>';
                $account_output .= '</tr>';
            }
            $account_output .= '</table>';
	}
        return $account_output;
    }
} //end class