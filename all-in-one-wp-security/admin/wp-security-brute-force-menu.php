<?php
if(!defined('ABSPATH')){
    exit;//Exit if accessed directly
}

class AIOWPSecurity_Brute_Force_Menu extends AIOWPSecurity_Admin_Menu
{
    var $menu_page_slug = AIOWPSEC_BRUTE_FORCE_MENU_SLUG;
    
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
        'tab1' => __('Rename Login Page','all-in-one-wp-security-and-firewall'),
        'tab2' => __('Cookie Based Brute Force Prevention', 'all-in-one-wp-security-and-firewall'),
        'tab3' => __('Login Captcha', 'all-in-one-wp-security-and-firewall'),
        'tab4' => __('Login Whitelist', 'all-in-one-wp-security-and-firewall'),
        'tab5' => __('Honeypot', 'all-in-one-wp-security-and-firewall'),
            
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
            if (AIOWPSecurity_Utility::is_multisite_install() && get_current_blog_id() != 1
                && stristr($tab_caption, "Rename Login Page") === false && stristr($tab_caption, "Login Captcha") === false){
                //Suppress the all Brute Force menu tabs if site is a multi site AND not the main site except "rename login" and "captcha"
            }else{
                $active = $current_tab == $tab_key ? 'nav-tab-active' : '';
                echo '<a class="nav-tab ' . $active . '" href="?page=' . $this->menu_page_slug . '&tab=' . $tab_key . '">' . $tab_caption . '</a>';	
            }
        }
        echo '</h2>';
    }
    
    /*
     * The menu rendering goes here
     */
    function render_menu_page() 
    {
        echo '<div class="wrap">';
        echo '<h2>'.__('Brute Force','all-in-one-wp-security-and-firewall').'</h2>';//Interface title
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
        global $wpdb, $aio_wp_security;
        global $aiowps_feature_mgr;
        $aiowps_login_page_slug = '';
        
        if (get_option('permalink_structure')){
            $home_url = trailingslashit(home_url());
        }else{
            $home_url = trailingslashit(home_url()) . '?';
        }

        if(isset($_POST['aiowps_save_rename_login_page_settings']))//Do form submission tasks
        {
            $error = '';
            $nonce=$_REQUEST['_wpnonce'];
            if (!wp_verify_nonce($nonce, 'aiowpsec-rename-login-page-nonce'))
            {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed for rename login page save!",4);
                die("Nonce check failed for rename login page save!");
            }

            if (empty($_POST['aiowps_login_page_slug']) && isset($_POST["aiowps_enable_rename_login_page"])){
                $error .= '<br />'.__('Please enter a value for your login page slug.','all-in-one-wp-security-and-firewall');
            }else if (!empty($_POST['aiowps_login_page_slug'])){
                $aiowps_login_page_slug = sanitize_text_field($_POST['aiowps_login_page_slug']);
                if($aiowps_login_page_slug == 'wp-admin'){
                    $error .= '<br />'.__('You cannot use the value "wp-admin" for your login page slug.','all-in-one-wp-security-and-firewall');
                }elseif(preg_match('/[^a-z_\-0-9]/i', $aiowps_login_page_slug)){
                    $error .= '<br />'.__('You must use alpha numeric characters for your login page slug.','all-in-one-wp-security-and-firewall');
                }
            }
            
            if($error){
                $this->show_msg_error(__('Attention!','all-in-one-wp-security-and-firewall').$error);
            }else{
                $htaccess_res = '';
                $cookie_feature_active = false;
                //Save all the form values to the options
                if (isset($_POST["aiowps_enable_rename_login_page"])){
                    $aio_wp_security->configs->set_value('aiowps_enable_rename_login_page', '1');
                    // check if the cookie based feature was active and deactivate it and delete the directives in .htaccess
                    if($aio_wp_security->configs->get_value('aiowps_enable_brute_force_attack_prevention')){
                        $cookie_feature_active = true;
                        $aio_wp_security->configs->set_value('aiowps_enable_brute_force_attack_prevention', '');//deactivate cookie based feature
                    }
                }else{
                    $aio_wp_security->configs->set_value('aiowps_enable_rename_login_page', '');
                }
                $aio_wp_security->configs->set_value('aiowps_login_page_slug',$aiowps_login_page_slug);
                $aio_wp_security->configs->save_config();

                // if cookie based feature was active previously need to clear those rules out of .htaccess
                if($cookie_feature_active){
                    $htaccess_res = AIOWPSecurity_Utility_Htaccess::write_to_htaccess(); //Delete the cookie based directives
                }

                //Recalculate points after the feature status/options have been altered
                $aiowps_feature_mgr->check_feature_status_and_recalculate_points();
                if ($htaccess_res === false) {
                    $this->show_msg_error(__('Could not delete the Cookie-based directives from the .htaccess file. Please check the file permissions.', 'all-in-one-wp-security-and-firewall'));
                }
                else {
                    $this->show_msg_settings_updated();
                }
                
                /** The following is a fix/workaround for the following issue:
                 * https://wordpress.org/support/topic/applying-brute-force-rename-login-page-not-working/
                 * ie, when saving the rename login config, the logout link does not update on the first page load after the $_POST submit to reflect the new rename login setting.
                 * Added a page refresh to fix this for now until I figure out a better solution.
                 * 
                **/
                $cur_url = "admin.php?page=".AIOWPSEC_BRUTE_FORCE_MENU_SLUG."&tab=tab1";
                AIOWPSecurity_Utility::redirect_to_url($cur_url);
                
            }
        }
        
        ?>
        <div class="aio_blue_box">
            <?php
            $cookie_based_feature_url = '<a href="admin.php?page='.AIOWPSEC_BRUTE_FORCE_MENU_SLUG.'&tab=tab2" target="_blank">'.__('Cookie Based Brute Force Prevention', 'all-in-one-wp-security-and-firewall').'</a>';
            $white_list_feature_url = '<a href="admin.php?page='.AIOWPSEC_BRUTE_FORCE_MENU_SLUG.'&tab=tab4" target="_blank">'.__('Login Page White List', 'all-in-one-wp-security-and-firewall').'</a>';
            echo '<p>'.__('An effective Brute Force prevention technique is to change the default WordPress login page URL.', 'all-in-one-wp-security-and-firewall').'</p>'.
            '<p>'.__('Normally if you wanted to login to WordPress you would type your site\'s home URL followed by wp-login.php.', 'all-in-one-wp-security-and-firewall').'</p>'.
            '<p>'.__('This feature allows you to change the login URL by setting your own slug and renaming the last portion of the login URL which contains the <strong>wp-login.php</strong> to any string that you like.', 'all-in-one-wp-security-and-firewall').'</p>'.
            '<p>'.__('By doing this, malicious bots and hackers will not be able to access your login page because they will not know the correct login page URL.', 'all-in-one-wp-security-and-firewall').'</p>'.
            '<div class="aio_section_separator_1"></div>'.
            '<p>'.__('You may also be interested in the following alternative brute force prevention features:', 'all-in-one-wp-security-and-firewall').'</p>'.
            '<p>'.$cookie_based_feature_url.'</p>'.
            '<p>'.$white_list_feature_url.'</p>';
            ?>
        </div>
        <?php 
        //Show the user the new login URL if this feature is active
        if ($aio_wp_security->configs->get_value('aiowps_enable_rename_login_page')=='1')
        {
        ?>
            <div class="aio_yellow_box">
                <p><?php _e('Your WordPress login page URL has been renamed.', 'all-in-one-wp-security-and-firewall'); ?></p>
                <p><?php _e('Your current login URL is:', 'all-in-one-wp-security-and-firewall'); ?></p>
                <p><strong><?php echo $home_url.$aio_wp_security->configs->get_value('aiowps_login_page_slug'); ?></strong></p>
                <p><strong><?php _e('NOTE: If you already had the Cookie-Based Brute Force Prevention feature active, the plugin has automatically deactivated it because only one of these features can be active at any one time.', 'all-in-one-wp-security-and-firewall'); ?></strong></p>
            </div>
            
        <?php
        }
        ?>
        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('Rename Login Page Settings', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
        <?php
        //Display security info badge
        global $aiowps_feature_mgr;
        $aiowps_feature_mgr->output_feature_details_badge("bf-rename-login-page");
        ?>

        <form action="" method="POST">
        <?php wp_nonce_field('aiowpsec-rename-login-page-nonce'); ?>
        <div class="aio_orange_box">
            <?php
            $read_link = '<a href="https://www.tipsandtricks-hq.com/wordpress-security-and-firewall-plugin#advanced_features_note" target="_blank">'.__('must read this message', 'all-in-one-wp-security-and-firewall').'</a>';
            echo '<p>'.sprintf(__('This feature can lock you out of admin if it doesn\'t work correctly on your site. You %s before activating this feature.', 'all-in-one-wp-security-and-firewall'), $read_link).'</p>';
            echo '<p>'.__("NOTE: If you are hosting your site on WPEngine or a provider which performs server caching, you will need to ask the host support people to NOT cache your renamed login page.", "all-in-one-wp-security-and-firewall").'</p>';
            ?>
        </div>
        <table class="form-table">
            <tr valign="top">
                <th scope="row"><?php _e('Enable Rename Login Page Feature', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td>
                <input name="aiowps_enable_rename_login_page" type="checkbox"<?php if($aio_wp_security->configs->get_value('aiowps_enable_rename_login_page')=='1') echo ' checked="checked"'; ?> value="1"/>
                <span class="description"><?php _e('Check this if you want to enable the rename login page feature', 'all-in-one-wp-security-and-firewall'); ?></span>
                </td>
            </tr>            
            <tr valign="top">
                <th scope="row"><?php _e('Login Page URL', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td><code><?php echo $home_url; ?></code><input type="text" size="15" name="aiowps_login_page_slug" value="<?php echo $aio_wp_security->configs->get_value('aiowps_login_page_slug'); ?>" />
                <span class="description"><?php _e('Enter a string which will represent your secure login page slug. You are enouraged to choose something which is hard to guess and only you will remember.', 'all-in-one-wp-security-and-firewall'); ?></span>
                </td> 
            </tr>
        </table>
        <input type="submit" name="aiowps_save_rename_login_page_settings" value="<?php _e('Save Settings', 'all-in-one-wp-security-and-firewall')?>" class="button-primary" />
        </form>
        </div></div>
        
        <?php
    }
    
    function render_tab2()
    {
        global $aio_wp_security;
        global $aiowps_feature_mgr;
        $error = false;

        //Save settings for brute force cookie method
        if(isset($_POST['aiowps_apply_cookie_based_bruteforce_firewall']))
        {
            $nonce=$_REQUEST['_wpnonce'];
            if (!wp_verify_nonce($nonce, 'aiowpsec-enable-cookie-based-brute-force-prevention'))
            {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed on enable cookie based brute force prevention feature!",4);
                die("Nonce check failed on enable cookie based brute force prevention feature!");
            }           
            
            if(isset($_POST['aiowps_enable_brute_force_attack_prevention']))
            {
                $brute_force_feature_secret_word = sanitize_text_field($_POST['aiowps_brute_force_secret_word']);
                if(empty($brute_force_feature_secret_word)){
                    $brute_force_feature_secret_word = "aiowps_secret";
                }else if(!ctype_alnum($brute_force_feature_secret_word)){
                    $msg = '<p>'.__('Settings have not been saved - your secret word must consist only of alphanumeric characters, ie, letters and/or numbers only!', 'all-in-one-wp-security-and-firewall').'</p>';
                    $error = true;
                }
                
                if(filter_var($_POST['aiowps_cookie_based_brute_force_redirect_url'], FILTER_VALIDATE_URL))
                {
                    $aio_wp_security->configs->set_value('aiowps_cookie_based_brute_force_redirect_url',esc_url_raw($_POST['aiowps_cookie_based_brute_force_redirect_url']));
                }
                else
                {
                    $aio_wp_security->configs->set_value('aiowps_cookie_based_brute_force_redirect_url','http://127.0.0.1');
                }

                $aio_wp_security->configs->set_value('aiowps_enable_brute_force_attack_prevention','1');
                $aio_wp_security->configs->set_value('aiowps_enable_rename_login_page',''); //Disable the Rename Login Page feature
                
                if (!$error)
                {
                    $aio_wp_security->configs->set_value('aiowps_brute_force_secret_word',$brute_force_feature_secret_word);
                    $msg = '<p>'.__('You have successfully enabled the cookie based brute force prevention feature', 'all-in-one-wp-security-and-firewall').'</p>';
                    $msg .= '<p>'.__('From now on you will need to log into your WP Admin using the following URL:', 'all-in-one-wp-security-and-firewall').'</p>';
                    $msg .= '<p><strong>'.AIOWPSEC_WP_URL.'/?'.$brute_force_feature_secret_word.'=1</strong></p>';
                    $msg .= '<p>'.__('It is important that you save this URL value somewhere in case you forget it, OR,', 'all-in-one-wp-security-and-firewall').'</p>';
                    $msg .= '<p>'.sprintf( __('simply remember to add a "?%s=1" to your current site URL address.', 'all-in-one-wp-security-and-firewall'), $brute_force_feature_secret_word).'</p>';
                }
            }
            else
            {
                $aio_wp_security->configs->set_value('aiowps_enable_brute_force_attack_prevention','');
                $msg = __('You have successfully saved cookie based brute force prevention feature settings.', 'all-in-one-wp-security-and-firewall');
            }
            
            if(isset($_POST['aiowps_brute_force_attack_prevention_pw_protected_exception']))
            {
                $aio_wp_security->configs->set_value('aiowps_brute_force_attack_prevention_pw_protected_exception','1');
            }
            else
            {
                $aio_wp_security->configs->set_value('aiowps_brute_force_attack_prevention_pw_protected_exception','');
            }

            if(isset($_POST['aiowps_brute_force_attack_prevention_ajax_exception']))
            {
                $aio_wp_security->configs->set_value('aiowps_brute_force_attack_prevention_ajax_exception','1');
            }
            else
            {
                $aio_wp_security->configs->set_value('aiowps_brute_force_attack_prevention_ajax_exception','');
            }

            if (!$error)
            {
                $aio_wp_security->configs->save_config();//save the value

                //Recalculate points after the feature status/options have been altered
                $aiowps_feature_mgr->check_feature_status_and_recalculate_points();

                $res = AIOWPSecurity_Utility_Htaccess::write_to_htaccess();
                if ($res) {
                    echo '<div id="message" class="updated fade"><p>';
                    echo $msg;
                    echo '</p></div>';
                }
                else {
                    $this->show_msg_error(__('Could not write to the .htaccess file. Please check the file permissions.', 'all-in-one-wp-security-and-firewall'));
                }
            }
            else
            {
                $this->show_msg_error($msg);
            }
        }

        ?>
        <h2><?php _e('Brute Force Prevention Firewall Settings', 'all-in-one-wp-security-and-firewall')?></h2>
        
        <div class="aio_blue_box">
            <?php
            //TODO - need to fix the following message
            echo '<p>'.__('A Brute Force Attack is when a hacker tries many combinations of usernames and passwords until they succeed in guessing the right combination.', 'all-in-one-wp-security-and-firewall').
            '<br />'.__('Due to the fact that at any one time there may be many concurrent login attempts occurring on your site via malicious automated robots, this also has a negative impact on your server\'s memory and performance.', 'all-in-one-wp-security-and-firewall').
            '<br />'.__('The features in this tab will stop the majority of Brute Force Login Attacks at the .htaccess level thus providing even better protection for your WP login page and also reducing the load on your server because the system does not have to run PHP code to process the login attempts.', 'all-in-one-wp-security-and-firewall').'</p>';
            ?>
        </div>
        <div class="aio_yellow_box">
            <?php
            $backup_tab_link = '<a href="admin.php?page='.AIOWPSEC_SETTINGS_MENU_SLUG.'&tab=tab2" target="_blank">'.__('backup', 'all-in-one-wp-security-and-firewall').'</a>';
            $video_link = '<a href="https://www.tipsandtricks-hq.com/all-in-one-wp-security-plugin-cookie-based-brute-force-login-attack-prevention-feature-5994" target="_blank">'.__('video tutorial', 'all-in-one-wp-security-and-firewall').'</a>';
            $info_msg = sprintf( __('Even though this feature should not have any impact on your site\'s general functionality <strong>you are strongly encouraged to take a %s of your .htaccess file before proceeding</strong>.', 'all-in-one-wp-security-and-firewall'), $backup_tab_link);
            $info_msg1 = __('If this feature is not used correctly, you can get locked out of your site. A backed up .htaccess file will come in handy if that happens.', 'all-in-one-wp-security-and-firewall');
            $info_msg2 = sprintf( __('To learn more about how to use this feature please watch the following %s.', 'all-in-one-wp-security-and-firewall'), $video_link);
            $brute_force_login_feature_link = '<a href="admin.php?page='.AIOWPSEC_FIREWALL_MENU_SLUG.'&tab=tab4" target="_blank">'.__('Cookie-Based Brute Force Login Prevention', 'all-in-one-wp-security-and-firewall').'</a>';
            echo '<p>'.$info_msg.
            '<br />'.$info_msg1.
            '<br />'.$info_msg2.'</p>';
            ?>
        </div>
        <?php 
        //Show the user the new login URL if this feature is active
        if ($aio_wp_security->configs->get_value('aiowps_enable_brute_force_attack_prevention')=='1')
        {
        ?>
            <div class="aio_yellow_box">
                <p><strong><?php _e('NOTE: If you already had the Rename Login Page feature active, the plugin has automatically deactivated it because only one of these features can be active at any one time.', 'all-in-one-wp-security-and-firewall'); ?></strong></p>
            </div>
            
        <?php
        }
        ?>

        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('Cookie Based Brute Force Login Prevention', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
        <?php
        //Display security info badge
        global $aiowps_feature_mgr;
        $aiowps_feature_mgr->output_feature_details_badge("firewall-enable-brute-force-attack-prevention");
        ?>
        <form action="" method="POST">
        <?php wp_nonce_field('aiowpsec-enable-cookie-based-brute-force-prevention'); ?>
        <div class="aio_orange_box">
            <p>
            <?php _e('This feature can lock you out of admin if it doesn\'t work correctly on your site. You <a href="https://www.tipsandtricks-hq.com/wordpress-security-and-firewall-plugin#advanced_features_note" target="_blank">'.__('must read this message', 'all-in-one-wp-security-and-firewall').'</a> before activating this feature.', 'all-in-one-wp-security-and-firewall'); ?>
            </p>
        </div>            
        <table class="form-table">
            <tr valign="top">
                <th scope="row"><?php _e('Enable Brute Force Attack Prevention', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td>
                <input name="aiowps_enable_brute_force_attack_prevention" type="checkbox"<?php if($aio_wp_security->configs->get_value('aiowps_enable_brute_force_attack_prevention')=='1') echo ' checked="checked"'; ?> value="1"/>
                <span class="description"><?php _e('Check this if you want to protect your login page from Brute Force Attack.', 'all-in-one-wp-security-and-firewall'); ?></span>
                <span class="aiowps_more_info_anchor"><span class="aiowps_more_info_toggle_char">+</span><span class="aiowps_more_info_toggle_text"><?php _e('More Info', 'all-in-one-wp-security-and-firewall'); ?></span></span>
                <div class="aiowps_more_info_body">
                    <p class="description">
                        <?php 
                        _e('This feature will deny access to your WordPress login page for all people except those who have a special cookie in their browser.', 'all-in-one-wp-security-and-firewall');
                        echo '<br />';
                        _e('To use this feature do the following:', 'all-in-one-wp-security-and-firewall');
                        echo '<br />';
                        _e('1) Enable the checkbox.', 'all-in-one-wp-security-and-firewall');
                        echo '<br />';
                        _e('2) Enter a secret word consisting of alphanumeric characters which will be difficult to guess. This secret word will be useful whenever you need to know the special URL which you will use to access the login page (see point below).', 'all-in-one-wp-security-and-firewall');
                        echo '<br />';
                        _e('3) You will then be provided with a special login URL. You will need to use this URL to login to your WordPress site instead of the usual login URL. NOTE: The system will deposit a special cookie in your browser which will allow you access to the WordPress administration login page.', 'all-in-one-wp-security-and-firewall');
                        echo '<br />';
                        _e('Any person trying to access your login page who does not have the special cookie in their browser will be automatically blocked.', 'all-in-one-wp-security-and-firewall');
                        ?>
                    </p>
                </div>
                </td>
            </tr>
            <tr valign="top">
                <th scope="row"><?php _e('Secret Word', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td><input type="text" size="40" name="aiowps_brute_force_secret_word" value="<?php echo $aio_wp_security->configs->get_value('aiowps_brute_force_secret_word'); ?>" />
                <span class="description"><?php _e('Choose a secret word consisting of alphanumeric characters which you can use to access your special URL. Your are highly encouraged to choose a word which will be difficult to guess.', 'all-in-one-wp-security-and-firewall'); ?></span>
                </td> 
            </tr>
            <tr valign="top">
                <th scope="row"><?php _e('Re-direct URL', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td><input type="text" size="40" name="aiowps_cookie_based_brute_force_redirect_url" value="<?php echo $aio_wp_security->configs->get_value('aiowps_cookie_based_brute_force_redirect_url'); ?>" />
                <span class="description">
                    <?php 
                    _e('Specify a URL to redirect a hacker to when they try to access your WordPress login page.', 'all-in-one-wp-security-and-firewall');
                    ?>
                </span>
                <span class="aiowps_more_info_anchor"><span class="aiowps_more_info_toggle_char">+</span><span class="aiowps_more_info_toggle_text"><?php _e('More Info', 'all-in-one-wp-security-and-firewall'); ?></span></span>
                <div class="aiowps_more_info_body">
                    <p class="description">
                        <?php 
                    _e('The URL specified here can be any site\'s URL and does not have to be your own. For example you can be as creative as you like and send hackers to the CIA or NSA home page.', 'all-in-one-wp-security-and-firewall');
                    echo '<br />';
                    _e('This field will default to: http://127.0.0.1 if you do not enter a value.', 'all-in-one-wp-security-and-firewall');
                    echo '<br />';
                    _e('Useful Tip:', 'all-in-one-wp-security-and-firewall');
                    echo '<br />';
                    _e('It\'s a good idea to not redirect attempted brute force login attempts to your site because it increases the load on your server.', 'all-in-one-wp-security-and-firewall');
                    echo '<br />';
                    _e('Redirecting a hacker or malicious bot back to "http://127.0.0.1" is ideal because it deflects them back to their own local host and puts the load on their server instead of yours.', 'all-in-one-wp-security-and-firewall');
                        ?>
                    </p>
                </div>
                </td> 
            </tr>
            <tr valign="top">
                <th scope="row"><?php _e('My Site Has Posts Or Pages Which Are Password Protected', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td>
                <input name="aiowps_brute_force_attack_prevention_pw_protected_exception" type="checkbox"<?php if($aio_wp_security->configs->get_value('aiowps_brute_force_attack_prevention_pw_protected_exception')=='1') echo ' checked="checked"'; ?> value="1"/>
                <span class="description"><?php _e('Check this if you are using the native WordPress password protection feature for some or all of your blog posts or pages.', 'all-in-one-wp-security-and-firewall'); ?></span>
                <span class="aiowps_more_info_anchor"><span class="aiowps_more_info_toggle_char">+</span><span class="aiowps_more_info_toggle_text"><?php _e('More Info', 'all-in-one-wp-security-and-firewall'); ?></span></span>
                <div class="aiowps_more_info_body">
                    <p class="description">
                        <?php 
                        _e('In the cases where you are protecting some of your posts or pages using the in-built WordPress password protection feature, a few extra lines of directives and exceptions need to be added to your .htacces file so that people trying to access pages are not automatically blocked.', 'all-in-one-wp-security-and-firewall');
                        echo '<br />';
                        _e('By enabling this checkbox the plugin will add the necessary rules and exceptions to your .htacces file so that people trying to access these pages are not automatically blocked.', 'all-in-one-wp-security-and-firewall');
                        echo '<br />';
                        echo "<strong>".__('Helpful Tip:', 'all-in-one-wp-security-and-firewall')."</strong>";
                        echo '<br />';
                        _e('If you do not use the WordPress password protection feature for your posts or pages then it is highly recommended that you leave this checkbox disabled.', 'all-in-one-wp-security-and-firewall');
                        ?>
                    </p>
                </div>
                </td>
            </tr>
            <tr valign="top">
                <th scope="row"><?php _e('My Site Has a Theme or Plugins Which Use AJAX', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td>
                <input name="aiowps_brute_force_attack_prevention_ajax_exception" type="checkbox"<?php if($aio_wp_security->configs->get_value('aiowps_brute_force_attack_prevention_ajax_exception')=='1') echo ' checked="checked"'; ?> value="1"/>
                <span class="description"><?php _e('Check this if your site uses AJAX functionality.', 'all-in-one-wp-security-and-firewall'); ?></span>
                <span class="aiowps_more_info_anchor"><span class="aiowps_more_info_toggle_char">+</span><span class="aiowps_more_info_toggle_text"><?php _e('More Info', 'all-in-one-wp-security-and-firewall'); ?></span></span>
                <div class="aiowps_more_info_body">
                    <p class="description">
                        <?php 
                        _e('In the cases where your WordPress installation has a theme or plugins which use AJAX, a few extra lines of directives and exceptions need to be added to your .htacces file to prevent AJAX requests from being automatically blocked by the brute force prevention feature.', 'all-in-one-wp-security-and-firewall');
                        echo '<br />';
                        _e('By enabling this checkbox the plugin will add the necessary rules and exceptions to your .htacces file so that AJAX operations will work as expected.', 'all-in-one-wp-security-and-firewall');
                        ?>
                    </p>
                </div>
                </td>
            </tr>
        </table>
        <?php
        $cookie_test_value = $aio_wp_security->configs->get_value('aiowps_cookie_test_success');
        $bfla_feature_enabled = $aio_wp_security->configs->get_value('aiowps_enable_brute_force_attack_prevention');
        if($cookie_test_value == '1' || $bfla_feature_enabled == '1')//If the cookie test is successful or if the feature is already enabled then go ahead as normal
        {
            if (isset($_REQUEST['aiowps_cookie_test']))
            {//Cookie test was just performed and the test succeded
                echo '<div class="aio_green_box"><p>';
                _e('The cookie test was successful. You can now enable this feature.', 'all-in-one-wp-security-and-firewall');
                echo '</p></div>';
            }            
            echo '<input type="submit" name="aiowps_apply_cookie_based_bruteforce_firewall" value="'.__('Save Feature Settings', 'all-in-one-wp-security-and-firewall').'" class="button-primary" />';
        }
        else
        {
            //Cookie test needs to be performed
            if(isset($_REQUEST['aiowps_cookie_test']) && $cookie_test_value != '1'){//Test failed
                echo '<div class="aio_red_box"><p>';
                _e('The cookie test failed on this server. So this feature cannot be used on this site.', 'all-in-one-wp-security-and-firewall');
                echo '</p></div>';
            }
            
            echo '<div class="aio_yellow_box"><p>';
            _e("Before using this feature you are required to perform a cookie test first. This is to make sure that your browser cookie is working correctly and that you won't lock yourself out.", 'all-in-one-wp-security-and-firewall');
            echo '</p></div>';
            echo '<input type="submit" name="aiowps_do_cookie_test_for_bfla" value="'.__('Perform Cookie Test', 'all-in-one-wp-security-and-firewall').'" class="button-primary" />';
        }
        ?>
        </form>
        </div></div>
        <?php
    }
    
    function render_tab3()
    {
        global $aio_wp_security;
        global $aiowps_feature_mgr;
        
        if(isset($_POST['aiowpsec_save_captcha_settings']))//Do form submission tasks
        {
            $error = '';
            $nonce=$_REQUEST['_wpnonce'];
            if (!wp_verify_nonce($nonce, 'aiowpsec-captcha-settings-nonce'))
            {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed on captcha settings save!",4);
                die("Nonce check failed on captcha settings save!");
            }


            //Save all the form values to the options
            $random_20_digit_string = AIOWPSecurity_Utility::generate_alpha_numeric_random_string(20); //Generate random 20 char string for use during captcha encode/decode
            $aio_wp_security->configs->set_value('aiowps_captcha_secret_key', $random_20_digit_string);
            $aio_wp_security->configs->set_value('aiowps_enable_login_captcha',isset($_POST["aiowps_enable_login_captcha"])?'1':'');
            $aio_wp_security->configs->set_value('aiowps_enable_woo_login_captcha',isset($_POST["aiowps_enable_woo_login_captcha"])?'1':'');
            $aio_wp_security->configs->set_value('aiowps_enable_woo_register_captcha',isset($_POST["aiowps_enable_woo_register_captcha"])?'1':'');
            $aio_wp_security->configs->set_value('aiowps_enable_woo_lostpassword_captcha',isset($_POST["aiowps_enable_woo_lostpassword_captcha"])?'1':'');
            $aio_wp_security->configs->set_value('aiowps_enable_custom_login_captcha',isset($_POST["aiowps_enable_custom_login_captcha"])?'1':'');
            $aio_wp_security->configs->set_value('aiowps_enable_lost_password_captcha',isset($_POST["aiowps_enable_lost_password_captcha"])?'1':'');
            
            // if secret key is masked then don't resave it or the site key
            $secret_key = sanitize_text_field($_POST["aiowps_recaptcha_secret_key"]);
            if(strpos($secret_key, '********') === false){
                $aio_wp_security->configs->set_value('aiowps_recaptcha_site_key',sanitize_text_field($_POST["aiowps_recaptcha_site_key"]));
                $aio_wp_security->configs->set_value('aiowps_recaptcha_secret_key',sanitize_text_field($_POST["aiowps_recaptcha_secret_key"]));
            }
            
            $aio_wp_security->configs->set_value('aiowps_default_recaptcha',isset($_POST["aiowps_default_recaptcha"])?'1':'');//Checkbox
            $aio_wp_security->configs->save_config();
            
            //Recalculate points after the feature status/options have been altered
            $aiowps_feature_mgr->check_feature_status_and_recalculate_points();
            
            $this->show_msg_settings_updated();
        }
        
        $secret_key_masked = AIOWPSecurity_Utility::mask_string($aio_wp_security->configs->get_value('aiowps_recaptcha_secret_key'));
        ?>
        <div class="aio_blue_box">
            <?php
            $recaptcha_link = '<a href="https://www.google.com/recaptcha" target="_blank">Google reCAPTCHA v2</a>';
            echo sprintf('<p>'.__('This feature allows you to add a captcha form on various WordPress login pages and forms.', 'all-in-one-wp-security-and-firewall').'
            <br />'.__('Adding a captcha form on a login page or form is another effective yet simple "Brute Force" prevention technique.', 'all-in-one-wp-security-and-firewall').'
            <br />'.__('You have the option of using either %s or a plain maths captcha form.', 'all-in-one-wp-security-and-firewall').'
            <br />'.__('If you enable Google reCAPTCHA the reCAPTCHA widget will be displayed for all forms the captcha settings below.', 'all-in-one-wp-security-and-firewall').'
            <br />'.__('If Google reCAPTCHA is disabled the simple maths captcha form will apply and users will need to enter the answer to a simple mathematical question.', 'all-in-one-wp-security-and-firewall').'
            </p>', $recaptcha_link);
            ?>
        </div>
        <form action="" method="POST">
        <?php wp_nonce_field('aiowpsec-captcha-settings-nonce'); ?>
        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('Google reCAPTCHA Settings', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
        <div class="aio_orange_box">
            <p>
            <?php
            echo __('By enabling these settings the Google reCAPTCHA v2 widget will be applied by default for all forms with captcha enabled.', 'all-in-one-wp-security-and-firewall');
            ?>
            </p>
        </div>            
            
        <table class="form-table">
            <tr valign="top">
                <th scope="row"><?php _e('Use Google reCAPTCHA as default', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td>
                <input name="aiowps_default_recaptcha" type="checkbox"<?php if($aio_wp_security->configs->get_value('aiowps_default_recaptcha')=='1') echo ' checked="checked"'; ?> value="1"/>
                <span class="description"><?php _e('Check this if you want to default to Google reCAPTCHA for all settings below. (If this is left unchecked, all captcha forms will revert to the plain maths captcha)', 'all-in-one-wp-security-and-firewall'); ?></span>
                </td>
            </tr>            
            <tr valign="top">
                <th scope="row"><?php _e('Site Key', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td><input type="text" size="50" name="aiowps_recaptcha_site_key" value="<?php echo esc_html( $aio_wp_security->configs->get_value('aiowps_recaptcha_site_key') ); ?>" />
                </td> 
            </tr>
            <tr valign="top">
                <th scope="row"><?php _e('Secret Key', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td><input type="text" size="50" name="aiowps_recaptcha_secret_key" value="<?php echo esc_html( $secret_key_masked ); ?>" />
                </td> 
            </tr>
        </table>
        </div></div>        
        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('Login Form Captcha Settings', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
        <?php
        //Display security info badge
        global $aiowps_feature_mgr;
        $aiowps_feature_mgr->output_feature_details_badge("user-login-captcha");
        ?>
        <table class="form-table">
            <tr valign="top">
                <th scope="row"><?php _e('Enable Captcha On Login Page', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td>
                <input name="aiowps_enable_login_captcha" type="checkbox"<?php if($aio_wp_security->configs->get_value('aiowps_enable_login_captcha')=='1') echo ' checked="checked"'; ?> value="1"/>
                <span class="description"><?php _e('Check this if you want to insert a captcha form on the login page', 'all-in-one-wp-security-and-firewall'); ?></span>
                </td>
            </tr>            
        </table>
        </div></div>
        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('Lost Password Form Captcha Settings', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
        <?php
        //Display security info badge
        global $aiowps_feature_mgr;
        $aiowps_feature_mgr->output_feature_details_badge("lost-password-captcha");
        ?>

        <table class="form-table">
            <tr valign="top">
                <th scope="row"><?php _e('Enable Captcha On Lost Password Page', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td>
                <input name="aiowps_enable_lost_password_captcha" type="checkbox"<?php if($aio_wp_security->configs->get_value('aiowps_enable_lost_password_captcha')=='1') echo ' checked="checked"'; ?> value="1"/>
                <span class="description"><?php _e('Check this if you want to insert a captcha form on the lost password page', 'all-in-one-wp-security-and-firewall'); ?></span>
                </td>
            </tr>            
        </table>
        </div></div>        
        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('Custom Login Form Captcha Settings', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
        <?php
        //Display security info badge
        global $aiowps_feature_mgr;
        $aiowps_feature_mgr->output_feature_details_badge("custom-login-captcha");
        ?>
        <table class="form-table">
            <tr valign="top">
                <th scope="row"><?php _e('Enable Captcha On Custom Login Form', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td>
                <input name="aiowps_enable_custom_login_captcha" type="checkbox"<?php if($aio_wp_security->configs->get_value('aiowps_enable_custom_login_captcha')=='1') echo ' checked="checked"'; ?> value="1"/>
                <span class="description"><?php _e('Check this if you want to insert captcha on a custom login form generated by the following WP function: wp_login_form()', 'all-in-one-wp-security-and-firewall'); ?></span>
                </td>
            </tr>            
        </table>
        </div></div> 
        <?php
        // Only display woocommerce captcha settings if woo is active 
        if ( in_array( 'woocommerce/woocommerce.php', apply_filters( 'active_plugins', get_option( 'active_plugins' ) ) ) ) {
        ?>
        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('Woocommerce Forms Captcha Settings', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
        <?php
        //Display security info badge
        global $aiowps_feature_mgr;
        $aiowps_feature_mgr->output_feature_details_badge("woo-login-captcha");
        ?>
        <table class="form-table">
            <tr valign="top">
                <th scope="row"><?php _e('Enable Captcha On Woocommerce Login Form', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td>
                <input name="aiowps_enable_woo_login_captcha" type="checkbox"<?php if($aio_wp_security->configs->get_value('aiowps_enable_woo_login_captcha')=='1') echo ' checked="checked"'; ?> value="1"/>
                <span class="description"><?php _e('Check this if you want to insert captcha on a Woocommerce login form', 'all-in-one-wp-security-and-firewall'); ?></span>
                </td>
            </tr>            
        </table>
            <hr>
        <?php
        $aiowps_feature_mgr->output_feature_details_badge("woo-lostpassword-captcha");
        ?>
        <table class="form-table">
            <tr valign="top">
                <th scope="row"><?php _e('Enable Captcha On Woocommerce Lost Password Form', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td>
                <input name="aiowps_enable_woo_lostpassword_captcha" type="checkbox"<?php if($aio_wp_security->configs->get_value('aiowps_enable_woo_lostpassword_captcha')=='1') echo ' checked="checked"'; ?> value="1"/>
                <span class="description"><?php _e('Check this if you want to insert captcha on a Woocommerce lost password form', 'all-in-one-wp-security-and-firewall'); ?></span>
                </td>
            </tr>            
        </table>
            <hr>
        <?php
        $aiowps_feature_mgr->output_feature_details_badge("woo-register-captcha");
        ?>
        <table class="form-table">
            <tr valign="top">
                <th scope="row"><?php _e('Enable Captcha On Woocommerce Registration Form', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td>
                <input name="aiowps_enable_woo_register_captcha" type="checkbox"<?php if($aio_wp_security->configs->get_value('aiowps_enable_woo_register_captcha')=='1') echo ' checked="checked"'; ?> value="1"/>
                <span class="description"><?php _e('Check this if you want to insert captcha on a Woocommerce registration form', 'all-in-one-wp-security-and-firewall'); ?></span>
                </td>
            </tr>            
        </table>
        </div></div>
        <?php
        }        
        ?>       
                   
        <input type="submit" name="aiowpsec_save_captcha_settings" value="<?php _e('Save Settings', 'all-in-one-wp-security-and-firewall')?>" class="button-primary" />
        </form>
        <?php
    }
    
    function render_tab4() 
    {
        global $aio_wp_security;
        global $aiowps_feature_mgr;
        $result = 1;
        $your_ip_address = AIOWPSecurity_Utility_IP::get_user_ip_address();
        if (isset($_POST['aiowps_save_whitelist_settings']))
        {
            $nonce=$_REQUEST['_wpnonce'];
            if (!wp_verify_nonce($nonce, 'aiowpsec-whitelist-settings-nonce'))
            {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed for save whitelist settings!",4);
                die(__('Nonce check failed for save whitelist settings!','all-in-one-wp-security-and-firewall'));
            }
            
            if (isset($_POST["aiowps_enable_whitelisting"]) && empty($_POST['aiowps_allowed_ip_addresses']))
            {
                $this->show_msg_error('You must submit at least one IP address!','all-in-one-wp-security-and-firewall');
            }
            else
            {
                if (!empty($_POST['aiowps_allowed_ip_addresses']))
                {
                    $ip_addresses = $_POST['aiowps_allowed_ip_addresses'];
                    $ip_list_array = AIOWPSecurity_Utility_IP::create_ip_list_array_from_string_with_newline($ip_addresses);
                    $payload = AIOWPSecurity_Utility_IP::validate_ip_list($ip_list_array, 'whitelist');
                    if($payload[0] == 1){
                        //success case
                        $result = 1;
                        $list = $payload[1];
                        $whitelist_ip_data = implode(PHP_EOL, $list);
                        $aio_wp_security->configs->set_value('aiowps_allowed_ip_addresses',$whitelist_ip_data);
                        $_POST['aiowps_allowed_ip_addresses'] = ''; //Clear the post variable for the banned address list
                    }
                    else{
                        $result = -1;
                        $error_msg = htmlspecialchars($payload[1][0]);
                        $this->show_msg_error($error_msg);
                    }
                    
                }
                else
                {
                    $aio_wp_security->configs->set_value('aiowps_allowed_ip_addresses',''); //Clear the IP address config value
                }

                if ($result == 1)
                {
                    $aio_wp_security->configs->set_value('aiowps_enable_whitelisting',isset($_POST["aiowps_enable_whitelisting"])?'1':'');
                    $aio_wp_security->configs->save_config(); //Save the configuration
                    
                    //Recalculate points after the feature status/options have been altered
                    $aiowps_feature_mgr->check_feature_status_and_recalculate_points();
                    
                    $this->show_msg_settings_updated();

                    $write_result = AIOWPSecurity_Utility_Htaccess::write_to_htaccess(); //now let's write to the .htaccess file
                    if ( !$write_result )
                    {
                        $this->show_msg_error(__('The plugin was unable to write to the .htaccess file. Please edit file manually.','all-in-one-wp-security-and-firewall'));
                        $aio_wp_security->debug_logger->log_debug("AIOWPSecurity_whitelist_Menu - The plugin was unable to write to the .htaccess file.");
                    }
                }
            }
        }
        ?>
        <h2><?php _e('Login Whitelist', 'all-in-one-wp-security-and-firewall')?></h2>
        <div class="aio_blue_box">
            <?php
            echo '<p>'.__('The All In One WP Security Whitelist feature gives you the option of only allowing certain IP addresses or ranges to have access to your WordPress login page.', 'all-in-one-wp-security-and-firewall').'
            <br />'.__('This feature will deny login access for all IP addresses which are not in your whitelist as configured in the settings below.', 'all-in-one-wp-security-and-firewall').'
            <br />'.__('The plugin achieves this by writing the appropriate directives to your .htaccess file.', 'all-in-one-wp-security-and-firewall').'
            <br />'.__('By allowing/blocking IP addresses via the .htaccess file your are using the most secure first line of defence because login access will only be granted to whitelisted IP addresses and other addresses will be blocked as soon as they try to access your login page.', 'all-in-one-wp-security-and-firewall').'
            </p>';
            ?>
        </div>
        <div class="aio_yellow_box">
            <?php
            $brute_force_login_feature_link = '<a href="admin.php?page='.AIOWPSEC_BRUTE_FORCE_MENU_SLUG.'&tab=tab2" target="_blank">'.__('Cookie-Based Brute Force Login Prevention', 'all-in-one-wp-security-and-firewall').'</a>';
            $rename_login_feature_link = '<a href="admin.php?page='.AIOWPSEC_BRUTE_FORCE_MENU_SLUG.'&tab=tab1" target="_blank">'.__('Rename Login Page', 'all-in-one-wp-security-and-firewall').'</a>';
            echo '<p>'.sprintf( __('Attention: If in addition to enabling the white list feature, you also have one of the %s or %s features enabled, <strong>you will still need to use your secret word or special slug in the URL when trying to access your WordPress login page</strong>.', 'all-in-one-wp-security-and-firewall'), $brute_force_login_feature_link, $rename_login_feature_link).'</p>
            <p>'.__('These features are NOT functionally related. Having both of them enabled on your site means you are creating 2 layers of security.', 'all-in-one-wp-security-and-firewall').'</p>';
            ?>
        </div>

        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('Login IP Whitelist Settings', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
        <?php
        //Display security info badge
        global $aiowps_feature_mgr;
        $aiowps_feature_mgr->output_feature_details_badge("whitelist-manager-ip-login-whitelisting");
        ?>    
        <form action="" method="POST">
        <?php wp_nonce_field('aiowpsec-whitelist-settings-nonce'); ?>            
        <table class="form-table">
            <tr valign="top">
                <th scope="row"><?php _e('Enable IP Whitelisting', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td>
                <input name="aiowps_enable_whitelisting" type="checkbox"<?php if($aio_wp_security->configs->get_value('aiowps_enable_whitelisting')=='1') echo ' checked="checked"'; ?> value="1"/>
                <span class="description"><?php _e('Check this if you want to enable the whitelisting of selected IP addresses specified in the settings below', 'all-in-one-wp-security-and-firewall'); ?></span>
                </td>
            </tr>            
            <tr valign="top">
                <th scope="row"><?php _e('Your Current IP Address', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td>
                <input size="20" name="aiowps_user_ip" type="text" value="<?php echo $your_ip_address; ?>" readonly="readonly"/>
                <span class="description"><?php _e('You can copy and paste this address in the text box below if you want to include it in your login whitelist.', 'all-in-one-wp-security-and-firewall'); ?></span>
                </td>
            </tr>            
            <tr valign="top">
                <th scope="row"><?php _e('Enter Whitelisted IP Addresses:', 'all-in-one-wp-security-and-firewall')?></th>
                <td>
                    <textarea name="aiowps_allowed_ip_addresses" rows="5" cols="50"><?php echo ($result == -1)?htmlspecialchars($_POST['aiowps_allowed_ip_addresses']):htmlspecialchars($aio_wp_security->configs->get_value('aiowps_allowed_ip_addresses')); ?></textarea>
                    <br />
                    <span class="description"><?php _e('Enter one or more IP addresses or IP ranges you wish to include in your whitelist. Only the addresses specified here will have access to the WordPress login page.','all-in-one-wp-security-and-firewall');?></span>
                    <span class="aiowps_more_info_anchor"><span class="aiowps_more_info_toggle_char">+</span><span class="aiowps_more_info_toggle_text"><?php _e('More Info', 'all-in-one-wp-security-and-firewall'); ?></span></span>
                    <div class="aiowps_more_info_body">
                            <?php 
                            echo '<p class="description"><strong>'.__('Each IP address must be on a new line.', 'all-in-one-wp-security-and-firewall').'</strong></p>';
                            echo '<p class="description">'.__('To specify an IPv4 range use a wildcard "*" character. Acceptable ways to use wildcards is shown in the examples below:', 'all-in-one-wp-security-and-firewall').'</p>';
                            echo '<p class="description">'.__('Example 1: 195.47.89.*', 'all-in-one-wp-security-and-firewall').'</p>';
                            echo '<p class="description">'.__('Example 2: 195.47.*.*', 'all-in-one-wp-security-and-firewall').'</p>';
                            echo '<p class="description">'.__('Example 3: 195.*.*.*', 'all-in-one-wp-security-and-firewall').'</p>';
                            echo '<p class="description">'.__('Or you can enter an IPv6 address (NOTE: ranges/wildcards are currently not supported for ipv6)', 'all-in-one-wp-security-and-firewall').'</p>';
                            echo '<p class="description">'.__('Example 4: 4102:0:3ea6:79fd:b:46f8:230f:bb05', 'all-in-one-wp-security-and-firewall').'</p>';
                            echo '<p class="description">'.__('Example 5: 2205:0:1ca2:810d::', 'all-in-one-wp-security-and-firewall').'</p>';
                            ?>
                    </div>

                </td>
            </tr>
        </table>
        <input type="submit" name="aiowps_save_whitelist_settings" value="<?php _e('Save Settings', 'all-in-one-wp-security-and-firewall')?>" class="button-primary" />
        </form>
        </div></div>
        <?php
    }
    
    function render_tab5()
    {
        global $aio_wp_security;
        global $aiowps_feature_mgr;
        
        if(isset($_POST['aiowpsec_save_honeypot_settings']))//Do form submission tasks
        {
            $error = '';
            $nonce=$_REQUEST['_wpnonce'];
            if (!wp_verify_nonce($nonce, 'aiowpsec-honeypot-settings-nonce'))
            {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed on honeypot settings save!",4);
                die("Nonce check failed on honeypot settings save!");
            }

            //Save all the form values to the options
            $aio_wp_security->configs->set_value('aiowps_enable_login_honeypot',isset($_POST["aiowps_enable_login_honeypot"])?'1':'');
            $aio_wp_security->configs->save_config();
            
            //Recalculate points after the feature status/options have been altered
            $aiowps_feature_mgr->check_feature_status_and_recalculate_points();
            
            $this->show_msg_settings_updated();
        }
        ?>
        <div class="aio_blue_box">
            <?php
            echo '<p>'.__('This feature allows you to add a special hidden "honeypot" field on the WordPress login page. This will only be visible to robots and not humans.', 'all-in-one-wp-security-and-firewall').'
            <br />'.__('Since robots usually fill in every input field from a login form, they will also submit a value for the special hidden honeypot field.', 'all-in-one-wp-security-and-firewall').'
            <br />'.__('The way honeypots work is that a hidden field is placed somewhere inside a form which only robots will submit. If that field contains a value when the form is submitted then a robot has most likely submitted the form and it is consequently dealt with.', 'all-in-one-wp-security-and-firewall').'
            <br />'.__('Therefore, if the plugin detects that this field has a value when the login form is submitted, then the robot which is attempting to login to your site will be redirected to its localhost address - http://127.0.0.1.', 'all-in-one-wp-security-and-firewall').'
            </p>';
            ?>
        </div>
        <form action="" method="POST">
        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('Login Form Honeypot Settings', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
        <?php
        //Display security info badge
        global $aiowps_feature_mgr;
        $aiowps_feature_mgr->output_feature_details_badge("login-honeypot");
        ?>

        <?php wp_nonce_field('aiowpsec-honeypot-settings-nonce'); ?>
        <table class="form-table">
            <tr valign="top">
                <th scope="row"><?php _e('Enable Honeypot On Login Page', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td>
                <input name="aiowps_enable_login_honeypot" type="checkbox"<?php if($aio_wp_security->configs->get_value('aiowps_enable_login_honeypot')=='1') echo ' checked="checked"'; ?> value="1"/>
                <span class="description"><?php _e('Check this if you want to enable the honeypot feature for the login page', 'all-in-one-wp-security-and-firewall'); ?></span>
                </td>
            </tr>            
        </table>
        </div></div>        
     
        <input type="submit" name="aiowpsec_save_honeypot_settings" value="<?php _e('Save Settings', 'all-in-one-wp-security-and-firewall')?>" class="button-primary" />
        </form>
        <?php
    }
    

} //end class