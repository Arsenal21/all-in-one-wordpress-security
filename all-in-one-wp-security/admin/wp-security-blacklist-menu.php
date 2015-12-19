<?php

class AIOWPSecurity_Blacklist_Menu extends AIOWPSecurity_Admin_Menu
{
    var $menu_page_slug = AIOWPSEC_BLACKLIST_MENU_SLUG;
    
    /* Specify all the tabs of this menu in the following array */
    var $menu_tabs;

    var $menu_tabs_handler = array(
        'tab1' => 'render_tab1',
        );
    
    function __construct() 
    {
        $this->render_menu_page();
    }
    
    function set_menu_tabs() 
    {
        $this->menu_tabs = array(
        'tab1' => __('Ban Users', 'all-in-one-wp-security-and-firewall'),
        );
    }
    
    function get_current_tab() 
    {
        $tab_keys = array_keys($this->menu_tabs);
        $tab = isset( $_GET['tab'] ) ? $_GET['tab'] : $tab_keys[0];
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
        echo '<h2>'.__('Blacklist Manager','all-in-one-wp-security-and-firewall').'</h2>';//Interface title
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
        $result = 1;
        if (isset($_POST['aiowps_save_blacklist_settings']))
        {
            $nonce=$_REQUEST['_wpnonce'];
            if (!wp_verify_nonce($nonce, 'aiowpsec-blacklist-settings-nonce'))
            {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed for save blacklist settings!",4);
                die(__('Nonce check failed for save blacklist settings!','all-in-one-wp-security-and-firewall'));
            }
            
            if (isset($_POST["aiowps_enable_blacklisting"]) && empty($_POST['aiowps_banned_ip_addresses']) && empty($_POST['aiowps_banned_user_agents']))
            {
                $this->show_msg_error('You must submit at least one IP address or one User Agent value or both!','all-in-one-wp-security-and-firewall');
            }
            else
            {
                if (!empty($_POST['aiowps_banned_ip_addresses']))
                {
                    $ip_addresses = $_POST['aiowps_banned_ip_addresses'];
                    $ip_list_array = AIOWPSecurity_Utility_IP::create_ip_list_array_from_string_with_newline($ip_addresses);
                    $payload = AIOWPSecurity_Utility_IP::validate_ip_list($ip_list_array, 'blacklist');
                    if($payload[0] == 1){
                        //success case
                        $result = 1;
                        $list = $payload[1];
                        $banned_ip_data = implode(PHP_EOL, $list);
                        $aio_wp_security->configs->set_value('aiowps_banned_ip_addresses',$banned_ip_data);
                        $_POST['aiowps_banned_ip_addresses'] = ''; //Clear the post variable for the banned address list
                    }
                    else{
                        $result = -1;
                        $error_msg = $payload[1][0];
                        $this->show_msg_error($error_msg);
                    }
                    
                }
                else
                {
                    $aio_wp_security->configs->set_value('aiowps_banned_ip_addresses',''); //Clear the IP address config value
                }

                if (!empty($_POST['aiowps_banned_user_agents']))
                {
                    $result = $result * $this->validate_user_agent_list();
                }else{
                    //clear the user agent list
                    $aio_wp_security->configs->set_value('aiowps_banned_user_agents','');
                }
                
                if ($result == 1)
                {
                    $aio_wp_security->configs->set_value('aiowps_enable_blacklisting',isset($_POST["aiowps_enable_blacklisting"])?'1':'');
                    $aio_wp_security->configs->save_config(); //Save the configuration
                    
                    //Recalculate points after the feature status/options have been altered
                    $aiowps_feature_mgr->check_feature_status_and_recalculate_points();
                    
                    $this->show_msg_settings_updated();

                    $write_result = AIOWPSecurity_Utility_Htaccess::write_to_htaccess(); //now let's write to the .htaccess file
                    if ($write_result == -1)
                    {
                        $this->show_msg_error(__('The plugin was unable to write to the .htaccess file. Please edit file manually.','all-in-one-wp-security-and-firewall'));
                        $aio_wp_security->debug_logger->log_debug("AIOWPSecurity_Blacklist_Menu - The plugin was unable to write to the .htaccess file.");
                    }
                }
            }
        }
        ?>
        <h2><?php _e('Ban IPs or User Agents', 'all-in-one-wp-security-and-firewall')?></h2>
        <div class="aio_blue_box">
            <?php
            echo '<p>'.__('The All In One WP Security Blacklist feature gives you the option of banning certain host IP addresses or ranges and also user agents.', 'all-in-one-wp-security-and-firewall').'
            <br />'.__('This feature will deny total site access for users which have IP addresses or user agents matching those which you have configured in the settings below.', 'all-in-one-wp-security-and-firewall').'
            <br />'.__('The plugin achieves this by making appropriate modifications to your .htaccess file.', 'all-in-one-wp-security-and-firewall').'
            <br />'.__('By blocking people via the .htaccess file your are using the most secure first line of defence which denies all access to blacklisted visitors as soon as they hit your hosting server.', 'all-in-one-wp-security-and-firewall').'
            </p>';
            ?>
        </div>

        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('IP Hosts and User Agent Blacklist Settings', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
        <?php
        //Display security info badge
        global $aiowps_feature_mgr;
        $aiowps_feature_mgr->output_feature_details_badge("blacklist-manager-ip-user-agent-blacklisting");
        ?>    
        <form action="" method="POST">
        <?php wp_nonce_field('aiowpsec-blacklist-settings-nonce'); ?>            
        <table class="form-table">
            <tr valign="top">
                <th scope="row"><?php _e('Enable IP or User Agent Blacklisting', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td>
                <input name="aiowps_enable_blacklisting" type="checkbox"<?php if($aio_wp_security->configs->get_value('aiowps_enable_blacklisting')=='1') echo ' checked="checked"'; ?> value="1"/>
                <span class="description"><?php _e('Check this if you want to enable the banning (or blacklisting) of selected IP addresses and/or user agents specified in the settings below', 'all-in-one-wp-security-and-firewall'); ?></span>
                </td>
            </tr>            
            <tr valign="top">
                <th scope="row"><?php _e('Enter IP Addresses:', 'all-in-one-wp-security-and-firewall')?></th>
                <td>
                    <textarea name="aiowps_banned_ip_addresses" rows="5" cols="50"><?php echo ($result == -1)?$_POST['aiowps_banned_ip_addresses']:$aio_wp_security->configs->get_value('aiowps_banned_ip_addresses'); ?></textarea>
                    <br />
                    <span class="description"><?php _e('Enter one or more IP addresses or IP ranges.','all-in-one-wp-security-and-firewall');?></span>
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
            <tr valign="top">
                <th scope="row"><?php _e('Enter User Agents:', 'all-in-one-wp-security-and-firewall')?></th>
                <td>
                    <textarea name="aiowps_banned_user_agents" rows="5" cols="50"><?php echo ($result == -1)?$_POST['aiowps_banned_user_agents']:$aio_wp_security->configs->get_value('aiowps_banned_user_agents'); ?></textarea>
                    <br />
                    <span class="description">
                        <?php _e('Enter one or more user agent strings.','all-in-one-wp-security-and-firewall');?></span>
                    <span class="aiowps_more_info_anchor"><span class="aiowps_more_info_toggle_char">+</span><span class="aiowps_more_info_toggle_text"><?php _e('More Info', 'all-in-one-wp-security-and-firewall'); ?></span></span>
                    <div class="aiowps_more_info_body">
                            <?php 
                            echo '<p class="description">'.__('Each user agent string must be on a new line.', 'all-in-one-wp-security-and-firewall').'</p>';
                            echo '<p class="description">'.__('Example 1 - A single user agent string to block:', 'all-in-one-wp-security-and-firewall').'</p>';
                            echo '<p class="description">SquigglebotBot</p>';
                            echo '<p class="description">'.__('Example 2 - A list of more than 1 user agent strings to block', 'all-in-one-wp-security-and-firewall').'</p>';
                            echo '<p class="description">baiduspider<br />SquigglebotBot<br />SurveyBot<br />VoidEYE<br />webcrawl.net<br />YottaShopping_Bot</p>';
                            ?>
                    </div>

                </td>
            </tr>
        </table>
        <input type="submit" name="aiowps_save_blacklist_settings" value="<?php _e('Save Settings', 'all-in-one-wp-security-and-firewall')?>" class="button-primary" />
        </form>
        </div></div>
        <?php
    }
    
    function validate_user_agent_list()
    {
        global $aio_wp_security;
        @ini_set('auto_detect_line_endings', true);
        //$errors = '';

        $submitted_agents = explode(PHP_EOL, $_POST['aiowps_banned_user_agents']);
	$agents = array();
	if (!empty($submitted_agents)) 
        {
            foreach ($submitted_agents as $agent)
            {
                $text = sanitize_text_field($agent);
                $agents[] = $text;
            }
        }
        
        if (sizeof($agents) > 1)
        {
            sort( $agents );
            $agents = array_unique($agents, SORT_STRING);
        }
        
        $banned_user_agent_data = implode(PHP_EOL, $agents);
        $aio_wp_security->configs->set_value('aiowps_banned_user_agents',$banned_user_agent_data);
        $_POST['aiowps_banned_user_agents'] = ''; //Clear the post variable for the banned address list
        return 1;
    }
} //end class