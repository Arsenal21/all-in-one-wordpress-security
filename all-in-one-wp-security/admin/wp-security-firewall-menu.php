<?php
if ( !defined( 'ABSPATH' ) ) { exit; } // Prevent direct access to file
class AIOWPSecurity_Firewall_Menu extends AIOWPSecurity_Admin_Menu
{
    var $menu_page_slug = AIOWPSEC_FIREWALL_MENU_SLUG;
    
    /* Specify all the tabs of this menu in the following array */
    var $menu_tabs;

    var $menu_tabs_handler = array(
        'tab1' => 'render_tab1',
        'tab2' => 'render_tab2',
        'tab3' => 'render_tab3',
        'tab4' => 'render_tab4',
        'tab5' => 'render_tab5',
        'tab6' => 'render_tab6',
        'tab7' => 'render_tab7',
        );
    
    function __construct() 
    {
        $this->render_menu_page();
    }
    
    function set_menu_tabs() 
    {
        $this->menu_tabs = array(
        'tab1' => __('Basic Firewall Rules', 'all-in-one-wp-security-and-firewall'),
        'tab2' => __('Additional Firewall Rules', 'all-in-one-wp-security-and-firewall'),
        'tab3' => __('6G Blacklist Firewall Rules', 'all-in-one-wp-security-and-firewall'),
        'tab4' => __('Internet Bots', 'all-in-one-wp-security-and-firewall'),
        'tab5' => __('Prevent Hotlinks', 'all-in-one-wp-security-and-firewall'),
        'tab6' => __('404 Detection', 'all-in-one-wp-security-and-firewall'),
        'tab7' => __('Custom Rules', 'all-in-one-wp-security-and-firewall'),
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
        echo '<h2>'.__('Firewall','all-in-one-wp-security-and-firewall').'</h2>';//Interface title
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
        global $aiowps_feature_mgr;
        global $aio_wp_security;
        if(isset($_POST['aiowps_apply_basic_firewall_settings']))//Do form submission tasks
        {
            $nonce=$_REQUEST['_wpnonce'];
            if (!wp_verify_nonce($nonce, 'aiowpsec-enable-basic-firewall-nonce'))
            {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed on enable basic firewall settings!",4);
                die("Nonce check failed on enable basic firewall settings!");
            }

            //Save settings
            if(isset($_POST['aiowps_enable_basic_firewall']))
            {
                $aio_wp_security->configs->set_value('aiowps_enable_basic_firewall','1');
            } 
            else
            {
                $aio_wp_security->configs->set_value('aiowps_enable_basic_firewall','');
            }

            $aio_wp_security->configs->set_value('aiowps_enable_pingback_firewall',isset($_POST["aiowps_enable_pingback_firewall"])?'1':''); //this disables all xmlrpc functionality
            $aio_wp_security->configs->set_value('aiowps_disable_xmlrpc_pingback_methods',isset($_POST["aiowps_disable_xmlrpc_pingback_methods"])?'1':''); //this disables only pingback methods of xmlrpc but leaves other methods so that Jetpack and other apps will still work
            $aio_wp_security->configs->set_value('aiowps_block_debug_log_file_access',isset($_POST["aiowps_block_debug_log_file_access"])?'1':'');

            //Commit the config settings
            $aio_wp_security->configs->save_config();
            
            //Recalculate points after the feature status/options have been altered
            $aiowps_feature_mgr->check_feature_status_and_recalculate_points();

            //Now let's write the applicable rules to the .htaccess file
            $res = AIOWPSecurity_Utility_Htaccess::write_to_htaccess();

            if ($res)
            {
                $this->show_msg_updated(__('Settings were successfully saved', 'all-in-one-wp-security-and-firewall'));
            }
            else
            {
                $this->show_msg_error(__('Could not write to the .htaccess file. Please check the file permissions.', 'all-in-one-wp-security-and-firewall'));
            }
        }

        ?>
        <h2><?php _e('Firewall Settings', 'all-in-one-wp-security-and-firewall')?></h2>
        <form action="" method="POST">
        <?php wp_nonce_field('aiowpsec-enable-basic-firewall-nonce'); ?>            

        <div class="aio_blue_box">
            <?php
            $backup_tab_link = '<a href="admin.php?page='.AIOWPSEC_SETTINGS_MENU_SLUG.'&tab=tab2" target="_blank">backup</a>';
            $info_msg = sprintf( __('This should not have any impact on your site\'s general functionality but if you wish you can take a %s of your .htaccess file before proceeding.', 'all-in-one-wp-security-and-firewall'), $backup_tab_link);
            echo '<p>'.__('The features in this tab allow you to activate some basic firewall security protection rules for your site.', 'all-in-one-wp-security-and-firewall').
            '<br />'.__('The firewall functionality is achieved via the insertion of special code into your currently active .htaccess file.', 'all-in-one-wp-security-and-firewall').
            '<br />'.$info_msg.'</p>';
            ?>
        </div>
            <?php
            //show a warning message if xmlrpc has been completely disabled
            if($aio_wp_security->configs->get_value('aiowps_enable_pingback_firewall')=='1'){
            ?>
        <div class="aio_orange_box">
            <p>
            <?php
            echo '<p>'.__('Attention: You have enabled the "Completely Block Access To XMLRPC" checkbox which means all XMLRPC functionality will be blocked.', 'all-in-one-wp-security-and-firewall').'</p>';
            echo '<p>'.__('By leaving this feature enabled you will prevent Jetpack or Wordpress iOS or other apps which need XMLRPC from working correctly on your site.', 'all-in-one-wp-security-and-firewall').'</p>';
            echo '<p>'.__('If you still need XMLRPC then uncheck the "Completely Block Access To XMLRPC" checkbox and enable only the "Disable Pingback Functionality From XMLRPC" checkbox.', 'all-in-one-wp-security-and-firewall').'</p>';
            ?>
            </p>
        </div>            
            
            <?php
            }
        ?>

        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('Basic Firewall Settings', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
        <?php
        //Display security info badge
        $aiowps_feature_mgr->output_feature_details_badge("firewall-basic-rules");
        ?>
        <table class="form-table">
            <tr valign="top">
                <th scope="row"><?php _e('Enable Basic Firewall Protection', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td>
                <input name="aiowps_enable_basic_firewall" type="checkbox"<?php if($aio_wp_security->configs->get_value('aiowps_enable_basic_firewall')=='1') echo ' checked="checked"'; ?> value="1"/>
                <span class="description"><?php _e('Check this if you want to apply basic firewall protection to your site.', 'all-in-one-wp-security-and-firewall'); ?></span>
                <span class="aiowps_more_info_anchor"><span class="aiowps_more_info_toggle_char">+</span><span class="aiowps_more_info_toggle_text"><?php _e('More Info', 'all-in-one-wp-security-and-firewall'); ?></span></span>
                <div class="aiowps_more_info_body">
                        <?php 
                        echo '<p class="description">'.__('This setting will implement the following basic firewall protection mechanisms on your site:', 'all-in-one-wp-security-and-firewall').'</p>';
                        echo '<p class="description">'.__('1) Protect your htaccess file by denying access to it.', 'all-in-one-wp-security-and-firewall').'</p>';
                        echo '<p class="description">'.__('2) Disable the server signature.', 'all-in-one-wp-security-and-firewall').'</p>';
                        echo '<p class="description">'.__('3) Limit file upload size (10MB).', 'all-in-one-wp-security-and-firewall').'</p>';
                        echo '<p class="description">'.__('4) Protect your wp-config.php file by denying access to it.', 'all-in-one-wp-security-and-firewall').'</p>';
                        echo '<p class="description">'.__('The above firewall features will be applied via your .htaccess file and should not affect your site\'s overall functionality.', 'all-in-one-wp-security-and-firewall').'</p>';
                        echo '<p class="description">'.__('You are still advised to take a backup of your active .htaccess file just in case.', 'all-in-one-wp-security-and-firewall').'</p>';
                        ?>
                </div>
                </td>
            </tr>            
        </table>
        </div></div>
        
        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('WordPress XMLRPC & Pingback Vulnerability Protection', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
        <?php
        //Display security info badge
        $aiowps_feature_mgr->output_feature_details_badge("firewall-pingback-rules");
        ?>
        <table class="form-table">
            <tr valign="top">
                <th scope="row"><?php _e('Completely Block Access To XMLRPC', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td>
                <input name="aiowps_enable_pingback_firewall" type="checkbox"<?php if($aio_wp_security->configs->get_value('aiowps_enable_pingback_firewall')=='1') echo ' checked="checked"'; ?> value="1"/>
                <span class="description"><?php _e('Check this if you are not using the WP XML-RPC functionality and you want to completely block external access to XMLRPC.', 'all-in-one-wp-security-and-firewall'); ?></span>
                <span class="aiowps_more_info_anchor"><span class="aiowps_more_info_toggle_char">+</span><span class="aiowps_more_info_toggle_text"><?php _e('More Info', 'all-in-one-wp-security-and-firewall'); ?></span></span>
                <div class="aiowps_more_info_body">
                        <?php 
                        echo '<p class="description">'.__('This setting will add a directive in your .htaccess to disable access to the WordPress xmlrpc.php file which is responsible for the XML-RPC functionality in WordPress.', 'all-in-one-wp-security-and-firewall').'</p>';
                        echo '<p class="description">'.__('Hackers can exploit various vulnerabilities in the WordPress XML-RPC API in a number of ways such as:', 'all-in-one-wp-security-and-firewall').'</p>';
                        echo '<p class="description">'.__('1) Denial of Service (DoS) attacks', 'all-in-one-wp-security-and-firewall').'</p>';
                        echo '<p class="description">'.__('2) Hacking internal routers.', 'all-in-one-wp-security-and-firewall').'</p>';
                        echo '<p class="description">'.__('3) Scanning ports in internal networks to get info from various hosts.', 'all-in-one-wp-security-and-firewall').'</p>';
                        echo '<p class="description">'.__('Apart from the security protection benefit, this feature may also help reduce load on your server, particularly if your site currently has a lot of unwanted traffic hitting the XML-RPC API on your installation.', 'all-in-one-wp-security-and-firewall').'</p>';
                        echo '<p class="description">'.__('NOTE: You should only enable this feature if you are not currently using the XML-RPC functionality on your WordPress installation.', 'all-in-one-wp-security-and-firewall').'</p>';
                        echo '<p class="description">'.__('Leave this feature disabled and use the feature below if you want pingback protection but you still need XMLRPC.', 'all-in-one-wp-security-and-firewall').'</p>';
                        ?>
                </div>
                </td>
            </tr>            
            <tr valign="top">
                <th scope="row"><?php _e('Disable Pingback Functionality From XMLRPC', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td>
                <input name="aiowps_disable_xmlrpc_pingback_methods" type="checkbox"<?php if($aio_wp_security->configs->get_value('aiowps_disable_xmlrpc_pingback_methods')=='1') echo ' checked="checked"'; ?> value="1"/>
                <span class="description"><?php _e('If you use Jetpack or WP iOS or other apps which need WP XML-RPC functionality then check this. This will enable protection against WordPress pingback vulnerabilities.', 'all-in-one-wp-security-and-firewall'); ?></span>
                <span class="aiowps_more_info_anchor"><span class="aiowps_more_info_toggle_char">+</span><span class="aiowps_more_info_toggle_text"><?php _e('More Info', 'all-in-one-wp-security-and-firewall'); ?></span></span>
                <div class="aiowps_more_info_body">
                        <?php 
                        echo '<p class="description">'.__('NOTE: If you use Jetpack or the Wordpress iOS or other apps then you should enable this feature but leave the "Completely Block Access To XMLRPC" checkbox unchecked.', 'all-in-one-wp-security-and-firewall').'</p>';
                        echo '<p class="description">'.__('The feature will still allow XMLRPC functionality on your site but will disable the pingback methods.', 'all-in-one-wp-security-and-firewall').'</p>';
                        echo '<p class="description">'.__('This feature will also remove the "X-Pingback" header if it is present.', 'all-in-one-wp-security-and-firewall').'</p>';
                        ?>
                </div>
                </td>
            </tr>            
        </table>
        </div></div>
            
        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('Block Accesss to Debug Log File', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
        <?php
        //Display security info badge
        $aiowps_feature_mgr->output_feature_details_badge("firewall-block-debug-file-access");
        ?>
        <table class="form-table">
            <tr valign="top">
                <th scope="row"><?php _e('Block Access to debug.log File', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td>
                <input name="aiowps_block_debug_log_file_access" type="checkbox"<?php if($aio_wp_security->configs->get_value('aiowps_block_debug_log_file_access')=='1') echo ' checked="checked"'; ?> value="1"/>
                <span class="description"><?php _e('Check this if you want to block access to the debug.log file that WordPress creates when debug logging is enabled.', 'all-in-one-wp-security-and-firewall'); ?></span>
                <span class="aiowps_more_info_anchor"><span class="aiowps_more_info_toggle_char">+</span><span class="aiowps_more_info_toggle_text"><?php _e('More Info', 'all-in-one-wp-security-and-firewall'); ?></span></span>
                <div class="aiowps_more_info_body">
                    <?php 
                    echo '<p class="description">'.__('WordPress has an option to turn on the debug logging to a file located in wp-content/debug.log. This file may contain sensitive information.', 'all-in-one-wp-security-and-firewall').'</p>';
                    echo '<p class="description">'.__('Using this optoin will block external access to this file. You can still access this file by logging into your site via FTP', 'all-in-one-wp-security-and-firewall').'</p>';
                    ?>
                </div>
                </td>
            </tr>            
        </table>
        </div></div>
            
        <input type="submit" name="aiowps_apply_basic_firewall_settings" value="<?php _e('Save Basic Firewall Settings', 'all-in-one-wp-security-and-firewall')?>" class="button-primary" />
        </form>
        <?php
    }
    
    function render_tab2()
    {
        global $aio_wp_security;
        $error = '';
        if(isset($_POST['aiowps_apply_additional_firewall_settings']))//Do advanced firewall submission tasks
        {
            $nonce=$_REQUEST['_wpnonce'];
            if (!wp_verify_nonce($nonce, 'aiowpsec-enable-additional-firewall-nonce'))
            {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed on enable advanced firewall settings!",4);
                die("Nonce check failed on enable advanced firewall settings!");
            }

            //Save settings
            if(isset($_POST['aiowps_disable_index_views']))
            {
                $aio_wp_security->configs->set_value('aiowps_disable_index_views','1');
            }
            else
            {
                $aio_wp_security->configs->set_value('aiowps_disable_index_views','');
            }
            
            if(isset($_POST['aiowps_disable_trace_and_track']))
            {
                $aio_wp_security->configs->set_value('aiowps_disable_trace_and_track','1');
            }
            else
            {
                $aio_wp_security->configs->set_value('aiowps_disable_trace_and_track','');
            }

            if(isset($_POST['aiowps_forbid_proxy_comments']))
            {
                $aio_wp_security->configs->set_value('aiowps_forbid_proxy_comments','1');
            } 
            else
            {
                $aio_wp_security->configs->set_value('aiowps_forbid_proxy_comments','');
            }

            if(isset($_POST['aiowps_deny_bad_query_strings']))
            {
                $aio_wp_security->configs->set_value('aiowps_deny_bad_query_strings','1');
            } 
            else
            {
                $aio_wp_security->configs->set_value('aiowps_deny_bad_query_strings','');
            }

            if(isset($_POST['aiowps_advanced_char_string_filter']))
            {
                $aio_wp_security->configs->set_value('aiowps_advanced_char_string_filter','1');
            } 
            else
            {
                $aio_wp_security->configs->set_value('aiowps_advanced_char_string_filter','');
            }

            //Commit the config settings
            $aio_wp_security->configs->save_config();

            //Now let's write the applicable rules to the .htaccess file
            $res = AIOWPSecurity_Utility_Htaccess::write_to_htaccess();

            if ($res)
            {
                $this->show_msg_updated(__('You have successfully saved the Additional Firewall Protection configuration', 'all-in-one-wp-security-and-firewall'));
            }
            else
            {
                $this->show_msg_error(__('Could not write to the .htaccess file. Please check the file permissions.', 'all-in-one-wp-security-and-firewall'));
            }

            if($error)
            {
                $this->show_msg_error($error);
            }

        }
        ?>
        <h2><?php _e('Additional Firewall Protection', 'all-in-one-wp-security-and-firewall')?></h2>
        <div class="aio_blue_box">
            <?php
            $backup_tab_link = '<a href="admin.php?page='.AIOWPSEC_SETTINGS_MENU_SLUG.'&tab=tab2" target="_blank">backup</a>';
            $info_msg = sprintf( __('Due to the nature of the code being inserted to the .htaccess file, this feature may break some functionality for certain plugins and you are therefore advised to take a %s of .htaccess before applying this configuration.', 'all-in-one-wp-security-and-firewall'), $backup_tab_link);

            echo '<p>'.__('This feature allows you to activate more advanced firewall settings to your site.', 'all-in-one-wp-security-and-firewall').
            '<br />'.__('The advanced firewall rules are applied via the insertion of special code to your currently active .htaccess file.', 'all-in-one-wp-security-and-firewall').
            '<br />'.$info_msg.'</p>';
            ?>
        </div>

        <form action="" method="POST">
        <?php wp_nonce_field('aiowpsec-enable-additional-firewall-nonce'); ?>            

        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('Listing of Directory Contents', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
        <?php
        //Display security info badge
        global $aiowps_feature_mgr;
        $aiowps_feature_mgr->output_feature_details_badge("firewall-disable-index-views");
        ?>
        <table class="form-table">
            <tr valign="top">
                <th scope="row"><?php _e('Disable Index Views', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td>
                <input name="aiowps_disable_index_views" type="checkbox"<?php if($aio_wp_security->configs->get_value('aiowps_disable_index_views')=='1') echo ' checked="checked"'; ?> value="1"/>
                <span class="description"><?php _e('Check this if you want to disable directory and file listing.', 'all-in-one-wp-security-and-firewall'); ?></span>
                <span class="aiowps_more_info_anchor"><span class="aiowps_more_info_toggle_char">+</span><span class="aiowps_more_info_toggle_text"><?php _e('More Info', 'all-in-one-wp-security-and-firewall'); ?></span></span>
                <div class="aiowps_more_info_body">
                    <p class="description">
                        <?php 
                        _e('By default, an Apache server will allow the listing of the contents of a directory if it doesn\'t contain an index.php file.', 'all-in-one-wp-security-and-firewall');
                        echo '<br />';
                        _e('This feature will prevent the listing of contents for all directories.', 'all-in-one-wp-security-and-firewall');
                        echo '<br />';
                        _e('NOTE: In order for this feature to work "AllowOverride" of the Indexes directive must be enabled in your httpd.conf file. Ask your hosting provider to check this if you don\'t have access to httpd.conf', 'all-in-one-wp-security-and-firewall');
                        ?>
                    </p>
                </div>
                </td>
            </tr>
        </table>
        </div></div>
        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('Trace and Track', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
        <?php
        //Display security info badge
        global $aiowps_feature_mgr;
        $aiowps_feature_mgr->output_feature_details_badge("firewall-disable-trace-track");
        ?>
        <table class="form-table">
            <tr valign="top">
                <th scope="row"><?php _e('Disable Trace and Track', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td>
                <input name="aiowps_disable_trace_and_track" type="checkbox"<?php if($aio_wp_security->configs->get_value('aiowps_disable_trace_and_track')=='1') echo ' checked="checked"'; ?> value="1"/>
                <span class="description"><?php _e('Check this if you want to disable trace and track.', 'all-in-one-wp-security-and-firewall'); ?></span>
                <span class="aiowps_more_info_anchor"><span class="aiowps_more_info_toggle_char">+</span><span class="aiowps_more_info_toggle_text"><?php _e('More Info', 'all-in-one-wp-security-and-firewall'); ?></span></span>
                <div class="aiowps_more_info_body">
                    <p class="description">
                        <?php 
                        _e('HTTP Trace attack (XST) can be used to return header requests and grab cookies and other information.', 'all-in-one-wp-security-and-firewall');
                        echo '<br />';
                        _e('This hacking technique is usually used together with cross site scripting attacks (XSS).', 'all-in-one-wp-security-and-firewall');
                        echo '<br />';
                        _e('Disabling trace and track on your site will help prevent HTTP Trace attacks.', 'all-in-one-wp-security-and-firewall');
                        ?>
                    </p>
                </div>
                </td>
            </tr>
        </table>
        </div></div>
        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('Proxy Comment Posting', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
        <?php
        //Display security info badge
        global $aiowps_feature_mgr;
        $aiowps_feature_mgr->output_feature_details_badge("firewall-forbid-proxy-comments");
        ?>
            
        <table class="form-table">
            <tr valign="top">
                <th scope="row"><?php _e('Forbid Proxy Comment Posting', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td>
                <input name="aiowps_forbid_proxy_comments" type="checkbox"<?php if($aio_wp_security->configs->get_value('aiowps_forbid_proxy_comments')=='1') echo ' checked="checked"'; ?> value="1"/>
                <span class="description"><?php _e('Check this if you want to forbid proxy comment posting.', 'all-in-one-wp-security-and-firewall'); ?></span>
                <span class="aiowps_more_info_anchor"><span class="aiowps_more_info_toggle_char">+</span><span class="aiowps_more_info_toggle_text"><?php _e('More Info', 'all-in-one-wp-security-and-firewall'); ?></span></span>
                <div class="aiowps_more_info_body">
                    <p class="description">
                        <?php 
                        _e('This setting will deny any requests that use a proxy server when posting comments.', 'all-in-one-wp-security-and-firewall');
                        echo '<br />'.__('By forbidding proxy comments you are in effect eliminating some SPAM and other proxy requests.', 'all-in-one-wp-security-and-firewall');
                        ?>
                    </p>
                </div>
                </td>
            </tr>            
        </table>
        </div></div>
        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('Bad Query Strings', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
        <?php
        //Display security info badge
        global $aiowps_feature_mgr;
        $aiowps_feature_mgr->output_feature_details_badge("firewall-deny-bad-queries");
        ?>
            
        <table class="form-table">
            <tr valign="top">
                <th scope="row"><?php _e('Deny Bad Query Strings', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td>
                <input name="aiowps_deny_bad_query_strings" type="checkbox"<?php if($aio_wp_security->configs->get_value('aiowps_deny_bad_query_strings')=='1') echo ' checked="checked"'; ?> value="1"/>
                <span class="description"><?php _e('This will help protect you against malicious queries via XSS.', 'all-in-one-wp-security-and-firewall'); ?></span>
                <span class="aiowps_more_info_anchor"><span class="aiowps_more_info_toggle_char">+</span><span class="aiowps_more_info_toggle_text"><?php _e('More Info', 'all-in-one-wp-security-and-firewall'); ?></span></span>
                <div class="aiowps_more_info_body">
                    <p class="description">
                        <?php 
                        _e('This feature will write rules in your .htaccess file to prevent malicious string attacks on your site using XSS.', 'all-in-one-wp-security-and-firewall');
                        echo '<br />'.__('NOTE: Some of these strings might be used for plugins or themes and hence this might break some functionality.', 'all-in-one-wp-security-and-firewall');
                        echo '<br /><strong>'.__('You are therefore strongly advised to take a backup of your active .htaccess file before applying this feature.', 'all-in-one-wp-security-and-firewall').'<strong>';
                        ?>
                    </p>
                </div>
                </td>
            </tr>            
        </table>
        </div></div>
        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('Advanced Character String Filter', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
        <?php
        //Display security info badge
        global $aiowps_feature_mgr;
        $aiowps_feature_mgr->output_feature_details_badge("firewall-advanced-character-string-filter");
        ?>
            
        <table class="form-table">
            <tr valign="top">
                <th scope="row"><?php _e('Enable Advanced Character String Filter', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td>
                <input name="aiowps_advanced_char_string_filter" type="checkbox"<?php if($aio_wp_security->configs->get_value('aiowps_advanced_char_string_filter')=='1') echo ' checked="checked"'; ?> value="1"/>
                <span class="description"><?php _e('This will block bad character matches from XSS.', 'all-in-one-wp-security-and-firewall'); ?></span>
                <span class="aiowps_more_info_anchor"><span class="aiowps_more_info_toggle_char">+</span><span class="aiowps_more_info_toggle_text"><?php _e('More Info', 'all-in-one-wp-security-and-firewall'); ?></span></span>
                <div class="aiowps_more_info_body">
                    <p class="description">
                        <?php 
                        _e('This is an advanced character string filter to prevent malicious string attacks on your site coming from Cross Site Scripting (XSS).', 'all-in-one-wp-security-and-firewall');
                        echo '<br />'.__('This setting matches for common malicious string patterns and exploits and will produce a 403 error for the hacker attempting the query.', 'all-in-one-wp-security-and-firewall');
                        echo '<br />'.__('NOTE: Some strings for this setting might break some functionality.', 'all-in-one-wp-security-and-firewall');
                        echo '<br /><strong>'.__('You are therefore strongly advised to take a backup of your active .htaccess file before applying this feature.', 'all-in-one-wp-security-and-firewall').'<strong>';
                        ?>
                    </p>
                </div>
                </td>
            </tr>            
        </table>
        </div></div>
        <input type="submit" name="aiowps_apply_additional_firewall_settings" value="<?php _e('Save Additional Firewall Settings', 'all-in-one-wp-security-and-firewall')?>" class="button-primary" />
        </form>
        <?php
    }
    
    function render_tab3()
    {
        global $aio_wp_security, $aiowps_feature_mgr;
        if(isset($_POST['aiowps_apply_5g_6g_firewall_settings']))//Do form submission tasks
        {
            $nonce=$_REQUEST['_wpnonce'];
            if (!wp_verify_nonce($nonce, 'aiowpsec-enable-5g-6g-firewall-nonce'))
            {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed on enable 5G/6G firewall settings!",4);
                die("Nonce check failed on enable 5G/6G firewall settings!");
            }

            //Save settings
            if(isset($_POST['aiowps_enable_5g_firewall']))
            {
                $aio_wp_security->configs->set_value('aiowps_enable_5g_firewall','1');
            } 
            else
            {
                $aio_wp_security->configs->set_value('aiowps_enable_5g_firewall','');
            }
            if(isset($_POST['aiowps_enable_6g_firewall']))
            {
                $aio_wp_security->configs->set_value('aiowps_enable_6g_firewall','1');
            }
            else
            {
                $aio_wp_security->configs->set_value('aiowps_enable_6g_firewall','');
            }

            //Commit the config settings
            $aio_wp_security->configs->save_config();

            //Now let's write the applicable rules to the .htaccess file
            $res = AIOWPSecurity_Utility_Htaccess::write_to_htaccess();

            if ($res)
            {
                $this->show_msg_updated(__('You have successfully saved the 5G/6G Firewall Protection configuration', 'all-in-one-wp-security-and-firewall'));
                // Recalculate points after the feature status/options have been altered
                $aiowps_feature_mgr->check_feature_status_and_recalculate_points();
            }
            else
            {
                $this->show_msg_error(__('Could not write to the .htaccess file. Please check the file permissions.', 'all-in-one-wp-security-and-firewall'));
            }
        }

        ?>
        <h2><?php _e('Firewall Settings', 'all-in-one-wp-security-and-firewall')?></h2>
        <div class="aio_blue_box">
            <?php
            $backup_tab_link = '<a href="admin.php?page='.AIOWPSEC_SETTINGS_MENU_SLUG.'&tab=tab2" target="_blank">backup</a>';
            $info_msg = '<p>'.sprintf( __('This feature allows you to activate the %s (or legacy %s) firewall security protection rules designed and produced by %s.', 'all-in-one-wp-security-and-firewall'), '<a href="http://perishablepress.com/6g/" target="_blank">6G</a>', '<a href="http://perishablepress.com/5g-blacklist-2013/" target="_blank">5G</a>', '<a href="http://perishablepress.com/" target="_blank">Perishable Press</a>').'</p>';
			$info_msg .= '<p>'.__('The 6G Blacklist is updated and improved version of 5G Blacklist. If you have 5G Blacklist active, you might consider activating 6G Blacklist instead.', 'all-in-one-wp-security-and-firewall').'</p>';
            $info_msg .= '<p>'.__('The 6G Blacklist is a simple, flexible blacklist that helps reduce the number of malicious URL requests that hit your website.', 'all-in-one-wp-security-and-firewall').'</p>';
            $info_msg .= '<p>'.__('The added advantage of applying the 6G firewall to your site is that it has been tested and confirmed by the people at PerishablePress.com to be an optimal and least disruptive set of .htaccess security rules for general WP sites running on an Apache server or similar.', 'all-in-one-wp-security-and-firewall').'</p>';
            $info_msg .= '<p>'.sprintf( __('Therefore the 6G firewall rules should not have any impact on your site\'s general functionality but if you wish you can take a %s of your .htaccess file before proceeding.', 'all-in-one-wp-security-and-firewall'), $backup_tab_link).'</p>';
            echo $info_msg;
            ?>
        </div>

        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('6G Blacklist/Firewall Settings', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
        <?php
        //Display security info badge
        global $aiowps_feature_mgr;
        $aiowps_feature_mgr->output_feature_details_badge("firewall-enable-5g-6g-blacklist");
        ?>
            
        <form action="" method="POST">
        <?php wp_nonce_field('aiowpsec-enable-5g-6g-firewall-nonce'); ?>
        <table class="form-table">
            <tr valign="top">
                <th scope="row"><?php _e('Enable 6G Firewall Protection', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td>
                <input name="aiowps_enable_6g_firewall" type="checkbox"<?php if($aio_wp_security->configs->get_value('aiowps_enable_6g_firewall')=='1') echo ' checked="checked"'; ?> value="1"/>
                <span class="description"><?php _e('Check this if you want to apply the 6G Blacklist firewall protection from perishablepress.com to your site.', 'all-in-one-wp-security-and-firewall'); ?></span>
                <span class="aiowps_more_info_anchor"><span class="aiowps_more_info_toggle_char">+</span><span class="aiowps_more_info_toggle_text"><?php _e('More Info', 'all-in-one-wp-security-and-firewall'); ?></span></span>
                <div class="aiowps_more_info_body">
                        <?php
                        echo '<p class="description">'.__('This setting will implement the 6G security firewall protection mechanisms on your site which include the following things:', 'all-in-one-wp-security-and-firewall').'</p>';
                        echo '<p class="description">'.__('1) Block forbidden characters commonly used in exploitative attacks.', 'all-in-one-wp-security-and-firewall').'</p>';
                        echo '<p class="description">'.__('2) Block malicious encoded URL characters such as the ".css(" string.', 'all-in-one-wp-security-and-firewall').'</p>';
                        echo '<p class="description">'.__('3) Guard against the common patterns and specific exploits in the root portion of targeted URLs.', 'all-in-one-wp-security-and-firewall').'</p>';
                        echo '<p class="description">'.__('4) Stop attackers from manipulating query strings by disallowing illicit characters.', 'all-in-one-wp-security-and-firewall').'</p>';
                        echo '<p class="description">'.__('....and much more.', 'all-in-one-wp-security-and-firewall').'</p>';
                        ?>
                </div>
                </td>
            </tr>
            <tr valign="top">
                <th scope="row"><?php _e('Enable legacy 5G Firewall Protection', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td>
                <input name="aiowps_enable_5g_firewall" type="checkbox"<?php if($aio_wp_security->configs->get_value('aiowps_enable_5g_firewall')=='1') echo ' checked="checked"'; ?> value="1"/>
                <span class="description"><?php _e('Check this if you want to apply the 5G Blacklist firewall protection from perishablepress.com to your site.', 'all-in-one-wp-security-and-firewall'); ?></span>
                <span class="aiowps_more_info_anchor"><span class="aiowps_more_info_toggle_char">+</span><span class="aiowps_more_info_toggle_text"><?php _e('More Info', 'all-in-one-wp-security-and-firewall'); ?></span></span>
                <div class="aiowps_more_info_body">
                        <?php 
                        echo '<p class="description">'.__('This setting will implement the 5G security firewall protection mechanisms on your site which include the following things:', 'all-in-one-wp-security-and-firewall').'</p>';
                        echo '<p class="description">'.__('1) Block forbidden characters commonly used in exploitative attacks.', 'all-in-one-wp-security-and-firewall').'</p>';
                        echo '<p class="description">'.__('2) Block malicious encoded URL characters such as the ".css(" string.', 'all-in-one-wp-security-and-firewall').'</p>';
                        echo '<p class="description">'.__('3) Guard against the common patterns and specific exploits in the root portion of targeted URLs.', 'all-in-one-wp-security-and-firewall').'</p>';
                        echo '<p class="description">'.__('4) Stop attackers from manipulating query strings by disallowing illicit characters.', 'all-in-one-wp-security-and-firewall').'</p>';
                        echo '<p class="description">'.__('....and much more.', 'all-in-one-wp-security-and-firewall').'</p>';
                        ?>
                </div>
                </td>
            </tr>            
        </table>
        <input type="submit" name="aiowps_apply_5g_6g_firewall_settings" value="<?php _e('Save 5G/6G Firewall Settings', 'all-in-one-wp-security-and-firewall')?>" class="button-primary" />
        </form>
        </div></div>
        <?php
    }

    function render_tab4()
    {
        global $aio_wp_security;
        if(isset($_POST['aiowps_save_internet_bot_settings']))//Do form submission tasks
        {
            $nonce=$_REQUEST['_wpnonce'];
            if (!wp_verify_nonce($nonce, 'aiowpsec-save-internet-bot-settings-nonce'))
            {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed for save internet bot settings!",4);
                die("Nonce check failed for save internet bot settings!");
            }

            //Save settings
            if(isset($_POST['aiowps_block_fake_googlebots']))
            {
                $aio_wp_security->configs->set_value('aiowps_block_fake_googlebots','1');
            } 
            else
            {
                $aio_wp_security->configs->set_value('aiowps_block_fake_googlebots','');
            }

            //Commit the config settings
            $aio_wp_security->configs->save_config();

            $this->show_msg_updated(__('The Internet bot settings were successfully saved', 'all-in-one-wp-security-and-firewall'));
        }

        ?>
        <h2><?php _e('Internet Bot Settings', 'all-in-one-wp-security-and-firewall')?></h2>
        <form action="" method="POST">
        <?php wp_nonce_field('aiowpsec-save-internet-bot-settings-nonce'); ?>            
        <div class="aio_blue_box">
            <?php
            $info_msg = '';
            $wiki_link = '<a href="http://en.wikipedia.org/wiki/Internet_bot" target="_blank">What is an Internet Bot</a>';
            $info_msg .= '<p><strong>'.sprintf( __('%s?', 'all-in-one-wp-security-and-firewall'), $wiki_link).'</strong></p>';
            
            $info_msg .= '<p>'. __('A bot is a piece of software which runs on the Internet and performs automatic tasks. For example when Google indexes your pages it uses automatic bots to achieve this task.', 'all-in-one-wp-security-and-firewall').'</p>';
            $info_msg .= '<p>'. __('A lot of bots are legitimate and non-malicous but not all bots are good and often you will find some which try to impersonate legitimate bots such as "Googlebot" but in reality they have nohing to do with Google at all.', 'all-in-one-wp-security-and-firewall').'</p>';
            $info_msg .= '<p>'. __('Although most of the bots out there are relatively harmless sometimes website owners want to have more control over which bots they allow into their site.', 'all-in-one-wp-security-and-firewall').'</p>';
            $info_msg .= '<p>'. __('This feature allows you to block bots which are impersonating as a Googlebot but actually aren\'t. (In other words they are fake Google bots)', 'all-in-one-wp-security-and-firewall').'</p>';
            $info_msg .= '<p>'.__('Googlebots have a unique indentity which cannot easily be forged and this feature will indentify any fake Google bots and block them from reading your site\'s pages.', 'all-in-one-wp-security-and-firewall').'</p>';
            echo $info_msg;
            ?>
        </div>
        <div class="aio_yellow_box">
            <?php
            $info_msg_2 = '<p>'. __('<strong>Attention</strong>: Sometimes non-malicious Internet organizations might have bots which impersonate as a "Googlebot".', 'all-in-one-wp-security-and-firewall').'</p>';
            $info_msg_2 .= '<p>'.__('Just be aware that if you activate this feature the plugin will block all bots which use the "Googlebot" string in their User Agent information but are NOT officially from Google (irrespective whether they are malicious or not).', 'all-in-one-wp-security-and-firewall').'</p>';
            $info_msg_2 .= '<p>'.__('All other bots from other organizations such as "Yahoo", "Bing" etc will not be affected by this feature.', 'all-in-one-wp-security-and-firewall').'</p>';
            echo $info_msg_2;
            ?>
        </div>

        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('Block Fake Googlebots', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
        <?php
        //Display security info badge
        global $aiowps_feature_mgr;
        $aiowps_feature_mgr->output_feature_details_badge("firewall-block-fake-googlebots");
        ?>
            
        <table class="form-table">
            <tr valign="top">
                <th scope="row"><?php _e('Block Fake Googlebots', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td>
                <input name="aiowps_block_fake_googlebots" type="checkbox"<?php if($aio_wp_security->configs->get_value('aiowps_block_fake_googlebots')=='1') echo ' checked="checked"'; ?> value="1"/>
                <span class="description"><?php _e('Check this if you want to block all fake Googlebots.', 'all-in-one-wp-security-and-firewall'); ?></span>
                <span class="aiowps_more_info_anchor"><span class="aiowps_more_info_toggle_char">+</span><span class="aiowps_more_info_toggle_text"><?php _e('More Info', 'all-in-one-wp-security-and-firewall'); ?></span></span>
                <div class="aiowps_more_info_body">
                        <?php 
                        echo '<p class="description">'.__('This feature will check if the User Agent information of a bot contains the string "Googlebot".', 'all-in-one-wp-security-and-firewall').'</p>';
                        echo '<p class="description">'.__('It will then perform a few tests to verify if the bot is legitimately from Google and if so it will allow the bot to proceed.', 'all-in-one-wp-security-and-firewall').'</p>';
                        echo '<p class="description">'.__('If the bot fails the checks then the plugin will mark it as being a fake Googlebot and it will block it', 'all-in-one-wp-security-and-firewall').'</p>';
                        ?>
                </div>
                </td>
            </tr>            
        </table>
        </div></div>
        <input type="submit" name="aiowps_save_internet_bot_settings" value="<?php _e('Save Internet Bot Settings', 'all-in-one-wp-security-and-firewall')?>" class="button-primary" />
        </form>
        <?php
    }
    
    function render_tab5()
    {
        global $aio_wp_security;
        global $aiowps_feature_mgr;
        
        if(isset($_POST['aiowps_save_prevent_hotlinking']))//Do form submission tasks
        {
            $nonce=$_REQUEST['_wpnonce'];
            if (!wp_verify_nonce($nonce, 'aiowpsec-prevent-hotlinking-nonce'))
            {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed on prevent hotlinking options save!",4);
                die("Nonce check failed on prevent hotlinking options save!");
            }
            $aio_wp_security->configs->set_value('aiowps_prevent_hotlinking',isset($_POST["aiowps_prevent_hotlinking"])?'1':'');
            $aio_wp_security->configs->save_config();
            
            //Recalculate points after the feature status/options have been altered
            $aiowps_feature_mgr->check_feature_status_and_recalculate_points();

            //Now let's write the applicable rules to the .htaccess file
            $res = AIOWPSecurity_Utility_Htaccess::write_to_htaccess();

            if ($res)
            {
                $this->show_msg_updated(__('Settings were successfully saved', 'all-in-one-wp-security-and-firewall'));
            }
            else
            {
                $this->show_msg_error(__('Could not write to the .htaccess file. Please check the file permissions.', 'all-in-one-wp-security-and-firewall'));
            }
    }
        ?>
        <h2><?php _e('Prevent Image Hotlinking', 'all-in-one-wp-security-and-firewall')?></h2>
        <div class="aio_blue_box">
            <?php
            echo '<p>'.__('A Hotlink is where someone displays an image on their site which is actually located on your site by using a direct link to the source of the image on your server.', 'all-in-one-wp-security-and-firewall');
            echo '<br />'.__('Due to the fact that the image being displayed on the other person\'s site is coming from your server, this can cause leaking of bandwidth and resources for you because your server has to present this image for the people viewing it on someone elses\'s site.','all-in-one-wp-security-and-firewall');
            echo '<br />'.__('This feature will prevent people from directly hotlinking images from your site\'s pages by writing some directives in your .htaccess file.', 'all-in-one-wp-security-and-firewall').'</p>';
            ?>
        </div>

        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('Prevent Hotlinking', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
        <?php
        //Display security info badge
        global $aiowps_feature_mgr;
        $aiowps_feature_mgr->output_feature_details_badge("prevent-hotlinking");
        ?>

        <form action="" method="POST">
        <?php wp_nonce_field('aiowpsec-prevent-hotlinking-nonce'); ?>            
        <table class="form-table">
            <tr valign="top">
                <th scope="row"><?php _e('Prevent Image Hotlinking', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td>
                <input name="aiowps_prevent_hotlinking" type="checkbox"<?php if($aio_wp_security->configs->get_value('aiowps_prevent_hotlinking')=='1') echo ' checked="checked"'; ?> value="1"/>
                <span class="description"><?php _e('Check this if you want to prevent hotlinking to images on your site.', 'all-in-one-wp-security-and-firewall'); ?></span>
                </td>
            </tr>            
        </table>
        <input type="submit" name="aiowps_save_prevent_hotlinking" value="<?php _e('Save Settings', 'all-in-one-wp-security-and-firewall')?>" class="button-primary" />
        </form>
        </div></div>
    <?php
    }
    
    function render_tab6() 
    {
        global $aio_wp_security;
        global $aiowps_feature_mgr;
        if (isset($_POST['aiowps_delete_404_event_records']))
        {
            $nonce=$_REQUEST['_wpnonce'];
            if (!wp_verify_nonce($nonce, 'aiowpsec-delete-404-event-records-nonce'))
            {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed for delete all 404 event logs operation!",4);
                die(__('Nonce check failed for delete all 404 event logs operation!','all-in-one-wp-security-and-firewall'));
            }
            global $wpdb;
            $events_table_name = AIOWPSEC_TBL_EVENTS;
            //Delete all 404 records from the events table
            $where = array('event_type' => '404');
            $result = $wpdb->delete($events_table_name, $where);
                    
            if ($result === FALSE)
            {
                $aio_wp_security->debug_logger->log_debug("404 Detection Feature - Delete all 404 event logs operation failed!",4);
                $this->show_msg_error(__('404 Detection Feature - Delete all 404 event logs operation failed!','all-in-one-wp-security-and-firewall'));
            } 
            else
            {
                $this->show_msg_updated(__('All 404 event logs were deleted from the DB successfully!','all-in-one-wp-security-and-firewall'));
            }
        }
        
        
        include_once 'wp-security-list-404.php'; //For rendering the AIOWPSecurity_List_Table in tab1
        $event_list_404 = new AIOWPSecurity_List_404(); //For rendering the AIOWPSecurity_List_Table in tab1

        if(isset($_POST['aiowps_save_404_detect_options']))//Do form submission tasks
        {
            $error = '';
            $nonce=$_REQUEST['_wpnonce'];
            if (!wp_verify_nonce($nonce, 'aiowpsec-404-detection-nonce'))
            {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed on 404 detection options save!",4);
                die("Nonce check failed on 404 detection options save!");
            }
            
            $aio_wp_security->configs->set_value('aiowps_enable_404_logging',isset($_POST["aiowps_enable_404_IP_lockout"])?'1':''); //the "aiowps_enable_404_IP_lockout" checkbox currently controls both the 404 lockout and 404 logging
            $aio_wp_security->configs->set_value('aiowps_enable_404_IP_lockout',isset($_POST["aiowps_enable_404_IP_lockout"])?'1':'');
            
            $lockout_time_length = isset($_POST['aiowps_404_lockout_time_length'])?sanitize_text_field($_POST['aiowps_404_lockout_time_length']):'';
            if(!is_numeric($lockout_time_length))
            {
                $error .= '<br />'.__('You entered a non numeric value for the lockout time length field. It has been set to the default value.','all-in-one-wp-security-and-firewall');
                $lockout_time_length = '60';//Set it to the default value for this field
            }

            $redirect_url = isset($_POST['aiowps_404_lock_redirect_url'])?trim($_POST['aiowps_404_lock_redirect_url']):'';
            if ($redirect_url == '' || esc_url($redirect_url, array('http', 'https')) == ''){
                $error .= '<br />'.__('You entered an incorrect format for the "Redirect URL" field. It has been set to the default value.','all-in-one-wp-security-and-firewall');
                $redirect_url = 'http://127.0.0.1';
            }
            
            if($error)
            {
                $this->show_msg_error(__('Attention!','all-in-one-wp-security-and-firewall').$error);
            }
            
            $aio_wp_security->configs->set_value('aiowps_404_lockout_time_length',absint($lockout_time_length));
            $aio_wp_security->configs->set_value('aiowps_404_lock_redirect_url',$redirect_url);
            $aio_wp_security->configs->save_config();
            
            //Recalculate points after the feature status/options have been altered
            $aiowps_feature_mgr->check_feature_status_and_recalculate_points();
            
            $this->show_msg_settings_updated();
        }
        
                
        if(isset($_REQUEST['action'])) //Do list table form row action tasks
        {
            if($_REQUEST['action'] == 'temp_block'){ //Temp Block link was clicked for a row in list table
                $event_list_404->block_ip(strip_tags($_REQUEST['ip_address']));
            }

            if($_REQUEST['action'] == 'blacklist_ip'){ //Blacklist IP link was clicked for a row in list table
                $event_list_404->blacklist_ip_address(strip_tags($_REQUEST['ip_address']));
            }
            
            if($_REQUEST['action'] == 'delete_event_log'){ //Unlock link was clicked for a row in list table
                $event_list_404->delete_404_event_records(strip_tags($_REQUEST['id']));
            }
        }
        ?>
        <h2><?php _e('404 Detection Configuration', 'all-in-one-wp-security-and-firewall')?></h2>
        <div class="aio_blue_box">
            <?php
            echo '<p>'.__('A 404 or Not Found error occurs when somebody tries to access a non-existent page on your website.', 'all-in-one-wp-security-and-firewall').'
                <br />'.__('Typically, most 404 errors happen quite innocently when people have mis-typed a URL or used an old link to page which doesn\'t exist anymore.', 'all-in-one-wp-security-and-firewall').'
                <br />'.__('However, in some cases you may find many repeated 404 errors which occur in a relatively short space of time and from the same IP address which are all attempting to access a variety of non-existent page URLs.', 'all-in-one-wp-security-and-firewall').'
                <br />'.__('Such behaviour can mean that a hacker might be trying to find a particular page or URL for sinister reasons.', 'all-in-one-wp-security-and-firewall').'
                <br /><br />'.__('This feature allows you to monitor all 404 events which occur on your site, and it also gives you the option of blocking IP addresses for a configured length of time.', 'all-in-one-wp-security-and-firewall').'
                <br />'.__('If you want to temporarily block an IP address, simply click the "Temp Block" link for the applicable IP entry in the "404 Event Logs" table below.', 'all-in-one-wp-security-and-firewall').'</p>';
            ?>
        </div>
        <div class="aio_grey_box">
            <?php
            $addon_link = '<strong><a href="http://www.site-scanners.com/smart-404-security-blocking-addon/" target="_blank">Smart404 Blocking Addon</a></strong>';
            $info_msg = sprintf( __('You may also be interested in our %s.', 'all-in-one-wp-security-and-firewall'), $addon_link);
            $info_msg2 = __('This addon allows you to automatically and permanently block IP addresses based on how many 404 errors they produce.', 'all-in-one-wp-security-and-firewall');

            echo '<p>'.$info_msg.
                '<br />'.$info_msg2.'</p>';
            ?>
        </div>

        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('404 Detection Options', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
        <?php
        //Display security info badge
        global $aiowps_feature_mgr;
        $aiowps_feature_mgr->output_feature_details_badge("firewall-enable-404-blocking");
        ?>

        <form action="" method="POST">
        <?php wp_nonce_field('aiowpsec-404-detection-nonce'); ?>
        <table class="form-table">
            <tr valign="top">
                <th scope="row"><?php _e('Enable 404 IP Detection and Lockout', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td>
                <input name="aiowps_enable_404_IP_lockout" type="checkbox"<?php if($aio_wp_security->configs->get_value('aiowps_enable_404_IP_lockout')=='1') echo ' checked="checked"'; ?> value="1"/>
                <span class="description"><?php _e('Check this if you want to enable the lockout of selected IP addresses.', 'all-in-one-wp-security-and-firewall'); ?></span>
                <span class="aiowps_more_info_anchor"><span class="aiowps_more_info_toggle_char">+</span><span class="aiowps_more_info_toggle_text"><?php _e('More Info', 'all-in-one-wp-security-and-firewall'); ?></span></span>
                <div class="aiowps_more_info_body">
                    <p class="description">
                        <?php 
                        _e('When you enable this checkbox, all 404 events on your site will be logged in the table below. You can monitor these events and select some IP addresses listed in the table below and block them for a specified amount of time. All IP addresses you select to be blocked from the "404 Event Logs" table section will be unable to access your site during the time specified.', 'all-in-one-wp-security-and-firewall');
                        ?>
                    </p>
                </div>
                </td>
            </tr>
            <!-- currently this option is automatically set when the aiowps_enable_404_IP_lockout feature is turned on
            <tr valign="top">
                <th scope="row"><?php _e('Enable 404 Event Logging', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td>
                <input name="aiowps_enable_404_logging" type="checkbox"<?php if($aio_wp_security->configs->get_value('aiowps_enable_404_logging')=='1') echo ' checked="checked"'; ?> value="1"/>
                <span class="description"><?php _e('Check this if you want to enable the logging of 404 events', 'all-in-one-wp-security-and-firewall'); ?></span>
                </td>
            </tr>
            -->
            <tr valign="top">
                <th scope="row"><?php _e('Time Length of 404 Lockout (min)', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td><input type="text" size="5" name="aiowps_404_lockout_time_length" value="<?php echo $aio_wp_security->configs->get_value('aiowps_404_lockout_time_length'); ?>" />
                <span class="description"><?php _e('Set the length of time for which a blocked IP address will be prevented from visiting your site', 'all-in-one-wp-security-and-firewall'); ?></span>
                <span class="aiowps_more_info_anchor"><span class="aiowps_more_info_toggle_char">+</span><span class="aiowps_more_info_toggle_text"><?php _e('More Info', 'all-in-one-wp-security-and-firewall'); ?></span></span>
                <div class="aiowps_more_info_body">
                    <p class="description">
                        <?php 
                        _e('You can lock any IP address which is recorded in the "404 Event Logs" table section below.', 'all-in-one-wp-security-and-firewall');
                        echo '<br />';
                        _e('To temporarily lock an IP address, hover over the ID column and click the "Temp Block" link for the applicable IP entry.', 'all-in-one-wp-security-and-firewall');
                        ?>
                    </p>
                </div>
                </td> 
            </tr>
            <tr valign="top">
                <th scope="row"><?php _e('404 Lockout Redirect URL', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td><input type="text" size="50" name="aiowps_404_lock_redirect_url" value="<?php echo esc_url_raw( $aio_wp_security->configs->get_value('aiowps_404_lock_redirect_url'), array( 'http', 'https' ) ); ?>" />
                <span class="description"><?php _e('A blocked visitor will be automatically redirected to this URL.', 'all-in-one-wp-security-and-firewall'); ?></span>
                </td> 
            </tr>
        </table>
        <input type="submit" name="aiowps_save_404_detect_options" value="<?php _e('Save Settings', 'all-in-one-wp-security-and-firewall')?>" class="button-primary" />
            
        </form>
        </div></div>
        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('404 Event Logs', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
            <?php 
            //Fetch, prepare, sort, and filter our data...
            $event_list_404->prepare_items();
            //echo "put table of locked entries here"; 
            ?>
            <form id="tables-filter" method="post">
            <!-- For plugins, we also need to ensure that the form posts back to our current page -->
            <input type="hidden" name="page" value="<?php echo esc_attr($_REQUEST['page']); ?>" />
            <?php $event_list_404->search_box('Search', 'search_404_events'); ?>
            <?php
            if(isset($_REQUEST["tab"]))
            {
                echo '<input type="hidden" name="tab" value="'.$_REQUEST["tab"].'" />';
            }
            ?>
            <!-- Now we can render the completed list table -->
            <?php $event_list_404->display(); ?>
            </form>
        </div></div>
        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('Delete All 404 Event Logs', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
        <form action="" method="POST">
        <?php wp_nonce_field('aiowpsec-delete-404-event-records-nonce'); ?>
        <table class="form-table">
            <tr valign="top">
            <span class="description"><?php _e('Click this button if you wish to purge all 404 event logs from the DB.', 'all-in-one-wp-security-and-firewall'); ?></span>
            </tr>            
        </table>
        <input type="submit" name="aiowps_delete_404_event_records" value="<?php _e('Delete All 404 Event Logs', 'all-in-one-wp-security-and-firewall')?>" class="button-primary" onclick="return confirm('Are you sure you want to delete all records?')"/>
        </form>
        </div></div>
        
        <?php
    }

    function render_tab7()
    {
        global $aio_wp_security;
        if(isset($_POST['aiowps_save_custom_rules_settings']))//Do form submission tasks
        {
            $nonce=$_REQUEST['_wpnonce'];
            if (!wp_verify_nonce($nonce, 'aiowpsec-save-custom-rules-settings-nonce'))
            {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed for save custom rules settings!",4);
                die("Nonce check failed for save custom rules settings!");
            }

            //Save settings
            if (isset($_POST["aiowps_enable_custom_rules"]) && empty($_POST['aiowps_custom_rules']))
            {
                $this->show_msg_error('You must enter some .htaccess directives code in the text box below','all-in-one-wp-security-and-firewall');
            }
            else
            {
                if (!empty($_POST['aiowps_custom_rules']))
                {
                    // Undo magic quotes that are automatically added to `$_GET`,
                    // `$_POST`, `$_COOKIE`, and `$_SERVER` by WordPress as
                    // they corrupt any custom rule with backslash in it...
                    $custom_rules = stripslashes($_POST['aiowps_custom_rules']);
                }
                else
                {
                    $aio_wp_security->configs->set_value('aiowps_custom_rules',''); //Clear the custom rules config value
                }

                $aio_wp_security->configs->set_value('aiowps_custom_rules',$custom_rules);
                $aio_wp_security->configs->set_value('aiowps_enable_custom_rules',isset($_POST["aiowps_enable_custom_rules"])?'1':'');
                $aio_wp_security->configs->save_config(); //Save the configuration

                $this->show_msg_settings_updated();

                $write_result = AIOWPSecurity_Utility_Htaccess::write_to_htaccess(); //now let's write to the .htaccess file
                if ( !$write_result )
                {
                    $this->show_msg_error(__('The plugin was unable to write to the .htaccess file. Please edit file manually.','all-in-one-wp-security-and-firewall'));
                    $aio_wp_security->debug_logger->log_debug("Custom Rules feature - The plugin was unable to write to the .htaccess file.");
                }
            }

        }

        ?>
        <h2><?php _e('Custom .htaccess Rules Settings', 'all-in-one-wp-security-and-firewall')?></h2>
        <form action="" method="POST">
            <?php wp_nonce_field('aiowpsec-save-custom-rules-settings-nonce'); ?>
            <div class="aio_blue_box">
                <?php
                $info_msg = '';

                $info_msg .= '<p>'. __('This feature can be used to apply your own custom .htaccess rules and directives.', 'all-in-one-wp-security-and-firewall').'</p>';
                $info_msg .= '<p>'. __('It is useful for when you want to tweak our existing firewall rules or when you want to add your own.', 'all-in-one-wp-security-and-firewall').'</p>';
                $info_msg .= '<p>'. __('NOTE: This feature can only used if your site is hosted in an apache or similar web server.', 'all-in-one-wp-security-and-firewall').'</p>';
                echo $info_msg;
                ?>
            </div>
            <div class="aio_yellow_box">
                <?php
                $info_msg_2 = '<p>'. __('<strong>Warning</strong>: Only use this feature if you know what you are doing.', 'all-in-one-wp-security-and-firewall').'</p>';
                $info_msg_2 .= '<p>'.__('Incorrect .htaccess rules or directives can break or prevent access to your site.', 'all-in-one-wp-security-and-firewall').'</p>';
                $info_msg_2 .= '<p>'.__('It is your responsibility to ensure that you are entering the correct code!', 'all-in-one-wp-security-and-firewall').'</p>';
                $info_msg_2 .= '<p>'.__('If you break your site you will need to access your server via FTP or something similar and then edit your .htaccess file and delete the changes you made.', 'all-in-one-wp-security-and-firewall').'</p>';
                echo $info_msg_2;
                ?>
            </div>

            <div class="postbox">
                <h3 class="hndle"><label for="title"><?php _e('Custom .htaccess Rules', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
                <div class="inside">
                    <table class="form-table">
                        <tr valign="top">
                            <th scope="row"><?php _e('Enable Custom .htaccess Rules', 'all-in-one-wp-security-and-firewall')?>:</th>
                            <td>
                                <input name="aiowps_enable_custom_rules" type="checkbox"<?php if($aio_wp_security->configs->get_value('aiowps_enable_custom_rules')=='1') echo ' checked="checked"'; ?> value="1"/>
                                <span class="description"><?php _e('Check this if you want to enable custom rules entered in the text box below', 'all-in-one-wp-security-and-firewall'); ?></span>
                            </td>
                        </tr>
                        <tr valign="top">
                            <th scope="row"><?php _e('Enter Custom .htaccess Rules:', 'all-in-one-wp-security-and-firewall')?></th>
                            <td>
                                <textarea name="aiowps_custom_rules" rows="35" cols="50"><?php echo htmlspecialchars($aio_wp_security->configs->get_value('aiowps_custom_rules')); ?></textarea>
                                <br />
                                <span class="description"><?php _e('Enter your custom .htaccess rules/directives.','all-in-one-wp-security-and-firewall');?></span>
                            </td>
                        </tr>
                    </table>
                </div></div>
            <input type="submit" name="aiowps_save_custom_rules_settings" value="<?php _e('Save Custom Rules', 'all-in-one-wp-security-and-firewall')?>" class="button-primary" />
        </form>
    <?php
    }

} //end class