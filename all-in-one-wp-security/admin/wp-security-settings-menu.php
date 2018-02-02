<?php
if(!defined('ABSPATH')){
    exit;//Exit if accessed directly
}

class AIOWPSecurity_Settings_Menu extends AIOWPSecurity_Admin_Menu
{
    var $menu_page_slug = AIOWPSEC_SETTINGS_MENU_SLUG;
    
    /* Specify all the tabs of this menu in the following array */
    var $menu_tabs;

    var $menu_tabs_handler = array(
        'tab1' => 'render_tab1', 
        'tab2' => 'render_tab2',
        'tab3' => 'render_tab3',
        'tab4' => 'render_tab4',
        'tab5' => 'render_tab5',
        'tab6' => 'render_tab6',
        );

    function __construct() 
    {
        $this->render_menu_page();
    }

    function set_menu_tabs() 
    {
        $this->menu_tabs = array(
            'tab1' => __('General Settings', 'all-in-one-wp-security-and-firewall'),
            'tab2' => '.htaccess '.__('File', 'all-in-one-wp-security-and-firewall'),
            'tab3' => 'wp-config.php '.__('File', 'all-in-one-wp-security-and-firewall'),
            'tab4' => __('WP Version Info', 'all-in-one-wp-security-and-firewall'),
            'tab5' => __('Import/Export', 'all-in-one-wp-security-and-firewall'),
            'tab6' => __('Advanced Settings', 'all-in-one-wp-security-and-firewall'),
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
        echo '<h2>'.__('Settings','all-in-one-wp-security-and-firewall').'</h2>';//Interface title
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
        if(isset($_POST['aiowpsec_disable_all_features']))//Do form submission tasks
        {
            $nonce=$_REQUEST['_wpnonce'];
            if (!wp_verify_nonce($nonce, 'aiowpsec-disable-all-features'))
            {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed on disable all security features!",4);
                die("Nonce check failed on disable all security features!");
            }
            AIOWPSecurity_Configure_Settings::turn_off_all_security_features();
            //Now let's clear the applicable rules from the .htaccess file
            $res = AIOWPSecurity_Utility_Htaccess::write_to_htaccess();
            
            //Now let's revert the disable editing setting in the wp-config.php file if necessary
            $res2 = AIOWPSecurity_Utility::enable_file_edits();

            if ($res)
            {
                $this->show_msg_updated(__('All the security features have been disabled successfully!', 'all-in-one-wp-security-and-firewall'));
            }
            else
            {
                $this->show_msg_error(__('Could not write to the .htaccess file. Please restore your .htaccess file manually using the restore functionality in the ".htaccess File".', 'all-in-one-wp-security-and-firewall'));
            }

            if(!$res2)
            {
                $this->show_msg_error(__('Could not write to the wp-config.php. Please restore your wp-config.php file manually using the restore functionality in the "wp-config.php File".', 'all-in-one-wp-security-and-firewall'));
            }
        }

        if(isset($_POST['aiowpsec_disable_all_firewall_rules']))//Do form submission tasks
        {
            $nonce=$_REQUEST['_wpnonce'];
            if (!wp_verify_nonce($nonce, 'aiowpsec-disable-all-firewall-rules'))
            {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed on disable all firewall rules!",4);
                die("Nonce check failed on disable all firewall rules!");
            }
            AIOWPSecurity_Configure_Settings::turn_off_all_firewall_rules();
            //Now let's clear the applicable rules from the .htaccess file
            $res = AIOWPSecurity_Utility_Htaccess::write_to_htaccess();

            if ($res)
            {
                $this->show_msg_updated(__('All firewall rules have been disabled successfully!', 'all-in-one-wp-security-and-firewall'));
            }
            else
            {
                $this->show_msg_error(__('Could not write to the .htaccess file. Please restore your .htaccess file manually using the restore functionality in the ".htaccess File".', 'all-in-one-wp-security-and-firewall'));
            }
        }

        if(isset($_POST['aiowps_save_debug_settings']))//Do form submission tasks
        {
            $nonce=$_REQUEST['_wpnonce'];
            if (!wp_verify_nonce($nonce, 'aiowpsec-save-debug-settings'))
            {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed on save debug settings!",4);
                die("Nonce check failed on save debug settings!");
            }

            $aio_wp_security->configs->set_value('aiowps_enable_debug',isset($_POST["aiowps_enable_debug"])?'1':'');
            $aio_wp_security->configs->save_config();
            $this->show_msg_settings_updated();
        }

        ?>
        <div class="aio_grey_box">
 	<p>For information, updates and documentation, please visit the <a href="https://www.tipsandtricks-hq.com/wordpress-security-and-firewall-plugin" target="_blank">AIO WP Security & Firewall Plugin</a> Page.</p>
        <p><a href="https://www.tipsandtricks-hq.com/development-center" target="_blank">Follow us</a> on Twitter, Google+ or via Email to stay upto date about the new security features of this plugin.</p>
        </div>
        
        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('WP Security Plugin', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
        <p><?php _e('Thank you for using our WordPress security plugin. There are a lot of security features in this plugin.', 'all-in-one-wp-security-and-firewall'); ?></p>
        <p><?php _e('Go through each menu items and enable the security options to add more security to your site. Start by activating the basic features first.', 'all-in-one-wp-security-and-firewall'); ?></p>
        <p><?php _e('It is a good practice to take a backup of your .htaccess file, database and wp-config.php file before activating the security features. This plugin has options that you can use to backup those resources easily.', 'all-in-one-wp-security-and-firewall'); ?></p>
        <p>
        <ul class="aiowps_admin_ul_grp1">
            <li><a href="admin.php?page=aiowpsec_database&tab=tab2" target="_blank"><?php _e('Backup your database', 'all-in-one-wp-security-and-firewall'); ?></a></li>
            <li><a href="admin.php?page=aiowpsec_settings&tab=tab2" target="_blank"><?php _e('Backup .htaccess file', 'all-in-one-wp-security-and-firewall'); ?></a></li>
            <li><a href="admin.php?page=aiowpsec_settings&tab=tab3" target="_blank"><?php _e('Backup wp-config.php file', 'all-in-one-wp-security-and-firewall'); ?></a></li>
        </ul>
        </p>
        </div>
        </div> <!-- end postbox-->
        
        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('Disable Security Features', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
        <form method="post" action="<?php echo $_SERVER["REQUEST_URI"]; ?>">
        <?php wp_nonce_field('aiowpsec-disable-all-features'); ?>
        <div class="aio_blue_box">
            <?php
            echo '<p>'.__('If you think that some plugin functionality on your site is broken due to a security feature you enabled in this plugin, then use the following option to turn off all the security features of this plugin.', 'all-in-one-wp-security-and-firewall').'</p>';
            ?>
        </div>      
        <div class="submit">
            <input type="submit" class="button" name="aiowpsec_disable_all_features" value="<?php _e('Disable All Security Features'); ?>" />
        </div>
        </form>   
        </div>
        </div> <!-- end postbox-->

        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('Disable All Firewall Rules', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
        <form method="post" action="<?php echo $_SERVER["REQUEST_URI"]; ?>">
        <?php wp_nonce_field('aiowpsec-disable-all-firewall-rules'); ?>
        <div class="aio_blue_box">
            <?php
            echo '<p>'.__('This feature will disable all firewall rules which are currently active in this plugin and it will also delete these rules from your .htacess file. Use it if you think one of the firewall rules is causing an issue on your site.', 'all-in-one-wp-security-and-firewall').'</p>';
            ?>
        </div>      
        <div class="submit">
            <input type="submit" class="button" name="aiowpsec_disable_all_firewall_rules" value="<?php _e('Disable All Firewall Rules'); ?>" />
        </div>
        </form>   
        </div>
        </div> <!-- end postbox-->

        <div class="postbox">
            <h3 class="hndle"><label for="title"><?php _e('Debug Settings', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
            <div class="inside">
                <form method="post" action="<?php echo $_SERVER["REQUEST_URI"]; ?>">
                    <?php wp_nonce_field('aiowpsec-save-debug-settings'); ?>
                    <div class="aio_blue_box">
                        <?php
                        echo '<p>'.__('This setting allows you to enable/disable debug for this plugin.', 'all-in-one-wp-security-and-firewall').'</p>';
                        echo '<p>'.__('Note: the debug log files are located in the "plugins/all-in-one-wp-security-and-firewall/logs" directory.', 'all-in-one-wp-security-and-firewall').'</p>';
                        ?>
                    </div>

                    <table class="form-table">
                        <tr valign="top">
                            <th scope="row"><?php _e('Enable Debug', 'all-in-one-wp-security-and-firewall')?>:</th>
                            <td>
                                <input name="aiowps_enable_debug" type="checkbox"<?php if($aio_wp_security->configs->get_value('aiowps_enable_debug')=='1') echo ' checked="checked"'; ?> value="1"/>
                                <span class="description"><?php _e('Check this if you want to enable debug. You should keep this option disabled after you have finished debugging the issue.', 'all-in-one-wp-security-and-firewall'); ?></span>
                                <p class="description"><?php _e('Please note that the log files are reset on every plugin update.', 'all-in-one-wp-security-and-firewall'); ?></p>
                            </td>
                        </tr>
                    </table>
                    <input type="submit" name="aiowps_save_debug_settings" value="<?php _e('Save Debug Settings', 'all-in-one-wp-security-and-firewall')?>" class="button" />
                </form>
            </div>
        </div> <!-- end postbox-->
        <?php
    }
    
    function render_tab2()
    {
        global $aio_wp_security;

        if(isset($_POST['aiowps_save_htaccess']))//Do form submission tasks
        {
            $nonce=$_REQUEST['_wpnonce'];
            if (!wp_verify_nonce($nonce, 'aiowpsec-save-htaccess-nonce'))
            {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed on htaccess file save!",4);
                die("Nonce check failed on htaccess file save!");
            }
            $htaccess_path = ABSPATH . '.htaccess';
            $result = AIOWPSecurity_Utility_File::backup_and_rename_htaccess($htaccess_path); //Backup the htaccess file
            
            if ($result)
            {
                $random_prefix = AIOWPSecurity_Utility::generate_alpha_numeric_random_string(10);
                $aiowps_backup_dir = WP_CONTENT_DIR.'/'.AIO_WP_SECURITY_BACKUPS_DIR_NAME;
                if (rename($aiowps_backup_dir.'/'.'.htaccess.backup', $aiowps_backup_dir.'/'.$random_prefix.'_htaccess_backup.txt'))
                {
                    echo '<div id="message" class="updated fade"><p>';
                    _e('Your .htaccess file was successfully backed up! Using an FTP program go to the "/wp-content/aiowps_backups" directory to save a copy of the file to your computer.','all-in-one-wp-security-and-firewall');
                    echo '</p></div>';
                }
                else
                {
                    $aio_wp_security->debug_logger->log_debug("htaccess file rename failed during backup!",4);
                    $this->show_msg_error(__('htaccess file rename failed during backup. Please check your root directory for the backup file using FTP.','all-in-one-wp-security-and-firewall'));
                }
            } 
            else
            {
                $aio_wp_security->debug_logger->log_debug("htaccess - Backup operation failed!",4);
                $this->show_msg_error(__('htaccess backup failed.','all-in-one-wp-security-and-firewall'));
            }
        }
        
        if(isset($_POST['aiowps_restore_htaccess_button']))//Do form submission tasks
        {
            $nonce=$_REQUEST['_wpnonce'];
            if (!wp_verify_nonce($nonce, 'aiowpsec-restore-htaccess-nonce'))
            {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed on htaccess file restore!",4);
                die("Nonce check failed on htaccess file restore!");
            }
            
            if (empty($_POST['aiowps_htaccess_file']))
            {
                $this->show_msg_error(__('Please choose a .htaccess to restore from.', 'all-in-one-wp-security-and-firewall'));
            }
            else
            {
                //Let's copy the uploaded .htaccess file into the active root file
                $new_htaccess_file_path = trim($_POST['aiowps_htaccess_file']);
                //TODO
                //Verify that file chosen has contents which are relevant to .htaccess file
                $is_htaccess = AIOWPSecurity_Utility_Htaccess::check_if_htaccess_contents($new_htaccess_file_path);
                if ($is_htaccess == 1)
                {
                    $active_root_htaccess = ABSPATH.'.htaccess';
                    if (!copy($new_htaccess_file_path, $active_root_htaccess)) 
                    {
                        //Failed to make a backup copy
                        $aio_wp_security->debug_logger->log_debug("htaccess - Restore from .htaccess operation failed!",4);
                        $this->show_msg_error(__('htaccess file restore failed. Please attempt to restore the .htaccess manually using FTP.','all-in-one-wp-security-and-firewall'));
                    }
                    else
                    {
                        $this->show_msg_updated(__('Your .htaccess file has successfully been restored!', 'all-in-one-wp-security-and-firewall'));
                    }
                }
                else
                {
                    $aio_wp_security->debug_logger->log_debug("htaccess restore failed - Contents of restore file appear invalid!",4);
                    $this->show_msg_error(__('htaccess Restore operation failed! Please check the contents of the file you are trying to restore from.','all-in-one-wp-security-and-firewall'));
                }
            }
        }
        
        ?>
        <h2><?php _e('.htaccess File Operations', 'all-in-one-wp-security-and-firewall')?></h2>
        <div class="aio_blue_box">
            <?php
            echo '<p>'.__('Your ".htaccess" file is a key component of your website\'s security and it can be modified to implement various levels of protection mechanisms.', 'all-in-one-wp-security-and-firewall').'
            <br />'.__('This feature allows you to backup and save your currently active .htaccess file should you need to re-use the the backed up file in the future.', 'all-in-one-wp-security-and-firewall').'
            <br />'.__('You can also restore your site\'s .htaccess settings using a backed up .htaccess file.', 'all-in-one-wp-security-and-firewall').'
            </p>';
            ?>
        </div>
        <?php 
        if (AIOWPSecurity_Utility::is_multisite_install() && get_current_blog_id() != 1)
        {
           //Hide config settings if MS and not main site
           AIOWPSecurity_Utility::display_multisite_message();
        }
        else
        {
        ?>
        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('Save the current .htaccess file', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
        <form action="" method="POST">
        <?php wp_nonce_field('aiowpsec-save-htaccess-nonce'); ?>
            <p class="description"><?php _e('Click the button below to backup and save the currently active .htaccess file.', 'all-in-one-wp-security-and-firewall'); ?></p>
            <input type="submit" name="aiowps_save_htaccess" value="<?php _e('Backup .htaccess File', 'all-in-one-wp-security-and-firewall')?>" class="button-primary" />
        </form>
        </div></div>
        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('Restore from a backed up .htaccess file', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
        <form action="" method="POST">
        <?php wp_nonce_field('aiowpsec-restore-htaccess-nonce'); ?>
        <table class="form-table">
            <tr valign="top">
                <th scope="row"><?php _e('.htaccess file to restore from', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td>
                    <input type="button" id="aiowps_htaccess_file_button" name="aiowps_htaccess_file_button" class="button rbutton" value="Select Your htaccess File" />
                    <input name="aiowps_htaccess_file" type="text" id="aiowps_htaccess_file" value="" size="80" />
                    <p class="description">
                        <?php
                        _e('After selecting your file, click the button below to restore your site using the backed up htaccess file (htaccess_backup.txt).', 'all-in-one-wp-security-and-firewall');
                        ?>
                    </p>
                </td>
            </tr>            
        </table>
        <input type="submit" name="aiowps_restore_htaccess_button" value="<?php _e('Restore .htaccess File', 'all-in-one-wp-security-and-firewall')?>" class="button-primary" />
        </form>
        </div></div>
<!--        <div class="postbox">-->
<!--        <h3 class="hndle"><label for="title">--><?php //_e('View Contents of the currently active .htaccess file', 'all-in-one-wp-security-and-firewall'); ?><!--</label></h3>-->
<!--        <div class="inside">-->
<!--            --><?php
//            $ht_file = ABSPATH . '.htaccess';
//            $ht_contents = AIOWPSecurity_Utility_File::get_file_contents($ht_file);
//            //echo $ht_contents;
//            ?>
<!--            <textarea class="aio_text_area_file_output aio_half_width aio_spacer_10_tb" rows="15" readonly>--><?php //echo $ht_contents; ?><!--</textarea>-->
<!--        </div></div>-->

        <?php
        } // End if statement
    }

    function render_tab3()
    {
        global $aio_wp_security;
        
        if(isset($_POST['aiowps_restore_wp_config_button']))//Do form submission tasks
        {
            $nonce=$_REQUEST['_wpnonce'];
            if (!wp_verify_nonce($nonce, 'aiowpsec-restore-wp-config-nonce'))
            {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed on wp-config file restore!",4);
                die("Nonce check failed on wp-config file restore!");
            }
            
            if (empty($_POST['aiowps_wp_config_file']))
            {
                $this->show_msg_error(__('Please choose a wp-config.php file to restore from.', 'all-in-one-wp-security-and-firewall'));
            }
            else
            {
                //Let's copy the uploaded wp-config.php file into the active root file
                $new_wp_config_file_path = trim($_POST['aiowps_wp_config_file']);
                
                //Verify that file chosen is a wp-config.file
                $is_wp_config = $this->check_if_wp_config_contents($new_wp_config_file_path);
                if ($is_wp_config == 1)
                {
                    $active_root_wp_config = AIOWPSecurity_Utility_File::get_wp_config_file_path();
                    if (!copy($new_wp_config_file_path, $active_root_wp_config)) 
                    {
                        //Failed to make a backup copy
                        $aio_wp_security->debug_logger->log_debug("wp-config.php - Restore from backed up wp-config operation failed!",4);
                        $this->show_msg_error(__('wp-config.php file restore failed. Please attempt to restore this file manually using FTP.','all-in-one-wp-security-and-firewall'));
                    }
                    else
                    {
                        $this->show_msg_updated(__('Your wp-config.php file has successfully been restored!', 'all-in-one-wp-security-and-firewall'));
                    }
                }
                else
                {
                    $aio_wp_security->debug_logger->log_debug("wp-config.php restore failed - Contents of restore file appear invalid!",4);
                    $this->show_msg_error(__('wp-config.php Restore operation failed! Please check the contents of the file you are trying to restore from.','all-in-one-wp-security-and-firewall'));
                }
            }
        }
        
        ?>
        <h2><?php _e('wp-config.php File Operations', 'all-in-one-wp-security-and-firewall')?></h2>
        <div class="aio_blue_box">
            <?php
            echo '<p>'.__('Your "wp-config.php" file is one of the most important in your WordPress installation. It is a primary configuration file and contains crucial things such as details of your database and other critical components.', 'all-in-one-wp-security-and-firewall').'
            <br />'.__('This feature allows you to backup and save your currently active wp-config.php file should you need to re-use the the backed up file in the future.', 'all-in-one-wp-security-and-firewall').'
            <br />'.__('You can also restore your site\'s wp-config.php settings using a backed up wp-config.php file.', 'all-in-one-wp-security-and-firewall').'
            </p>';
            ?>
        </div>
        <?php 
        if (AIOWPSecurity_Utility::is_multisite_install() && get_current_blog_id() != 1)
        {
           //Hide config settings if MS and not main site
           AIOWPSecurity_Utility::display_multisite_message();
        }
        else
        {
        ?>
        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('Save the current wp-config.php file', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
        <form action="" method="POST">
        <?php wp_nonce_field('aiowpsec-save-wp-config-nonce'); ?>
            <p class="description"><?php _e('Click the button below to backup and download the contents of the currently active wp-config.php file.', 'all-in-one-wp-security-and-firewall'); ?></p>
            <input type="submit" name="aiowps_save_wp_config" value="<?php _e('Backup wp-config.php File', 'all-in-one-wp-security-and-firewall')?>" class="button-primary" />

        </form>
        </div></div>
        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('Restore from a backed up wp-config file', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
        <form action="" method="POST">
        <?php wp_nonce_field('aiowpsec-restore-wp-config-nonce'); ?>
        <table class="form-table">
            <tr valign="top">
                <th scope="row"><?php _e('wp-config file to restore from', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td>
                    <input type="button" id="aiowps_wp_config_file_button" name="aiowps_wp_config_file_button" class="button rbutton" value="Select Your wp-config File" />
                    <input name="aiowps_wp_config_file" type="text" id="aiowps_wp_config_file" value="" size="80" />                    
                    <p class="description">
                        <?php
                        _e('After selecting your file click the button below to restore your site using the backed up wp-config file (wp-config.php.backup.txt).', 'all-in-one-wp-security-and-firewall');
                        ?>
                    </p>
                </td>
            </tr>            
        </table>
        <input type="submit" name="aiowps_restore_wp_config_button" value="<?php _e('Restore wp-config File', 'all-in-one-wp-security-and-firewall')?>" class="button-primary" />
        </form>
        </div></div>
<!--        <div class="postbox">-->
<!--        <h3 class="hndle"><label for="title">--><?php //_e('View Contents of the currently active wp-config.php file', 'all-in-one-wp-security-and-firewall'); ?><!--</label></h3>-->
<!--        <div class="inside">-->
<!--            --><?php
//            $wp_config_file = AIOWPSecurity_Utility_File::get_wp_config_file_path();
//            $wp_config_contents = AIOWPSecurity_Utility_File::get_file_contents($wp_config_file);
//            ?>
<!--            <textarea class="aio_text_area_file_output aio_width_80 aio_spacer_10_tb" rows="20" readonly>--><?php //echo $wp_config_contents; ?><!--</textarea>-->
<!--        </div></div>-->

        <?php
        } //End if statement
    }
    
    function render_tab4()
    {
        global $aio_wp_security;
        global $aiowps_feature_mgr;
        
        if(isset($_POST['aiowps_save_remove_wp_meta_info']))//Do form submission tasks
        {
            $nonce=$_REQUEST['_wpnonce'];
            if (!wp_verify_nonce($nonce, 'aiowpsec-remove-wp-meta-info-nonce'))
            {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed on remove wp meta info options save!",4);
                die("Nonce check failed on remove wp meta info options save!");
            }
            $aio_wp_security->configs->set_value('aiowps_remove_wp_generator_meta_info',isset($_POST["aiowps_remove_wp_generator_meta_info"])?'1':'');
            $aio_wp_security->configs->save_config();
            
            //Recalculate points after the feature status/options have been altered
            $aiowps_feature_mgr->check_feature_status_and_recalculate_points();
            
            $this->show_msg_settings_updated();
    }
        ?>
        <h2><?php _e('WP Generator Meta Tag & Version Info', 'all-in-one-wp-security-and-firewall')?></h2>
        <div class="aio_blue_box">
            <?php
            echo '<p>'.__('Wordpress generator automatically adds some meta information inside the "head" tags of every page on your site\'s front end. Below is an example of this:', 'all-in-one-wp-security-and-firewall');
            echo '<br /><strong>&lt;meta name="generator" content="WordPress 3.5.1" /&gt;</strong>';
            echo '<br />'.__('The above meta information shows which version of WordPress your site is currently running and thus can help hackers or crawlers scan your site to see if you have an older version of WordPress or one with a known exploit.', 'all-in-one-wp-security-and-firewall').'
            <br /><br />'.__('There are also other ways wordpress reveals version info such as during style and script loading. An example of this is:', 'all-in-one-wp-security-and-firewall').'
            <br /><strong>&lt;link rel="stylesheet" id="jquery-ui-style-css"  href="//ajax.googleapis.com/ajax/libs/jqueryui/1.11.0/themes/smoothness/jquery-ui.css?ver=4.5.2" type="text/css" media="all" /&gt;</strong>
            <br /><br />'.__('This feature will allow you to remove the WP generator meta info and other version info from your site\'s pages.', 'all-in-one-wp-security-and-firewall').'
            </p>';
            ?>
        </div>

        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('WP Generator Meta Info', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
        <?php
        //Display security info badge
        global $aiowps_feature_mgr;
        $aiowps_feature_mgr->output_feature_details_badge("wp-generator-meta-tag");
        ?>

        <form action="" method="POST">
        <?php wp_nonce_field('aiowpsec-remove-wp-meta-info-nonce'); ?>            
        <table class="form-table">
            <tr valign="top">
                <th scope="row"><?php _e('Remove WP Generator Meta Info', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td>
                <input name="aiowps_remove_wp_generator_meta_info" type="checkbox"<?php if($aio_wp_security->configs->get_value('aiowps_remove_wp_generator_meta_info')=='1') echo ' checked="checked"'; ?> value="1"/>
                <span class="description"><?php _e('Check this if you want to remove the version and meta info produced by WP from all pages', 'all-in-one-wp-security-and-firewall'); ?></span>
                </td>
            </tr>            
        </table>
        <input type="submit" name="aiowps_save_remove_wp_meta_info" value="<?php _e('Save Settings', 'all-in-one-wp-security-and-firewall')?>" class="button-primary" />
        </form>
        </div></div>
    <?php
    }

    
function render_tab5()
    {
        global $aio_wp_security;
        
        global $wpdb;

        $events_table_name = AIOWPSEC_TBL_EVENTS;
        AIOWPSecurity_Utility::cleanup_table($events_table_name, 500);        
        if(isset($_POST['aiowps_import_settings']))//Do form submission tasks
        {
            $nonce=$_REQUEST['_wpnonce'];
            if (!wp_verify_nonce($nonce, 'aiowpsec-import-settings-nonce'))
            {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed on import AIOWPS settings!",4);
                die("Nonce check failed on import AIOWPS settings!");
            }

            if (empty($_POST['aiowps_import_settings_file']) && empty($_POST['aiowps_import_settings_text']))
            {
                $this->show_msg_error(__('Please choose a file to import your settings from.', 'all-in-one-wp-security-and-firewall'));
            }
            else
            {
                if (empty($_POST['aiowps_import_settings_file'])) {
                    $import_from = "text";
                } else {
                    $import_from = "file";
                }

                if ($import_from == "file") {
                    //Let's get the uploaded import file path
                    $submitted_import_file_path = trim($_POST['aiowps_import_settings_file']);
                    $attachment_id = AIOWPSecurity_Utility_File::get_attachment_id_from_url($submitted_import_file_path); //we'll need this later for deleting

                    //Verify that file chosen has valid AIOWPS settings contents
                    $aiowps_settings_file_contents = $this->check_if_valid_aiowps_settings_file($submitted_import_file_path);
                } else {
                    //Get the string right from the textarea. Still confirm it's in the expected format.
                    $aiowps_settings_file_contents = $this->check_if_valid_aiowps_settings_text($_POST['aiowps_import_settings_text']);
                }

                if ($aiowps_settings_file_contents != -1)
                {
                    //Apply the settings and delete the file (if applicable)
                    $settings_array = json_decode($aiowps_settings_file_contents, true);
                    $aiowps_settings_applied = update_option('aio_wp_security_configs', $settings_array);
                    
                    if (!$aiowps_settings_applied)
                    {
                        //Failed to import settings
                        $aio_wp_security->debug_logger->log_debug("Import AIOWPS settings from " . $import_from . " operation failed!",4);
                        $this->show_msg_error(__('Import AIOWPS settings from ' . $import_from . ' operation failed!','all-in-one-wp-security-and-firewall'));

                        if ($import_from == "file") {
                            //Delete the uploaded settings file for security purposes
                            wp_delete_attachment( $attachment_id, true );
                            if ( false === wp_delete_attachment( $attachment_id, true ) ){
                                $this->show_msg_error(__('The deletion of the import file failed. Please delete this file manually via the media menu for security purposes.', 'all-in-one-wp-security-and-firewall'));
                            }else{
                                $this->show_msg_updated(__('The file you uploaded was also deleted for security purposes because it contains security settings details.', 'all-in-one-wp-security-and-firewall'));
                            }
                        }
                    }
                    else
                    {
                        $aio_wp_security->configs->configs = $settings_array; //Refresh the configs global variable

                        //Just in case user submits partial config settings
                        //Run add_option_values to make sure any missing config items are at least set to default
                        AIOWPSecurity_Configure_Settings::add_option_values();
                        if ($import_from == "file") {
                            //Delete the uploaded settings file for security purposes
                            wp_delete_attachment( $attachment_id, true );
                            if ( false === wp_delete_attachment( $attachment_id, true ) ){
                                $this->show_msg_updated(__('Your AIOWPS settings were successfully imported via file input.', 'all-in-one-wp-security-and-firewall'));
                                $this->show_msg_error(__('The deletion of the import file failed. Please delete this file manually via the media menu for security purposes because it contains security settings details.', 'all-in-one-wp-security-and-firewall'));
                            }else{
                                $this->show_msg_updated(__('Your AIOWPS settings were successfully imported. The file you uploaded was also deleted for security purposes because it contains security settings details.', 'all-in-one-wp-security-and-firewall'));
                            }
                        } else {
                            $this->show_msg_updated(__('Your AIOWPS settings were successfully imported via text entry.', 'all-in-one-wp-security-and-firewall'));
                        }
                        //Now let's refresh the .htaccess file with any modified rules if applicable
                        $res = AIOWPSecurity_Utility_Htaccess::write_to_htaccess();

                        if( !$res )
                        {
                            $this->show_msg_error(__('Could not write to the .htaccess file. Please check the file permissions.', 'all-in-one-wp-security-and-firewall'));
                        }
                    }
                }
                else
                {
                    //Invalid settings file
                    $aio_wp_security->debug_logger->log_debug("The contents of your settings file appear invalid!",4);
                    $this->show_msg_error(__('The contents of your settings file appear invalid. Please check the contents of the file you are trying to import settings from.','all-in-one-wp-security-and-firewall'));

                    if ($import_from == "file") {
                        //Let's also delete the uploaded settings file for security purposes
                        wp_delete_attachment( $attachment_id, true );
                        if ( false === wp_delete_attachment( $attachment_id, true ) ){
                            $this->show_msg_error(__('The deletion of the import file failed. Please delete this file manually via the media menu for security purposes.', 'all-in-one-wp-security-and-firewall'));
                        }else{
                            $this->show_msg_updated(__('The file you uploaded was also deleted for security purposes because it contains security settings details.', 'all-in-one-wp-security-and-firewall'));
                        }
                    }

                }
            }
        }

        ?>
        <h2><?php _e('Export or Import Your AIOWPS Settings', 'all-in-one-wp-security-and-firewall')?></h2>
        <div class="aio_blue_box">
            <?php
            echo '<p>'.__('This section allows you to export or import your All In One WP Security & Firewall settings.', 'all-in-one-wp-security-and-firewall');
            echo '<br />'.__('This can be handy if you wanted to save time by applying the settings from one site to another site.', 'all-in-one-wp-security-and-firewall').'
            <br />'.__('NOTE: Before importing, it is your responsibility to know what settings you are trying to import. Importing settings blindly can cause you to be locked out of your site.', 'all-in-one-wp-security-and-firewall').'
            <br />'.__('For Example: If a settings item relies on the domain URL then it may not work correctly when imported into a site with a different domain.','all-in-one-wp-security-and-firewall').'
            </p>';
            ?>
        </div>

        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('Export AIOWPS Settings', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
        <form action="" method="POST">
        <?php wp_nonce_field('aiowpsec-export-settings-nonce'); ?>
        <table class="form-table">
            <tr valign="top">
            <span class="description"><?php _e('To export your All In One WP Security & Firewall settings click the button below.', 'all-in-one-wp-security-and-firewall'); ?></span>
            </tr>
        </table>
        <input type="submit" name="aiowps_export_settings" value="<?php _e('Export AIOWPS Settings', 'all-in-one-wp-security-and-firewall')?>" class="button-primary" />
        </form>
        </div></div>
        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('Import AIOWPS Settings', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
        <form action="" method="POST">
        <?php wp_nonce_field('aiowpsec-import-settings-nonce'); ?>
        <table class="form-table">
            <tr valign="top">
                <span class="description"><?php _e('Use this section to import your All In One WP Security & Firewall settings from a file. Alternatively, copy/paste the contents of your import file into the textarea below.', 'all-in-one-wp-security-and-firewall'); ?></span>
                <th scope="row"><?php _e('Import File', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td>
                    <input type="button" id="aiowps_import_settings_file_button" name="aiowps_import_settings_file_button" class="button rbutton" value="Select Your Import Settings File" />
                    <input name="aiowps_import_settings_file" type="text" id="aiowps_import_settings_file" value="" size="80" />
                    <p class="description">
                        <?php
                        _e('After selecting your file, click the button below to apply the settings to your site.', 'all-in-one-wp-security-and-firewall');
                        ?>
                    </p>
                </td>
            </tr>
            <tr valign="top">
                <th scope="row"><?php _e('Copy/Paste Import Data', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td>
                    <textarea name="aiowps_import_settings_text" id="aiowps_import_settings_text" style="width:80%;height:140px;"></textarea>
                </td>
            </tr>
        </table>
        <input type="submit" name="aiowps_import_settings" value="<?php _e('Import AIOWPS Settings', 'all-in-one-wp-security-and-firewall')?>" class="button-primary" />
        </form>
        </div></div>
    <?php
    }

    function render_tab6()
    {
        global $aio_wp_security;
        
        $result = 1;
        if (isset($_POST['aiowps_save_advanced_settings']))
        {
            $nonce=$_REQUEST['_wpnonce'];
            if (!wp_verify_nonce($nonce, 'aiowpsec-ip-settings-nonce'))
            {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed for save advanced settings!",4);
                die(__('Nonce check failed for save advanced settings!','aiowpsecurity'));
            }
            
            $aio_wp_security->configs->set_value('aiowps_ip_retrieve_method', sanitize_text_field($_POST["aiowps_ip_retrieve_method"]));
            $aio_wp_security->configs->save_config(); //Save the configuration

            //Clear logged in list because it might be showing wrong addresses
            if (AIOWPSecurity_Utility::is_multisite_install()){
                delete_site_transient('users_online');
            }
            else{
                delete_transient('users_online');
            }
            
            $this->show_msg_settings_updated();
        }
        ?>
        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('IP Retrieval Settings', 'aiowpsecurity'); ?></label></h3>
        <div class="inside">
        <div class="aio_blue_box">
            <?php
            echo '<p>'.__('The IP Retrieval Settings allow you to specify which $_SERVER global variable you want this plugin to use to retrieve the visitor IP address.', 'aiowpsecurity').
            '<br />'.__('By default this plugin uses the $_SERVER[\'REMOTE_ADDR\'] variable to retrieve the visitor IP address. This should normally be the most accurate safest way to get the IP.', 'aiowpsecurity').
            '<br />'.__('However in some setups such as those using proxies, load-balancers and CloudFlare, it may be necessary to use a different $_SERVER variable.', 'aiowpsecurity').
            '<br />'.__('You can use the settings below to configure which $_SERVER global you would like to use for retrieving the IP address.', 'aiowpsecurity').'</p>';
            ?>
        </div>
            
        <form action="" method="POST">
        <?php wp_nonce_field('aiowpsec-ip-settings-nonce'); ?>            
        <table class="form-table">
            <tr valign="top">
                <td>
                    <select id="aiowps_ip_retrieve_method" name="aiowps_ip_retrieve_method">
                        <option value="0" <?php selected( $aio_wp_security->configs->get_value('aiowps_ip_retrieve_method'), '0' ); ?>><?php echo 'REMOTE_ADDR' .' ('.__('Default','aiowpsecurity').')'; ?></option>
                        <option value="1" <?php selected( $aio_wp_security->configs->get_value('aiowps_ip_retrieve_method'), '1' ); ?>><?php echo 'HTTP_CF_CONNECTING_IP'; ?></option>
                        <option value="2" <?php selected( $aio_wp_security->configs->get_value('aiowps_ip_retrieve_method'), '2' ); ?>><?php echo 'HTTP_X_FORWARDED_FOR'; ?></option>
                        <option value="3" <?php selected( $aio_wp_security->configs->get_value('aiowps_ip_retrieve_method'), '3' ); ?>><?php echo 'HTTP_X_FORWARDED'; ?></option>
                        <option value="4" <?php selected( $aio_wp_security->configs->get_value('aiowps_ip_retrieve_method'), '4' ); ?>><?php echo 'HTTP_CLIENT_IP'; ?></option>
                    </select>
                <span class="description"><?php _e('Choose a $_SERVER variable you would like to retrieve the visitor IP address from.', 'aiowpsecurity'); ?>
                </span>
                <span class="aiowps_more_info_anchor"><span class="aiowps_more_info_toggle_char">+</span><span class="aiowps_more_info_toggle_text"><?php _e('More Info', 'all-in-one-wp-security-and-firewall'); ?></span></span>
                <div class="aiowps_more_info_body">
                    <p class="description">
                        <?php 
                        _e('If your chosen server variable fails the plugin will automatically fall back to retrieving the IP address from $_SERVER["REMOTE_ADDR"]', 'all-in-one-wp-security-and-firewall');
                        ?>
                    </p>
                </div>
                </td> 
            </tr>            
        </table>
        <input type="submit" name="aiowps_save_advanced_settings" value="<?php _e('Save Settings', 'aiowpsecurity')?>" class="button-primary" />
        </form>
        </div></div>
        <?php
        
    }
    
    function check_if_wp_config_contents($wp_file)
    {
        $is_wp_config = false;

        $file_contents = file($wp_file);

        if ($file_contents == '' || $file_contents == NULL || $file_contents == false)
        {
            return -1;
        }
        foreach ($file_contents as $line)
        {
            if ((strpos($line, "define('DB_NAME'") !== false))
            {
                $is_wp_config = true; //It appears that we have some sort of wp-config.php file
                break;
            }
            else
            {
                //see if we're at the end of the section
                $is_wp_config = false;
            }
        }
        if ($is_wp_config)
        {
            return 1;
        }
        else
        {
            return -1;
        }

    }

    function check_if_valid_aiowps_settings_text($strText) {
        if ($this->check_is_aiopws_settings($strText)) {
            return stripcslashes($strText);
        } else {
            return -1;
        }
    }

    function check_is_aiopws_settings($strText) {
        if(strpos($strText, 'aiowps_enable_login_lockdown') === FALSE){
            return false;
        } else {
            return true;
        }
    }

    //Checks if valid aiowps settings file and returns contents as string
    function check_if_valid_aiowps_settings_file($wp_file)
    {
        $is_aiopws_settings = false;

        $file_contents = file_get_contents($wp_file);

        if ($file_contents == '' || $file_contents == NULL || $file_contents == false)
        {
            return -1;
        }

        //Check a known aiowps config strings to see if it is contained within this file
        $is_aiopws_settings = $this->check_is_aiopws_settings($file_contents);

        if ($is_aiopws_settings)
        {
            return $file_contents;
        }
        else
        {
            return -1;
        }

    }

} //end class