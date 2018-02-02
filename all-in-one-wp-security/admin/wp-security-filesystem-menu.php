<?php
if ( !defined( 'ABSPATH' ) ) { exit; } // Prevent direct access to file
class AIOWPSecurity_Filesystem_Menu extends AIOWPSecurity_Admin_Menu
{
    var $menu_page_slug = AIOWPSEC_FILESYSTEM_MENU_SLUG;
    
    /* Specify all the tabs of this menu in the following array */
    var $menu_tabs;

    var $menu_tabs_handler = array(
        'tab1' => 'render_tab1', 
        'tab2' => 'render_tab2',
        'tab3' => 'render_tab3',
        'tab4' => 'render_tab4',
        );
    
    function __construct() 
    {
        $this->render_menu_page();
        add_action( 'admin_footer', array( &$this, 'filesystem_menu_footer_code' ) );
    }
    
    function set_menu_tabs() 
    {
        $this->menu_tabs = array(
        'tab1' => __('File Permissions','all-in-one-wp-security-and-firewall'),
        'tab2' => __('PHP File Editing','all-in-one-wp-security-and-firewall'),
        'tab3' => __('WP File Access','all-in-one-wp-security-and-firewall'),
        'tab4' => __('Host System Logs','all-in-one-wp-security-and-firewall'),
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
        echo '<h2>'.__('Filesystem Security','all-in-one-wp-security-and-firewall').'</h2>';//Interface title
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
        //if this is the case there is no need to display a "fix permissions" button
        global $wpdb, $aio_wp_security;
        if (isset($_POST['aiowps_fix_permissions']))
        {
            $nonce=$_REQUEST['_wpnonce'];
            if (!wp_verify_nonce($nonce, 'aiowpsec-fix-permissions-nonce'))
            {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed for manual DB backup operation!",4);
                die(__('Nonce check failed for manual DB backup operation!','all-in-one-wp-security-and-firewall'));
            }
            if (isset($_POST['aiowps_permission_chg_file']))
            {
                $folder_or_file = $_POST['aiowps_permission_chg_file'];
                $rec_perm_oct_string = $_POST['aiowps_recommended_permissions']; //Convert the octal string to dec so the chmod func will accept it
                $rec_perm_dec = octdec($rec_perm_oct_string); //Convert the octal string to dec so the chmod func will accept it
                $perm_result = @chmod($_POST['aiowps_permission_chg_file'], $rec_perm_dec);
                if ($perm_result === true)
                {
                    $msg = sprintf( __('The permissions for %s were succesfully changed to %s', 'all-in-one-wp-security-and-firewall'), $folder_or_file, $rec_perm_oct_string);
                    $this->show_msg_updated($msg);
                }else if($perm_result === false)
                {
                    $msg = sprintf( __('Unable to change permissions for %s!', 'all-in-one-wp-security-and-firewall'), $folder_or_file);
                    $this->show_msg_error($msg);
                }
            }
        }
        ?>
        <h2><?php _e('File Permissions Scan', 'all-in-one-wp-security-and-firewall')?></h2>
        <div class="aio_blue_box">
            <?php
            echo '<p>'.__('Your WordPress file and folder permission settings govern the accessability and read/write privileges of the files and folders which make up your WP installation.', 'all-in-one-wp-security-and-firewall').'
            <br />'.__('Your WP installation already comes with reasonably secure file permission settings for the filesystem.', 'all-in-one-wp-security-and-firewall').'
            <br />'.__('However, sometimes people or other plugins modify the various permission settings of certain core WP folders or files such that they end up making their site less secure because they chose the wrong permission values.', 'all-in-one-wp-security-and-firewall').'
            <br />'.__('This feature will scan the critical WP core folders and files and will highlight any permission settings which are insecure.', 'all-in-one-wp-security-and-firewall').'
            </p>';
            ?>
        </div>
        <?php
        $detected_os = strtoupper(PHP_OS);
        if(strpos($detected_os, "WIN") !== false){
            echo '<div class="aio_yellow_box">';
            echo '<p>'.__('This plugin has detected that your site is running on a Windows server.', 'all-in-one-wp-security-and-firewall').'
            <br />'.__('This feature is not applicable for Windows server installations.', 'all-in-one-wp-security-and-firewall').'
            </p>';
            echo '</div>';
        }else{
        ?>
        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('WP Directory and File Permissions Scan Results', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
        <?php
        //Display security info badge
        global $aiowps_feature_mgr;
        $aiowps_feature_mgr->output_feature_details_badge("filesystem-file-permissions");
        ?>
        <form action="" method="POST">
        <?php wp_nonce_field('aiowpsec-fix-permissions-nonce'); ?>            
            <table class="widefat file_permission_table">
                <thead>
                    <tr>
                        <th><?php _e('Name', 'all-in-one-wp-security-and-firewall') ?></th>
                        <th><?php _e('File/Folder', 'all-in-one-wp-security-and-firewall') ?></th>
                        <th><?php _e('Current Permissions', 'all-in-one-wp-security-and-firewall') ?></th>
                        <th><?php _e('Recommended Permissions', 'all-in-one-wp-security-and-firewall') ?></th>
                        <th><?php _e('Recommended Action', 'all-in-one-wp-security-and-firewall') ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php
                    $util = new AIOWPSecurity_Utility_File;
                    $files_dirs_to_check = $util->files_and_dirs_to_check;
                    foreach ($files_dirs_to_check as $file_or_dir)
                    {
                        $this->show_wp_filesystem_permission_status($file_or_dir['name'],$file_or_dir['path'],$file_or_dir['permissions']);
                    }
                    ?>
                </tbody>
                <tfoot>
                    <tr>
                        <th><?php _e('Name', 'all-in-one-wp-security-and-firewall') ?></th>
                        <th><?php _e('File/Folder', 'all-in-one-wp-security-and-firewall') ?></th>
                        <th><?php _e('Current Permissions', 'all-in-one-wp-security-and-firewall') ?></th>
                        <th><?php _e('Recommended Permissions', 'all-in-one-wp-security-and-firewall') ?></th>
                        <th><?php _e('Recommended Action', 'all-in-one-wp-security-and-firewall') ?></th>
                </tfoot>
            </table>
        </form>
        </div></div>
        <?php
        }
    }
    
    function render_tab2()
    {
        global $aio_wp_security;
        global $aiowps_feature_mgr;

        if(isset($_POST['aiowps_disable_file_edit']))//Do form submission tasks
        {
            $nonce=$_REQUEST['_wpnonce'];
            if (!wp_verify_nonce($nonce, 'aiowpsec-disable-file-edit-nonce'))
            {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed on disable PHP file edit options save!",4);
                die("Nonce check failed on disable PHP file edit options save!");
            }

            if(isset($_POST['aiowps_disable_file_editing']))
            {

                $res = AIOWPSecurity_Utility::disable_file_edits();//$this->disable_file_edits();
            } else 
            {
                $res = AIOWPSecurity_Utility::enable_file_edits();//$this->enable_file_edits();
            }
            if ($res)
            {
                //Save settings if no errors
                $aio_wp_security->configs->set_value('aiowps_disable_file_editing',isset($_POST["aiowps_disable_file_editing"])?'1':'');
                $aio_wp_security->configs->save_config();
                
                //Recalculate points after the feature status/options have been altered
                $aiowps_feature_mgr->check_feature_status_and_recalculate_points();
                $this->show_msg_updated(__('Your PHP file editing settings were saved successfully.', 'all-in-one-wp-security-and-firewall'));
            }
            else
            {
                $this->show_msg_error(__('Operation failed! Unable to modify or make a backup of wp-config.php file!', 'all-in-one-wp-security-and-firewall'));
            }
            //$this->show_msg_settings_updated();

        }
        else {
                // Make sure the setting value is up-to-date with current value in WP config
                $aio_wp_security->configs->set_value('aiowps_disable_file_editing', defined('DISALLOW_FILE_EDIT') && DISALLOW_FILE_EDIT ? '1' : '');
                $aio_wp_security->configs->save_config();
                //Recalculate points after the feature status/options have been altered
                $aiowps_feature_mgr->check_feature_status_and_recalculate_points();
        }
        ?>
        <h2><?php _e('File Editing', 'all-in-one-wp-security-and-firewall')?></h2>
        <div class="aio_blue_box">
            <?php
            echo '<p>'.__('The Wordpress Dashboard by default allows administrators to edit PHP files, such as plugin and theme files.', 'all-in-one-wp-security-and-firewall').'
            <br />'.__('This is often the first tool an attacker will use if able to login, since it allows code execution.', 'all-in-one-wp-security-and-firewall').'
            <br />'.__('This feature will disable the ability for people to edit PHP files via the dashboard.', 'all-in-one-wp-security-and-firewall').'
            </p>';
            ?>
        </div>

        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('Disable PHP File Editing', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
        <?php
        //Display security info badge
        global $aiowps_feature_mgr;
        $aiowps_feature_mgr->output_feature_details_badge("filesystem-file-editing");
        ?>

        <form action="" method="POST">
        <?php wp_nonce_field('aiowpsec-disable-file-edit-nonce'); ?>            
        <table class="form-table">
            <tr valign="top">
                <th scope="row"><?php _e('Disable Ability To Edit PHP Files', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td>
                <input name="aiowps_disable_file_editing" type="checkbox"<?php if($aio_wp_security->configs->get_value('aiowps_disable_file_editing')=='1') echo ' checked="checked"'; ?> value="1"/>
                <span class="description"><?php _e('Check this if you want to remove the ability for people to edit PHP files via the WP dashboard', 'all-in-one-wp-security-and-firewall'); ?></span>
                </td>
            </tr>            
        </table>
        <input type="submit" name="aiowps_disable_file_edit" value="<?php _e('Save Settings', 'all-in-one-wp-security-and-firewall')?>" class="button-primary" />
        </form>
        </div></div>
    <?php
    }

    function render_tab3()
    {
        global $aio_wp_security;
        global $aiowps_feature_mgr;
        if(isset($_POST['aiowps_save_wp_file_access_settings']))//Do form submission tasks
        {
            $nonce=$_REQUEST['_wpnonce'];
            if (!wp_verify_nonce($nonce, 'aiowpsec-prevent-default-wp-file-access-nonce'))
            {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed on enable basic firewall settings!",4);
                die("Nonce check failed on enable basic firewall settings!");
            }

            //Save settings
            if(isset($_POST['aiowps_prevent_default_wp_file_access']))
            {
                $aio_wp_security->configs->set_value('aiowps_prevent_default_wp_file_access','1');
            } 
            else
            {
                $aio_wp_security->configs->set_value('aiowps_prevent_default_wp_file_access','');
            }

            //Commit the config settings
            $aio_wp_security->configs->save_config();
            
            //Recalculate points after the feature status/options have been altered
            $aiowps_feature_mgr->check_feature_status_and_recalculate_points();

            //Now let's write the applicable rules to the .htaccess file
            $res = AIOWPSecurity_Utility_Htaccess::write_to_htaccess();

            if ($res)
            {
                $this->show_msg_updated(__('You have successfully saved the Prevent Access to Default WP Files configuration.', 'all-in-one-wp-security-and-firewall'));
            }
            else
            {
                $this->show_msg_error(__('Could not write to the .htaccess file. Please check the file permissions.', 'all-in-one-wp-security-and-firewall'));
            }
        }

        ?>
        <h2><?php _e('WordPress Files', 'all-in-one-wp-security-and-firewall')?></h2>
        <div class="aio_blue_box">
            <?php
            $info_msg = sprintf( __('This feature allows you to prevent access to files such as %s, %s and %s which are delivered with all WP installations.', 'all-in-one-wp-security-and-firewall'), 'readme.html', 'license.txt', 'wp-config-sample.php');
            echo '<p>'.$info_msg.'</p>'.'<p>'.__('By preventing access to these files you are hiding some key pieces of information (such as WordPress version info) from potential hackers.', 'all-in-one-wp-security-and-firewall').'</p>';
            ?>
        </div>

        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('Prevent Access to Default WP Files', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
        <?php
        //Display security info badge
        global $aiowps_feature_mgr;
        $aiowps_feature_mgr->output_feature_details_badge("block-wp-files-access");
        ?>
        <form action="" method="POST">
        <?php wp_nonce_field('aiowpsec-prevent-default-wp-file-access-nonce'); ?>            
        <table class="form-table">
            <tr valign="top">
                <th scope="row"><?php _e('Prevent Access to WP Default Install Files', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td>
                <input name="aiowps_prevent_default_wp_file_access" type="checkbox"<?php if($aio_wp_security->configs->get_value('aiowps_prevent_default_wp_file_access')=='1') echo ' checked="checked"'; ?> value="1"/>
                <span class="description"><?php _e('Check this if you want to prevent access to readme.html, license.txt and wp-config-sample.php.', 'all-in-one-wp-security-and-firewall'); ?></span>
                </td>
            </tr>            
        </table>
        <input type="submit" name="aiowps_save_wp_file_access_settings" value="<?php _e('Save Setting', 'all-in-one-wp-security-and-firewall')?>" class="button-primary" />
        </form>
        </div></div>
        <?php
    }

    function render_tab4()
    {
        global $aio_wp_security;
        
        if (isset($_POST['aiowps_system_log_file'])){
            if ($_POST['aiowps_system_log_file'] != NULL){
                $sys_log_file = esc_html($_POST['aiowps_system_log_file']);
                $aio_wp_security->configs->set_value('aiowps_system_log_file',$sys_log_file);
            }else{
                $sys_log_file = 'error_log';
                $aio_wp_security->configs->set_value('aiowps_system_log_file',$sys_log_file);
            }
            $aio_wp_security->configs->save_config();
        }else{
            $sys_log_file = $aio_wp_security->configs->get_value('aiowps_system_log_file');
        }
        
        ?>
        <h2><?php _e('System Logs', 'all-in-one-wp-security-and-firewall')?></h2>
        <div class="aio_blue_box">
            <?php
            echo '<p>'.__('Sometimes your hosting platform will produce error or warning logs in a file called "error_log".', 'all-in-one-wp-security-and-firewall').'
            <br />'.__('Depending on the nature and cause of the error or warning, your hosting server can create multiple instances of this file in numerous directory locations of your WordPress installation.', 'all-in-one-wp-security-and-firewall').'
            <br />'.__('By occassionally viewing the contents of these logs files you can keep informed of any underlying problems on your system which you might need to address.', 'all-in-one-wp-security-and-firewall').'
            </p>';
            ?>
        </div>

        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('View System Logs', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
            <p>Please click the button below to view the latest system logs:</p>
            <form action="" method="POST">
                <?php wp_nonce_field('aiowpsec-view-system-logs-nonce'); ?>
                <div><?php _e('Enter System Log File Name', 'all-in-one-wp-security-and-firewall')?>:
                <input type="text" size="25" name="aiowps_system_log_file" value="<?php echo esc_html($sys_log_file); ?>" />
                <span class="description"><?php _e('Enter your system log file name. (Defaults to error_log)', 'all-in-one-wp-security-and-firewall'); ?></span>
                </div>
                <div class="aio_spacer_15"></div>
                <input type="submit" name="aiowps_search_error_files" value="<?php _e('View Latest System Logs', 'all-in-one-wp-security-and-firewall'); ?>" class="button-primary search-error-files" />
                <span class="aiowps_loading_1">
                    <img src="<?php echo AIO_WP_SECURITY_URL.'/images/loading.gif'; ?>" alt="<?php __('Loading...', 'all-in-one-wp-security-and-firewall'); ?>" />
                </span>            
            </form>
        </div></div>
    <?php
        if (isset($_POST['aiowps_search_error_files']))
        {
            $nonce=$_REQUEST['_wpnonce'];
            if (!wp_verify_nonce($nonce, 'aiowpsec-view-system-logs-nonce'))
            {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed on view system log operation!",4);
                die("Nonce check failed on view system log operation!");
            }
            
            $logResults = AIOWPSecurity_Utility_File::recursive_file_search($sys_log_file, 0, ABSPATH);
            if (empty($logResults) || $logResults == NULL || $logResults == '' || $logResults === FALSE)
            {
                $this->show_msg_updated(__('No system logs were found!', 'all-in-one-wp-security-and-firewall'));
            }
            else 
            {
                foreach($logResults as $file)
                {
                    $this->display_system_logs_in_table($file);
                }
            }
        }
    }
    
    /*
     * Scans WP key core files and directory permissions and populates a wp wide_fat table
     * Displays a red background entry with a "Fix" button for permissions which are "777"
     * Displays a yellow background entry with a "Fix" button for permissions which are less secure than the recommended
     * Displays a green entry for permissions which are as secure or better than the recommended
     */
    function show_wp_filesystem_permission_status($name,$path,$recommended)
    {
        $fix = false;
        $configmod = AIOWPSecurity_Utility_File::get_file_permission($path);
        if ($configmod == "0777"){
            $trclass = "aio_table_row_red"; //Display a red background if permissions are set as least secure ("777")
            $fix = true;
        } 
        else if($configmod != $recommended)
        {
            //$res = $this->is_file_permission_secure($recommended, $configmod);
            $res = AIOWPSecurity_Utility_File::is_file_permission_secure($recommended, $configmod);
            if ($res)
            {
                $trclass = "aio_table_row_green"; //If the current permissions are even tighter than recommended then display a green row
                $fix = true;
            }
            else
            {
                $trclass = "aio_table_row_yellow"; //Display a yellow background if permissions are set to something different than recommended
                $fix = true;
            }
        } 
        else
        {
            $trclass = "aio_table_row_green";
        }
        echo "<tr class=".$trclass.">";
            echo '<td>' . $name . "</td>";
            echo '<td>'. $path ."</td>";
            echo '<td>' . $configmod . '</td>';
            echo '<td>' . $recommended . '</td>';
            if ($fix)
            {
                echo '<td>
                    <input type="submit" name="aiowps_fix_permissions" value="'.__('Set Recommended Permissions','all-in-one-wp-security-and-firewall').'" class="button-secondary" />
                    <input type="hidden" name="aiowps_permission_chg_file" value="'.$path.'"/>
                    <input type="hidden" name="aiowps_recommended_permissions" value="'.$recommended.'"/>                        
                    </td>';
            } else
            {
                echo '<td>'.__('No Action Required', 'all-in-one-wp-security-and-firewall').'</td>';
            }
        echo "</tr>";
    }
    
    
    
    function filesystem_menu_footer_code()
    {
        ?>
        <script type="text/javascript">
	/* <![CDATA[ */
	jQuery(document).ready(function($) {
            loading_span = $('.aiowps_loading_1');
            loading_span.hide(); //hide the spinner gif after page has successfully loaded
            $('.search-error-files').on("click",function(){
                loading_span.show();
            });
	});
	/* ]]> */
	</script>
         <?php
    }
    
    function display_system_logs_in_table($filepath)
    {
        global $aio_wp_security;
        //Get contents of the error_log file
        $error_file_contents = file($filepath);
        if (!$error_file_contents)
        {
            //TODO - error could not read file, display notice???
            $aio_wp_security->debug_logger->log_debug("AIOWPSecurity_Filesystem_Menu - Unable to read file: ".$filepath,4);
            
        }
        $last_50_entries = array_slice($error_file_contents, -50); //extract the last 50 entries
        ?>
        <table class="widefat file_permission_table">
            <thead>
                <tr>
                    <th><?php echo(sprintf(__('Showing latest entries of error_log file: %s', 'all-in-one-wp-security-and-firewall'),'<strong>'.$filepath.'</strong>')); ?></th>
                </tr>
            </thead>
            <tbody>
                <?php
                foreach ($last_50_entries as $entry)
                {
                    echo "<tr>";
                    echo '<td>' . $entry . "</td>";
                    echo "</tr>";                    
                }
                ?>
            </tbody>
        </table>
        <?php

    }
} //end class