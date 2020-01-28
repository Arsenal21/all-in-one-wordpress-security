<?php
if(!defined('ABSPATH')){
    exit;//Exit if accessed directly
}

class AIOWPSecurity_Filescan_Menu extends AIOWPSecurity_Admin_Menu
{
    var $menu_page_slug = AIOWPSEC_FILESCAN_MENU_SLUG;
    
    /* Specify all the tabs of this menu in the following array */
    var $menu_tabs;

    var $menu_tabs_handler = array(
        'tab1' => 'render_tab1',
        'tab2' => 'render_tab2',
        );
    
    function __construct() 
    {
        $this->render_menu_page();
    }
    
    function set_menu_tabs() 
    {
        $this->menu_tabs = array(
            'tab1' => __('File Change Detection','all-in-one-wp-security-and-firewall'),
            'tab2' => __('Malware Scan','all-in-one-wp-security-and-firewall'),
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
        echo '<h2>'.__('Scanner','all-in-one-wp-security-and-firewall').'</h2>';//Interface title
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
        if (isset($_POST['fcd_scan_info']))
        {
            //Display scan file change info and clear the global alert variable
            
            //Clear the global variable
            $aio_wp_security->configs->set_value('aiowps_fcds_change_detected', FALSE);
            $aio_wp_security->configs->save_config();
            
            //Display the last scan results
            $this->display_last_scan_results();
        }

        if (isset($_POST['aiowps_view_last_fcd_results']))
        {
            //Display the last scan results
            if (!$this->display_last_scan_results()){
                $this->show_msg_updated(__('There have been no file changes since the last scan.', 'all-in-one-wp-security-and-firewall'));
            }
        }

        if (isset($_POST['aiowps_manual_fcd_scan']))
        {
            $nonce=$_REQUEST['_wpnonce'];
            if (!wp_verify_nonce($nonce, 'aiowpsec-fcd-manual-scan-nonce'))
            {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed for manual file change detection scan operation!",4);
                die(__('Nonce check failed for manual file change detection scan operation!','all-in-one-wp-security-and-firewall'));
            }

            $result = $aio_wp_security->scan_obj->execute_file_change_detection_scan();
            if ($result === false) {
                // error case
                $this->show_msg_error(__('There was an error during the file change detection scan. Please check the aiowps logs.','all-in-one-wp-security-and-firewall'));
            }
            
            //If this is first scan display special message
            if ($result['initial_scan'] == 1)
            {
                $this->show_msg_updated(__('The plugin has detected that this is your first file change detection scan. The file details from this scan will be used to detect file changes for future scans.','all-in-one-wp-security-and-firewall'));
            }else if(!$aio_wp_security->configs->get_value('aiowps_fcds_change_detected')){
                $this->show_msg_updated(__('Scan Complete - There were no file changes detected!', 'all-in-one-wp-security-and-firewall'));
            }
        }

        if(isset($_POST['aiowps_schedule_fcd_scan']))//Do form submission tasks
        {
            $error = '';
            $reset_scan_data = FALSE;
            $file_types = '';
            $files = '';

            $nonce=$_REQUEST['_wpnonce'];
            if (!wp_verify_nonce($nonce, 'aiowpsec-scheduled-fcd-scan-nonce'))
            {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed for file change detection scan options save!",4);
                die("Nonce check failed for file change detection scan options save!");
            }

            $fcd_scan_frequency = sanitize_text_field($_POST['aiowps_fcd_scan_frequency']);
            if(!is_numeric($fcd_scan_frequency))
            {
                $error .= '<br />'.__('You entered a non numeric value for the "backup time interval" field. It has been set to the default value.','all-in-one-wp-security-and-firewall');
                $fcd_scan_frequency = '4';//Set it to the default value for this field
            }
            
            if (!empty($_POST['aiowps_fcd_exclude_filetypes']))
            {
                $file_types = trim($_POST['aiowps_fcd_exclude_filetypes']);
                //$file_types_array = preg_split( '/\r\n|\r|\n/', $file_types );

                //Get the currently saved config value and check if this has changed. If so do another scan to reset the scan data so it omits these filetypes
                if ($file_types != $aio_wp_security->configs->get_value('aiowps_fcd_exclude_filetypes'))
                {
                    $reset_scan_data = TRUE;
                }
            }
            
            if (!empty($_POST['aiowps_fcd_exclude_files']))
            {
                $files = trim($_POST['aiowps_fcd_exclude_files']);
                //Get the currently saved config value and check if this has changed. If so do another scan to reset the scan data so it omits these files/dirs
                if ($files != $aio_wp_security->configs->get_value('aiowps_fcd_exclude_files'))
                {
                    $reset_scan_data = TRUE;
                }

            }

            // Explode by end-of-line character, then trim and filter empty lines
            $email_list_array = array_filter(array_map('trim', explode(PHP_EOL, $_POST['aiowps_fcd_scan_email_address'])), 'strlen');
            $errors = array();
            foreach($email_list_array as $key=>$value){
                $email_sane = sanitize_email($value);
                if(!is_email($email_sane))
                {
                    $errors[] = __('The following address was removed because it is not a valid email address: ', 'all-in-one-wp-security-and-firewall')
                        . htmlspecialchars($value);
                    unset($email_list_array[$key]);
                }
            }
            $email_address = implode(PHP_EOL, $email_list_array);
            if ( !empty($errors) )
            {
                $this->show_msg_error(__('Attention!','all-in-one-wp-security-and-firewall') . '<br/>' . implode('<br />', $errors));
            }

            //Save all the form values to the options
            $aio_wp_security->configs->set_value('aiowps_enable_automated_fcd_scan',isset($_POST["aiowps_enable_automated_fcd_scan"])?'1':'');
            $aio_wp_security->configs->set_value('aiowps_fcd_scan_frequency',absint($fcd_scan_frequency));
            $aio_wp_security->configs->set_value('aiowps_fcd_scan_interval',$_POST["aiowps_fcd_scan_interval"]);
            $aio_wp_security->configs->set_value('aiowps_fcd_exclude_filetypes',$file_types);
            $aio_wp_security->configs->set_value('aiowps_fcd_exclude_files',$files);
            $aio_wp_security->configs->set_value('aiowps_send_fcd_scan_email',isset($_POST["aiowps_send_fcd_scan_email"])?'1':'');
            $aio_wp_security->configs->set_value('aiowps_fcd_scan_email_address',$email_address);
            $aio_wp_security->configs->save_config();

            //Recalculate points after the feature status/options have been altered
            $aiowps_feature_mgr->check_feature_status_and_recalculate_points();
            $this->show_msg_settings_updated();
            
            //Let's check if backup interval was set to less than 24 hours
            if (isset($_POST["aiowps_enable_automated_fcd_scan"]) && ($fcd_scan_frequency < 24) && $_POST["aiowps_fcd_scan_interval"]==0)
            {
                $alert_user_msg = 'ATTENTION: You have configured your file change detection scan to occur at least once daily. For most websites we recommended that you choose a less frequent
                    schedule such as once every few days, once a week or once a month. Choosing a less frequent schedule will also help reduce your server load.';
                $this->show_msg_updated(__($alert_user_msg, 'all-in-one-wp-security-and-firewall'));
            }
            
            if($reset_scan_data)
            {
                //Clear old scan row and ask user to perform a fresh scan to reset the data
                $aiowps_global_meta_tbl_name = AIOWPSEC_TBL_GLOBAL_META_DATA;
                $where = array('meta_key1' => 'file_change_detection', 'meta_value1' => 'file_scan_data');
                $wpdb->delete( $aiowps_global_meta_tbl_name, $where);
                $result = $aio_wp_security->scan_obj->execute_file_change_detection_scan();
                $new_scan_alert = __('NEW SCAN COMPLETED: The plugin has detected that you have made changes to the "File Types To Ignore" or "Files To Ignore" fields.
                    In order to ensure that future scan results are accurate, the old scan data has been refreshed.', 'all-in-one-wp-security-and-firewall');
                $this->show_msg_updated($new_scan_alert);
            }

        }
        
        //Display an alert warning message if a file change was detected
        if ($aio_wp_security->configs->get_value('aiowps_fcds_change_detected'))
        {
            $error_msg = __('All In One WP Security & Firewall has detected that there was a change in your host\'s files.', 'all-in-one-wp-security-and-firewall');
            
            $button = '<div><form action="" method="POST"><input type="submit" name="fcd_scan_info" value="'.__('View Scan Details & Clear This Message', 'all-in-one-wp-security-and-firewall').'" class="button-secondary" /></form></div>';
            $error_msg .= $button;
            $this->show_msg_error($error_msg);
        } 

        
        ?>
        <div class="aio_blue_box">
            <?php
            echo '<p>'.__('If given an opportunity hackers can insert their code or files into your system which they can then use to carry out malicious acts on your site.', 'all-in-one-wp-security-and-firewall').
            '<br />'.__('Being informed of any changes in your files can be a good way to quickly prevent a hacker from causing damage to your website.', 'all-in-one-wp-security-and-firewall').
            '<br />'.__('In general, WordPress core and plugin files and file types such as ".php" or ".js" should not change often and when they do, it is important that you are made aware when a change occurs and which file was affected.', 'all-in-one-wp-security-and-firewall').
            '<br />'.__('The "File Change Detection Feature" will notify you of any file change which occurs on your system, including the addition and deletion of files by performing a regular automated or manual scan of your system\'s files.', 'all-in-one-wp-security-and-firewall').
            '<br />'.__('This feature also allows you to exclude certain files or folders from the scan in cases where you know that they change often as part of their normal operation. (For example log files and certain caching plugin files may change often and hence you may choose to exclude such files from the file change detection scan)', 'all-in-one-wp-security-and-firewall').'</p>';
            ?>
        </div>

        <?php 
        if (!class_exists ( "FilesystemIterator" )){
        ?>
        <div class="aio_orange_box">
            <p>
            <?php
            $read_link = '<a href="https://secure.php.net/manual/en/class.filesystemiterator.php" target="_blank">the FilesystemIterator class</a>';
            echo sprintf(__('It appears that your server is using an old PHP version which is missing the %s. The file scanner feature needs this class in order to work. If you would like to use this feature please upgrade your server PHP version to 5.3 or greater.', 'all-in-one-wp-security-and-firewall'), $read_link);
            ?>
            </p>
        </div>            
        <?php
        } else {
        ?>
        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('Manual File Change Detection Scan', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
        <form action="" method="POST">
        <?php wp_nonce_field('aiowpsec-fcd-manual-scan-nonce'); ?>
        <table class="form-table">
            <tr valign="top">
            <span class="description"><?php _e('To perform a manual file change detection scan click on the button below.', 'all-in-one-wp-security-and-firewall'); ?></span>
            </tr>            
        </table>
        <input type="submit" name="aiowps_manual_fcd_scan" value="<?php _e('Perform Scan Now', 'all-in-one-wp-security-and-firewall')?>" class="button-primary" />
        </form>
        </div></div>
        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('View Last Saved File Change Results', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
        <form action="" method="POST">
        <?php wp_nonce_field('aiowpsec-view-last-fcd-results-nonce'); ?>
        <table class="form-table">
            <tr valign="top">
            <span class="description"><?php _e('Click the button below to view the saved file change results from the last scan.', 'all-in-one-wp-security-and-firewall'); ?></span>
            </tr>            
        </table>
        <input type="submit" name="aiowps_view_last_fcd_results" value="<?php _e('View Last File Change', 'all-in-one-wp-security-and-firewall')?>" class="button-primary" />
        </form>
        </div></div>
        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('File Change Detection Settings', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
        <?php
        //Display security info badge
        global $aiowps_feature_mgr;
        $aiowps_feature_mgr->output_feature_details_badge("scan-file-change-detection");
        ?>

        <form action="" method="POST">
        <?php wp_nonce_field('aiowpsec-scheduled-fcd-scan-nonce'); ?>
        <table class="form-table">
            <tr valign="top">
                <th scope="row"><?php _e('Enable Automated File Change Detection Scan', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td>
                <input name="aiowps_enable_automated_fcd_scan" type="checkbox"<?php if($aio_wp_security->configs->get_value('aiowps_enable_automated_fcd_scan')=='1') echo ' checked="checked"'; ?> value="1"/>
                <span class="description"><?php _e('Check this if you want the system to automatically/periodically scan your files to check for file changes based on the settings below', 'all-in-one-wp-security-and-firewall'); ?></span>
                </td>
            </tr>            
            <tr valign="top">
                <th scope="row"><?php _e('Scan Time Interval', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td><input type="text" size="5" name="aiowps_fcd_scan_frequency" value="<?php echo $aio_wp_security->configs->get_value('aiowps_fcd_scan_frequency'); ?>" />
                    <select id="backup_interval" name="aiowps_fcd_scan_interval">
                        <option value="0" <?php selected( $aio_wp_security->configs->get_value('aiowps_fcd_scan_interval'), '0' ); ?>><?php _e( 'Hours', 'all-in-one-wp-security-and-firewall' ); ?></option>
                        <option value="1" <?php selected( $aio_wp_security->configs->get_value('aiowps_fcd_scan_interval'), '1' ); ?>><?php _e( 'Days', 'all-in-one-wp-security-and-firewall' ); ?></option>
                        <option value="2" <?php selected( $aio_wp_security->configs->get_value('aiowps_fcd_scan_interval'), '2' ); ?>><?php _e( 'Weeks', 'all-in-one-wp-security-and-firewall' ); ?></option>
                    </select>
                <span class="description"><?php _e('Set the value for how often you would like a scan to occur', 'all-in-one-wp-security-and-firewall'); ?></span>
                </td> 
            </tr>
            <tr valign="top">
                <th scope="row"><?php _e('File Types To Ignore', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td><textarea name="aiowps_fcd_exclude_filetypes" rows="5" cols="50"><?php echo htmlspecialchars($aio_wp_security->configs->get_value('aiowps_fcd_exclude_filetypes')); ?></textarea>
                    <br />
                    <span class="description"><?php _e('Enter each file type or extension on a new line which you wish to exclude from the file change detection scan.', 'all-in-one-wp-security-and-firewall'); ?></span>
                    <span class="aiowps_more_info_anchor"><span class="aiowps_more_info_toggle_char">+</span><span class="aiowps_more_info_toggle_text"><?php _e('More Info', 'all-in-one-wp-security-and-firewall'); ?></span></span>
                    <div class="aiowps_more_info_body">
                            <?php 
                            echo '<p class="description">'.__('You can exclude file types from the scan which would not normally pose any security threat if they were changed. These can include things such as image files.', 'all-in-one-wp-security-and-firewall').'</p>';
                            echo '<p class="description">'.__('Example: If you want the scanner to ignore files of type jpg, png, and bmp, then you would enter the following:', 'all-in-one-wp-security-and-firewall').'</p>';
                            echo '<p class="description">'.__('jpg', 'all-in-one-wp-security-and-firewall').'</p>';
                            echo '<p class="description">'.__('png', 'all-in-one-wp-security-and-firewall').'</p>';
                            echo '<p class="description">'.__('bmp', 'all-in-one-wp-security-and-firewall').'</p>';
                            ?>
                    </div>
                </td> 
            </tr>
            <tr valign="top">
                <th scope="row"><?php _e('Files/Directories To Ignore', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td><textarea name="aiowps_fcd_exclude_files" rows="5" cols="50"><?php echo htmlspecialchars($aio_wp_security->configs->get_value('aiowps_fcd_exclude_files')); ?></textarea>
                    <br />
                    <span class="description"><?php _e('Enter each file or directory on a new line which you wish to exclude from the file change detection scan.', 'all-in-one-wp-security-and-firewall'); ?></span>
                    <span class="aiowps_more_info_anchor"><span class="aiowps_more_info_toggle_char">+</span><span class="aiowps_more_info_toggle_text"><?php _e('More Info', 'all-in-one-wp-security-and-firewall'); ?></span></span>
                    <div class="aiowps_more_info_body">
                            <?php 
                            echo '<p class="description">'.__('You can exclude specific files/directories from the scan which would not normally pose any security threat if they were changed. These can include things such as log files.', 'all-in-one-wp-security-and-firewall').'</p>';
                            echo '<p class="description">'.__('Example: If you want the scanner to ignore certain files in different directories or whole directories, then you would enter the following:', 'all-in-one-wp-security-and-firewall').'</p>';
                            echo '<p class="description">'.__('cache/config/master.php', 'all-in-one-wp-security-and-firewall').'</p>';
                            echo '<p class="description">'.__('somedirectory', 'all-in-one-wp-security-and-firewall').'</p>';
                            ?>
                    </div>
                </td> 
            </tr>
            <tr valign="top">
                <th scope="row"><?php _e('Send Email When Change Detected', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td>
                <input name="aiowps_send_fcd_scan_email" type="checkbox"<?php if($aio_wp_security->configs->get_value('aiowps_send_fcd_scan_email')=='1') echo ' checked="checked"'; ?> value="1"/>
                <span class="description"><?php _e('Check this if you want the system to email you if a file change was detected', 'all-in-one-wp-security-and-firewall'); ?></span>
                <br />
                    <textarea name="aiowps_fcd_scan_email_address" rows="5" cols="50"><?php echo htmlspecialchars($aio_wp_security->configs->get_value('aiowps_fcd_scan_email_address')); ?></textarea>
                    <br />
                    <span class="description"><?php _e('Enter one or more email addresses on a new line.', 'all-in-one-wp-security-and-firewall'); ?></span>
                </td>
            </tr>            
        </table>
        <input type="submit" name="aiowps_schedule_fcd_scan" value="<?php _e('Save Settings', 'all-in-one-wp-security-and-firewall')?>" class="button-primary" />
        </form>
        </div></div>
        
        <?php
        }
    }
    
    function render_tab2()
    {
        ?>
        <div class="aio_blue_box">
            <?php
            echo '<h2>'.__('What is Malware?', 'all-in-one-wp-security-and-firewall').'</h2>';
            echo '<p>'.__('The word Malware stands for Malicious Software. It can consist of things like trojan horses, adware, worms, spyware and any other undesirable code which a hacker will try to inject into your website.', 'all-in-one-wp-security-and-firewall').'</p>'.
            '<p>'.__('Often when malware code has been inserted into your site you will normally not notice anything out of the ordinary based on appearances, but it can have a dramatic effect on your site\'s search ranking.', 'all-in-one-wp-security-and-firewall').'</p>'.
            '<p>'.__('This is because the bots and spiders from search engines such as Google have the capability to detect malware when they are indexing the pages on your site, and consequently they can blacklist your website which will in turn affect your search rankings.', 'all-in-one-wp-security-and-firewall').'</p>';

            $site_scanners_link = '<a href="http://www.site-scanners.com" target="_blank">'.__('CLICK HERE', 'all-in-one-wp-security-and-firewall').'</a>';

            echo '<h2>'.__('Scanning For Malware', 'all-in-one-wp-security-and-firewall').'</h2>';
            echo '<p>'.__('Due to the constantly changing and complex nature of Malware, scanning for such things using a standalone plugin will not work reliably. This is something best done via an external scan of your site regularly.', 'all-in-one-wp-security-and-firewall').'</p>'.
            '<p>'.__('This is why we have created an easy-to-use scanning service which is hosted off our own server which will scan your site for malware once every day and notify you if it finds anything.', 'all-in-one-wp-security-and-firewall').'</p>';
            echo '<p>'.__('When you sign up for this service you will get the following:', 'all-in-one-wp-security-and-firewall').'</p>';
            echo '<ul class="aiowps_admin_ul_grp1">
                <li>'.__('Automatic Daily Scan of 1 Website','all-in-one-wp-security-and-firewall').'</li>
                <li>'.__('Automatic Malware & Blacklist Monitoring','all-in-one-wp-security-and-firewall').'</li>
                <li>'.__('Automatic Email Alerting','all-in-one-wp-security-and-firewall').'</li>
                <li>'.__('Site uptime monitoring','all-in-one-wp-security-and-firewall').'</li>
                <li>'.__('Site response time monitoring','all-in-one-wp-security-and-firewall').'</li>
                <li>'.__('We provide advice for malware cleanup','all-in-one-wp-security-and-firewall').'</li>
                <li>'.__('Blacklist Removal','all-in-one-wp-security-and-firewall').'</li>
                <li>'.__('No Contract (Cancel Anytime)','all-in-one-wp-security-and-firewall').'</li>
            </ul>';
            echo '<p>'.sprintf(__('To learn more please %s.', 'all-in-one-wp-security-and-firewall'), $site_scanners_link).'</p>';
            ?>
        </div>

        <?php
    }
    

    /*
     * Outputs the last scan results in a postbox
     */
    function display_last_scan_results()
    {
        $fcd_data = AIOWPSecurity_Scan::get_fcd_data();
        if (!$fcd_data || !isset($fcd_data['last_scan_result']))
        {
            // no fcd data found
            return false;
        }
        ?>
        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('Latest File Change Scan Results', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
        <?php
        $files_added_output = "";
        $files_removed_output = "";
        $files_changed_output = "";
        $last_scan_results = $fcd_data['last_scan_result'];
        if (!empty($last_scan_results['files_added']))
        {
            //Output table of files added
            echo '<div class="aio_info_with_icon aio_spacer_10_tb">'.__('The following files were added to your host.', 'all-in-one-wp-security-and-firewall').'</div>';
            $files_added_output .= '<table class="widefat">';
            $files_added_output .= '<tr>';
            $files_added_output .= '<th>'.__('File','all-in-one-wp-security-and-firewall').'</th>';
            $files_added_output .= '<th>'.__('File Size','all-in-one-wp-security-and-firewall').'</th>';
            $files_added_output .= '<th>'.__('File Modified','all-in-one-wp-security-and-firewall').'</th>';
            $files_added_output .= '</tr>';
            foreach ($last_scan_results['files_added'] as $key=>$value) {
                $files_added_output .= '<tr>';
                $files_added_output .= '<td>'.$key.'</td>';
                $files_added_output .= '<td>'.$value['filesize'].'</td>';
                $files_added_output .= '<td>'.date('Y-m-d H:i:s',$value['last_modified']).'</td>';
                $files_added_output .= '</tr>';
            }
            $files_added_output .= '</table>';
            echo $files_added_output;
        }
        echo '<div class="aio_spacer_15"></div>';
        if (!empty($last_scan_results['files_removed']))
        {
            //Output table of files removed
            echo '<div class="aio_info_with_icon aio_spacer_10_tb">'.__('The following files were removed from your host.', 'all-in-one-wp-security-and-firewall').'</div>';
            $files_removed_output .= '<table class="widefat">';
            $files_removed_output .= '<tr>';
            $files_removed_output .= '<th>'.__('File','all-in-one-wp-security-and-firewall').'</th>';
            $files_removed_output .= '<th>'.__('File Size','all-in-one-wp-security-and-firewall').'</th>';
            $files_removed_output .= '<th>'.__('File Modified','all-in-one-wp-security-and-firewall').'</th>';
            $files_removed_output .= '</tr>';
            foreach ($last_scan_results['files_removed'] as $key=>$value) {
                $files_removed_output .= '<tr>';
                $files_removed_output .= '<td>'.$key.'</td>';
                $files_removed_output .= '<td>'.$value['filesize'].'</td>';
                $files_removed_output .= '<td>'.date('Y-m-d H:i:s',$value['last_modified']).'</td>';
                $files_removed_output .= '</tr>';
            }
            $files_removed_output .= '</table>';
            echo $files_removed_output;
            
        }

        echo '<div class="aio_spacer_15"></div>';

        if (!empty($last_scan_results['files_changed']))
        {
            //Output table of files changed
            echo '<div class="aio_info_with_icon aio_spacer_10_tb">'.__('The following files were changed on your host.', 'all-in-one-wp-security-and-firewall').'</div>';
            $files_changed_output .= '<table class="widefat">';
            $files_changed_output .= '<tr>';
            $files_changed_output .= '<th>'.__('File','all-in-one-wp-security-and-firewall').'</th>';
            $files_changed_output .= '<th>'.__('File Size','all-in-one-wp-security-and-firewall').'</th>';
            $files_changed_output .= '<th>'.__('File Modified','all-in-one-wp-security-and-firewall').'</th>';
            $files_changed_output .= '</tr>';
            foreach ($last_scan_results['files_changed'] as $key=>$value) {
                $files_changed_output .= '<tr>';
                $files_changed_output .= '<td>'.$key.'</td>';
                $files_changed_output .= '<td>'.$value['filesize'].'</td>';
                $files_changed_output .= '<td>'.date('Y-m-d H:i:s',$value['last_modified']).'</td>';
                $files_changed_output .= '</tr>';
            }
            $files_changed_output .= '</table>';
            echo $files_changed_output;
        }
        
        ?>
        </div></div>
        <?php
    }    
} //end class