<?php
if(!defined('ABSPATH')){
    exit;//Exit if accessed directly
}

class AIOWPSecurity_Database_Menu extends AIOWPSecurity_Admin_Menu
{
    var $menu_page_slug = AIOWPSEC_DB_SEC_MENU_SLUG;
    
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
        if (AIOWPSecurity_Utility::is_multisite_install() && get_current_blog_id() != 1){
            //Suppress the DB prefix change tab if site is a multi site AND not the main site
            $this->menu_tabs = array(
            //'tab1' => __('DB Prefix', 'all-in-one-wp-security-and-firewall'),
            'tab2' => __('DB Backup', 'all-in-one-wp-security-and-firewall'),
            );
        }else{
            $this->menu_tabs = array(
            'tab1' => __('DB Prefix', 'all-in-one-wp-security-and-firewall'),
            'tab2' => __('DB Backup', 'all-in-one-wp-security-and-firewall'),
            );
        }
        
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
        echo '<h2>'.__('Database Security','all-in-one-wp-security-and-firewall').'</h2>';//Interface title
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
        $old_db_prefix = $wpdb->prefix;
        $new_db_prefix = '';
        $perform_db_change = false;
        
        if (isset($_POST['aiowps_db_prefix_change']))//Do form submission tasks
        {
            $nonce=$_REQUEST['_wpnonce'];
            if (!wp_verify_nonce($nonce, 'aiowpsec-db-prefix-change-nonce'))
            {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed for DB prefix change operation!",4);
                die(__('Nonce check failed for DB prefix change operation!','all-in-one-wp-security-and-firewall'));
            }
            
            //Let's first check if user's system allows writing to wp-config.php file. If plugin cannot write to wp-config we will not do the prefix change.
            $config_file = AIOWPSecurity_Utility_File::get_wp_config_file_path();
            $file_write = AIOWPSecurity_Utility_File::is_file_writable($config_file);
            if (!$file_write)
            {
                $this->show_msg_error(__('The plugin has detected that it cannot write to the wp-config.php file. This feature can only be used if the plugin can successfully write to the wp-config.php file.', 'all-in-one-wp-security-and-firewall'));
            }
            else
            {
                if( isset($_POST['aiowps_enable_random_prefix'])) 
                {//User has elected to generate a random DB prefix
                    $string = AIOWPSecurity_Utility::generate_alpha_random_string('5');
                    $new_db_prefix = $string . '_';
                    $perform_db_change = true;
                }else 
                {
                    if (empty($_POST['aiowps_new_manual_db_prefix']))
                    {
                        $this->show_msg_error(__('Please enter a value for the DB prefix.', 'all-in-one-wp-security-and-firewall'));
                    }
                    else
                    {
                        //User has chosen their own DB prefix value
                        $new_db_prefix = wp_strip_all_tags( trim( $_POST['aiowps_new_manual_db_prefix'] ) );
                        $error = $wpdb->set_prefix( $new_db_prefix ); //validate the user chosen prefix
                        if(is_wp_error($error))
                        {
                            wp_die( __('<strong>ERROR</strong>: The table prefix can only contain numbers, letters, and underscores.', 'all-in-one-wp-security-and-firewall') );
                        }
                        $wpdb->set_prefix( $old_db_prefix );
                        $perform_db_change = true;
                    }
                }
            }
        }
        ?>
        <h2><?php _e('Change Database Prefix', 'all-in-one-wp-security-and-firewall')?></h2>
        <div class="aio_blue_box">
            <?php
            echo '<p>'.__('Your WordPress DB is the most important asset of your website because it contains a lot of your site\'s precious information.', 'all-in-one-wp-security-and-firewall').'
            <br />'.__('The DB is also a target for hackers via methods such as SQL injections and malicious and automated code which targets certain tables.', 'all-in-one-wp-security-and-firewall').'
            <br />'.__('One way to add a layer of protection for your DB is to change the default WordPress table prefix from "wp_" to something else which will be difficult for hackers to guess.', 'all-in-one-wp-security-and-firewall').'
            <br />'.__('This feature allows you to easily change the prefix to a value of your choice or to a random value set by this plugin.', 'all-in-one-wp-security-and-firewall').'
            </p>';
            ?>
        </div>

        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('DB Prefix Options', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
        <?php
        //Display security info badge
        global $aiowps_feature_mgr;
        $aiowps_feature_mgr->output_feature_details_badge("db-security-db-prefix");
        ?>

        <div class="aio_red_box">
            <?php
            $backup_tab_link = '<a href="admin.php?page='.AIOWPSEC_DB_SEC_MENU_SLUG.'&tab=tab2">DB Backup</a>';
            $info_msg = '<p><strong>'.sprintf( __('It is recommended that you perform a %s before using this feature', 'all-in-one-wp-security-and-firewall'), $backup_tab_link).'</strong></p>';
            echo $info_msg;
            ?>
        </div>

        <form action="" method="POST">
        <?php wp_nonce_field('aiowpsec-db-prefix-change-nonce'); ?>
        <table class="form-table">
            <tr valign="top">
                <th scope="row"><?php _e('Current DB Table Prefix', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td>
                    <span class="aiowpsec_field_value"><strong><?php echo $wpdb->prefix; ?></strong></span>
                    <?php
                    //now let's display a warning notification if default prefix is used
                    if ($old_db_prefix == 'wp_') {
                        echo '&nbsp;&nbsp;&nbsp;<span class="aio_error_with_icon">'.__('Your site is currently using the default WordPress DB prefix value of "wp_". 
                            To increase your site\'s security you should consider changing the DB prefix value to another value.', 'all-in-one-wp-security-and-firewall').'</span>';
                    }
                    ?>                    
                </td> 
            </tr>
            <tr valign="top">
                <th scope="row"><?php _e('Generate New DB Table Prefix', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td>
                <input name="aiowps_enable_random_prefix" type="checkbox" <?php if($aio_wp_security->configs->get_value('aiowps_enable_random_prefix')=='1') echo ' checked="checked"'; ?> value="1"/>
                <span class="description"><?php _e('Check this if you want the plugin to generate a random 6 character string for the table prefix', 'all-in-one-wp-security-and-firewall'); ?></span>
                <br /><?php _e('OR', 'all-in-one-wp-security-and-firewall'); ?>
                <br /><input type="text" size="10" name="aiowps_new_manual_db_prefix" value="<?php //echo $aio_wp_security->configs->get_value('aiowps_new_manual_db_prefix'); ?>" />
                <span class="description"><?php _e('Choose your own DB prefix by specifying a string which contains letters and/or numbers and/or underscores. Example: xyz_', 'all-in-one-wp-security-and-firewall'); ?></span>
                </td>
            </tr>            
        </table>
        <input type="submit" name="aiowps_db_prefix_change" value="<?php _e('Change DB Prefix', 'all-in-one-wp-security-and-firewall')?>" class="button-primary" />
        </form>
        </div></div>
        <?php
        if ($perform_db_change)
        {
            //Do the DB prefix change operations
            $this->change_db_prefix($old_db_prefix,$new_db_prefix); 
        }
    }
    
    function render_tab2()
    {
        global $aio_wp_security;
        global $aiowps_feature_mgr;
        if (isset($_POST['aiowps_manual_db_backup']))
        {
            $nonce=$_REQUEST['_wpnonce'];
            if (!wp_verify_nonce($nonce, 'aiowpsec-db-manual-change-nonce'))
            {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed for manual DB backup operation!",4);
                die(__('Nonce check failed for manual DB backup operation!','all-in-one-wp-security-and-firewall'));
            }

            $result = $aio_wp_security->backup_obj->execute_backup();
            if ($result)
            {
                $backup_file_name = $aio_wp_security->backup_obj->last_backup_file_name;
                if (function_exists('is_multisite') && is_multisite()) 
                {
                    $aiowps_backup_file_path = $aio_wp_security->backup_obj->last_backup_file_dir_multisite . '/' . $backup_file_name;
                }
                else
                {
                    $aiowps_backup_dir = WP_CONTENT_DIR.'/'.AIO_WP_SECURITY_BACKUPS_DIR_NAME;
                    $aiowps_backup_file_path = $aiowps_backup_dir. '/' . $backup_file_name;
                }
                echo '<div id="message" class="updated fade"><p>';
                _e('DB Backup was successfully completed! You will receive the backup file via email if you have enabled "Send Backup File Via Email", otherwise you can retrieve it via FTP from the following directory:','all-in-one-wp-security-and-firewall');
                echo '</p><p>';
                _e('Your DB Backup File location: ');
                echo '<strong>'.$aiowps_backup_file_path.'</strong>';
                echo '</p></div>';
            } 
            else
            {
                $aio_wp_security->debug_logger->log_debug("DB Backup - Backup operation failed!",4);
                $this->show_msg_error(__('DB Backup failed. Please check the permissions of the backup directory.','all-in-one-wp-security-and-firewall'));
            }
        }

        if(isset($_POST['aiowps_schedule_backups']))//Do form submission tasks
        {
            $error = '';
            $nonce=$_REQUEST['_wpnonce'];
            if (!wp_verify_nonce($nonce, 'aiowpsec-scheduled-backup-nonce'))
            {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed on scheduled DB backup options save!",4);
                die("Nonce check failed on scheduled DB backup options save!");
            }

            $backup_frequency = sanitize_text_field($_POST['aiowps_db_backup_frequency']);
            if(!is_numeric($backup_frequency))
            {
                $error .= '<br />'.__('You entered a non numeric value for the "backup time interval" field. It has been set to the default value.','all-in-one-wp-security-and-firewall');
                $backup_frequency = '4';//Set it to the default value for this field
            }
            
            $files_to_keep = sanitize_text_field($_POST['aiowps_backup_files_stored']);
            if(!is_numeric($files_to_keep))
            {
                $error .= '<br />'.__('You entered a non numeric value for the "number of backup files to keep" field. It has been set to the default value.','all-in-one-wp-security-and-firewall');
                $files_to_keep = '2';//Set it to the default value for this field
            }

            $email_address = sanitize_email($_POST['aiowps_backup_email_address']);
            if(!is_email($email_address))
            {
                $error .= '<br />'.__('You have entered an incorrect email address format. It has been set to your WordPress admin email as default.','all-in-one-wp-security-and-firewall');
                $email_address = get_bloginfo('admin_email'); //Set the default value to the blog admin email
            }

            if($error)
            {
                $this->show_msg_error(__('Attention!','all-in-one-wp-security-and-firewall').$error);
            }

            //Save all the form values to the options
            $aio_wp_security->configs->set_value('aiowps_enable_automated_backups',isset($_POST["aiowps_enable_automated_backups"])?'1':'');
            $aio_wp_security->configs->set_value('aiowps_db_backup_frequency',absint($backup_frequency));
            $aio_wp_security->configs->set_value('aiowps_db_backup_interval',$_POST["aiowps_db_backup_interval"]);
            $aio_wp_security->configs->set_value('aiowps_backup_files_stored',absint($files_to_keep));
            $aio_wp_security->configs->set_value('aiowps_send_backup_email_address',isset($_POST["aiowps_send_backup_email_address"])?'1':'');
            $aio_wp_security->configs->set_value('aiowps_backup_email_address',$email_address);
            $aio_wp_security->configs->save_config();
            
            //Recalculate points after the feature status/options have been altered
            $aiowps_feature_mgr->check_feature_status_and_recalculate_points();
            $this->show_msg_settings_updated();
            
            //Let's check if backup interval was set to less than 24 hours
            if (isset($_POST["aiowps_enable_automated_backups"]) && ($backup_frequency < 24) && $_POST["aiowps_db_backup_interval"]==0)
            {
                $alert_user_msg = 'ATTENTION: You have configured your backups to occur at least once daily. For most websites we recommended that you choose a less frequent backup
                    schedule such as once every few days, once a week or once a month. Choosing a less frequent schedule will also help reduce your server load.';
                $this->show_msg_updated_st(__($alert_user_msg, 'all-in-one-wp-security-and-firewall'));
            }
        }
        
        ?>
        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('Manual Backup', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
        <form action="" method="POST">
        <?php wp_nonce_field('aiowpsec-db-manual-change-nonce'); ?>
        <p>
            <span class="description"><?php _e('To create a new DB backup just click on the button below.', 'all-in-one-wp-security-and-firewall'); ?></span>
        </p>
        <input type="submit" name="aiowps_manual_db_backup" value="<?php _e('Create DB Backup Now', 'all-in-one-wp-security-and-firewall')?>" class="button-primary" />
        </form>
        </div></div>
        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('Automated Scheduled Backups', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
        <?php
        //Display security info badge
        global $aiowps_feature_mgr;
        $aiowps_feature_mgr->output_feature_details_badge("db-security-db-backup");
        ?>

        <form action="" method="POST">
        <?php wp_nonce_field('aiowpsec-scheduled-backup-nonce'); ?>
        <table class="form-table">
            <tr valign="top">
                <th scope="row"><?php _e('Enable Automated Scheduled Backups', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td>
                <input name="aiowps_enable_automated_backups" type="checkbox"<?php if($aio_wp_security->configs->get_value('aiowps_enable_automated_backups')=='1') echo ' checked="checked"'; ?> value="1"/>
                <span class="description"><?php _e('Check this if you want the system to automatically generate backups periodically based on the settings below', 'all-in-one-wp-security-and-firewall'); ?></span>
                </td>
            </tr>            
            <tr valign="top">
                <th scope="row"><?php _e('Backup Time Interval', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td><input type="text" size="5" name="aiowps_db_backup_frequency" value="<?php echo $aio_wp_security->configs->get_value('aiowps_db_backup_frequency'); ?>" />
                    <select id="backup_interval" name="aiowps_db_backup_interval">
                        <option value="0" <?php selected( $aio_wp_security->configs->get_value('aiowps_db_backup_interval'), '0' ); ?>><?php _e( 'Hours', 'all-in-one-wp-security-and-firewall' ); ?></option>
                        <option value="1" <?php selected( $aio_wp_security->configs->get_value('aiowps_db_backup_interval'), '1' ); ?>><?php _e( 'Days', 'all-in-one-wp-security-and-firewall' ); ?></option>
                        <option value="2" <?php selected( $aio_wp_security->configs->get_value('aiowps_db_backup_interval'), '2' ); ?>><?php _e( 'Weeks', 'all-in-one-wp-security-and-firewall' ); ?></option>
                    </select>
                <span class="description"><?php _e('Set the value for how often you would like an automated backup to occur', 'all-in-one-wp-security-and-firewall'); ?></span>
                </td> 
            </tr>
            <tr valign="top">
                <th scope="row"><?php _e('Number of Backup Files To Keep', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td><input type="text" size="5" name="aiowps_backup_files_stored" value="<?php echo $aio_wp_security->configs->get_value('aiowps_backup_files_stored'); ?>" />
                <span class="description"><?php _e('Thie field allows you to choose the number of backup files you would like to keep in the backup directory', 'all-in-one-wp-security-and-firewall'); ?></span>
                </td> 
            </tr>
            <tr valign="top">
                <th scope="row"><?php _e('Send Backup File Via Email', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td>
                <input name="aiowps_send_backup_email_address" type="checkbox"<?php if($aio_wp_security->configs->get_value('aiowps_send_backup_email_address')=='1') echo ' checked="checked"'; ?> value="1"/>
                <span class="description"><?php _e('Check this if you want the system to email you the backup file after a DB backup has been performed', 'all-in-one-wp-security-and-firewall'); ?></span>
                <br /><input type="text" size="30" name="aiowps_backup_email_address" value="<?php echo $aio_wp_security->configs->get_value('aiowps_backup_email_address'); ?>" />
                <span class="description"><?php _e('Enter an email address', 'all-in-one-wp-security-and-firewall'); ?></span>
                </td>
            </tr>            
        </table>
        <input type="submit" name="aiowps_schedule_backups" value="<?php _e('Save Settings', 'all-in-one-wp-security-and-firewall')?>" class="button-primary" />
        </form>
        </div></div>
        
        <?php
    }
    
    /*
     * Changes the DB prefix
     */
    function change_db_prefix($table_old_prefix, $table_new_prefix)
    {
        global $wpdb, $aio_wp_security;
        $old_prefix_length = strlen( $table_old_prefix );
        $error = 0;

        //Config file path
        $config_file = AIOWPSecurity_Utility_File::get_wp_config_file_path();

        //Get the table resource
        //$result = mysql_list_tables(DB_NAME);
        $result = $this->get_mysql_tables(DB_NAME); //Fix for deprecated php mysql_list_tables function

        //Count the number of tables
        if (is_array($result) && count($result) > 0){
            $num_rows = count($result);
        }else{
            echo '<div class="aio_red_box"><p>'.__('Error - Could not get tables or no tables found!', 'all-in-one-wp-security-and-firewall').'</p></div>';
            return;
        }
        $table_count = 0;
        $info_msg_string = '<p class="aio_info_with_icon">'.__('Starting DB prefix change operations.....', 'all-in-one-wp-security-and-firewall').'</p>';
        
        $info_msg_string .= '<p class="aio_info_with_icon">'.sprintf( __('Your WordPress system has a total of %s tables and your new DB prefix will be: %s', 'all-in-one-wp-security-and-firewall'), '<strong>'.$num_rows.'</strong>', '<strong>'.$table_new_prefix.'</strong>').'</p>';
        echo ($info_msg_string);

        //Do a back of the config file
        if(!AIOWPSecurity_Utility_File::backup_and_rename_wp_config($config_file))
        {
            echo '<div class="aio_red_box"><p>'.__('Failed to make a backup of the wp-config.php file. This operation will not go ahead.', 'all-in-one-wp-security-and-firewall').'</p></div>';
            return;
        }
        else{
            echo '<p class="aio_success_with_icon">'.__('A backup copy of your wp-config.php file was created successfully!', 'all-in-one-wp-security-and-firewall').'</p>';
        }
        
        //Get multisite blog_ids if applicable
        if (AIOWPSecurity_Utility::is_multisite_install()) {
            $blog_ids = AIOWPSecurity_Utility::get_blog_ids();
        }

        //Rename all the table names
        foreach ($result as $db_table)
        {
            //Get table name with old prefix
            $table_old_name = $db_table; 

            if ( strpos( $table_old_name, $table_old_prefix ) === 0 ) 
            {
                //Get table name with new prefix
                $table_new_name = $table_new_prefix . substr( $table_old_name, $old_prefix_length );
                
                //Write query to rename tables name
                $sql = "RENAME TABLE `".$table_old_name."` TO `".$table_new_name."`";
                //$sql = "RENAME TABLE %s TO %s";

                //Execute the query
                if ( false === $wpdb->query($sql) )
                {
                    $error = 1;
                    echo '<p class="aio_error_with_icon">'.sprintf( __('%s table name update failed', 'all-in-one-wp-security-and-firewall'), '<strong>'.$table_old_name.'</strong>').'</p>';
                    $aio_wp_security->debug_logger->log_debug("DB Security Feature - Unable to change prefix of table ".$table_old_name,4);
                } else {
                    $table_count++;
                }
            } else
            {
                continue;
            }
        }
        if ( $error == 1 )
        {
            echo '<p class="aio_error_with_icon">'.sprintf( __('Please change the prefix manually for the above tables to: %s', 'all-in-one-wp-security-and-firewall'), '<strong>'.$table_new_prefix.'</strong>').'</p>';
        } else 
        {
            echo '<p class="aio_success_with_icon">'.sprintf( __('%s tables had their prefix updated successfully!', 'all-in-one-wp-security-and-firewall'), '<strong>'.$table_count.'</strong>').'</p>';
        }

        //Let's check for mysql tables of type "view"
        $this->alter_table_views($table_old_prefix, $table_new_prefix);

        //Get wp-config.php file contents and modify it with new info
        $config_contents = file($config_file);
        $prefix_match_string = '$table_prefix='; //this is our search string for the wp-config.php file
	foreach ($config_contents as $line_num => $line) {
            $no_ws_line = preg_replace( '/\s+/', '', $line ); //Strip white spaces
            if(strpos($no_ws_line, $prefix_match_string) !== FALSE){
                $config_contents[$line_num] = str_replace($table_old_prefix, $table_new_prefix, $line);
                break;
            }
	}
        //Now let's modify the wp-config.php file
        if (AIOWPSecurity_Utility_File::write_content_to_file($config_file, $config_contents))
        {
            echo '<p class="aio_success_with_icon">'. __('wp-config.php file was updated successfully!', 'all-in-one-wp-security-and-firewall').'</p>';
        }else
        {
            echo '<p class="aio_error_with_icon">'.sprintf( __('The "wp-config.php" file was not able to be modified. Please modify this file manually using your favourite editor and search 
                    for variable "$table_prefix" and assign the following value to that variable: %s', 'all-in-one-wp-security-and-firewall'), '<strong>'.$table_new_prefix.'</strong>').'</p>';
            $aio_wp_security->debug_logger->log_debug("DB Security Feature - Unable to modify wp-config.php",4);
        }
        
        //Now let's update the options table
        $update_option_table_query = $wpdb->prepare("UPDATE " . $table_new_prefix . "options
                                                                  SET option_name = '".$table_new_prefix ."user_roles' 
                                                                  WHERE option_name = %s LIMIT 1", $table_old_prefix."user_roles");

        if ( false === $wpdb->query($update_option_table_query) ) 
        {
            echo '<p class="aio_error_with_icon">'.sprintf( __('Update of table %s failed: unable to change %s to %s', 'all-in-one-wp-security-and-firewall'),$table_new_prefix.'options', $table_old_prefix.'user_roles', $table_new_prefix.'user_roles').'</p>';
            $aio_wp_security->debug_logger->log_debug("DB Security Feature - Error when updating the options table",4);//Log the highly unlikely event of DB error
        } else 
        {
            echo '<p class="aio_success_with_icon">'.sprintf( __('The options table records which had references to the old DB prefix were updated successfully!', 'all-in-one-wp-security-and-firewall')).'</p>';
        }

        //Now let's update the options tables for the multisite subsites if applicable
        if (AIOWPSecurity_Utility::is_multisite_install()) {
            if(!empty($blog_ids)){
                foreach ($blog_ids as $blog_id) {
                    if ($blog_id == 1){continue;} //skip main site
                    $new_pref_and_site_id = $table_new_prefix.$blog_id.'_';
                    $old_pref_and_site_id = $table_old_prefix.$blog_id.'_';
                    $update_ms_option_table_query = $wpdb->prepare("UPDATE " . $new_pref_and_site_id . "options
                                                                            SET option_name = '".$new_pref_and_site_id."user_roles'
                                                                            WHERE option_name = %s LIMIT 1", $old_pref_and_site_id."user_roles");
                    if ( false === $wpdb->query($update_ms_option_table_query) ) 
                    {
                        echo '<p class="aio_error_with_icon">'.sprintf( __('Update of table %s failed: unable to change %s to %s', 'all-in-one-wp-security-and-firewall'),$new_pref_and_site_id.'options', $old_pref_and_site_id.'user_roles', $new_pref_and_site_id.'user_roles').'</p>';
                        $aio_wp_security->debug_logger->log_debug("DB change prefix feature - Error when updating the subsite options table: ".$new_pref_and_site_id.'options',4);//Log the highly unlikely event of DB error
                    } else 
                    {
                        echo '<p class="aio_success_with_icon">'.sprintf( __('The %s table records which had references to the old DB prefix were updated successfully!', 'all-in-one-wp-security-and-firewall'),$new_pref_and_site_id.'options').'</p>';
                    }
                }

            }
        }
        
        //Now let's update the user meta table
        $custom_sql = "SELECT user_id, meta_key 
                        FROM " . $table_new_prefix . "usermeta 
                        WHERE meta_key 
                        LIKE '" . $table_old_prefix . "%'";
		
        $meta_keys = $wpdb->get_results( $custom_sql );

        $error_update_usermeta = '';

        //Update all meta_key field values which have the old table prefix in user_meta table
        foreach ($meta_keys as $meta_key ) {
            //Create new meta key
            $new_meta_key = $table_new_prefix . substr( $meta_key->meta_key, $old_prefix_length );

            $update_user_meta_sql = $wpdb->prepare("UPDATE " . $table_new_prefix . "usermeta
                                                            SET meta_key='" . $new_meta_key . "' 
                                                            WHERE meta_key=%s AND user_id=%s", $meta_key->meta_key, $meta_key->user_id);

            if (false === $wpdb->query($update_user_meta_sql))
            {
                $error_update_usermeta .= '<p class="aio_error_with_icon">'.sprintf( __('Error updating user_meta table where new meta_key = %s, old meta_key = %s and user_id = %s.', 'all-in-one-wp-security-and-firewall'),$new_meta_key,$meta_key->meta_key,$meta_key->user_id).'</p>';
                echo $error_update_usermeta;
                $aio_wp_security->debug_logger->log_debug("DB Security Feature - Error updating user_meta table where new meta_key = ".$new_meta_key." old meta_key = ".$meta_key->meta_key." and user_id = ".$meta_key->user_id,4);//Log the highly unlikely event of DB error
            }
        }
        echo '<p class="aio_success_with_icon">'.__('The usermeta table records which had references to the old DB prefix were updated successfully!', 'all-in-one-wp-security-and-firewall').'</p>';
        //Display tasks finished message
        $tasks_finished_msg_string = '<p class="aio_info_with_icon">'. __('DB prefix change tasks have been completed.', 'all-in-one-wp-security-and-firewall').'</p>';
        echo ($tasks_finished_msg_string);
    } 
    
    /**
    * This is an alternative to the deprecated "mysql_list_tables"
    * Returns an array of table names
    */
    function get_mysql_tables($database='')
    {
        global $aio_wp_security;
        $tables = array();
        $list_tables_sql = "SHOW TABLES FROM `{$database}`;";
        $mysqli = new mysqli(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME);
        
        if ($mysqli->connect_errno) {
            $aio_wp_security->debug_logger->log_debug("AIOWPSecurity_Database_Menu->get_mysql_tables() - DB connection error.",4);
            return false;
        }
        
        if ($result = $mysqli->query($list_tables_sql, MYSQLI_USE_RESULT)) {
            //Alternative way to get the tables
            while ($row = $result->fetch_assoc()) {
                foreach( $row  AS $value ) {
                    $tables[] = $value;
                }
            }            
            $result->close();
        }
        $mysqli->close();        
        return $tables;
    }
    
    /**
     * Will modify existing table view definitions to reflect the new DB prefix change
     * 
     * @param type $old_prefix
     * @param type $new_prefix
     */
    function alter_table_views($old_db_prefix, $new_db_prefix)
    {
        global $wpdb;
        $table_count = 0;
        $info_msg_string = '<p class="aio_info_with_icon">'.__('Checking for MySQL tables of type "view".....', 'all-in-one-wp-security-and-firewall').'</p>';
        echo ($info_msg_string);
        
        //get tables which are views
        $query = "SELECT * FROM INFORMATION_SCHEMA.VIEWS";
        $res = $wpdb->get_results($query);
        if(empty($res)) return;
        $view_count = 0;
        foreach ($res as $item){
            $old_def = $item->VIEW_DEFINITION;
            $new_def = str_replace($old_db_prefix, $new_db_prefix, $old_def);
            $new_def_no_bt = str_replace("`", "", $new_def); //remove any backticks because these will cause the "ALTER" command used later to fail

            $view_name = $item->TABLE_NAME;
            $chg_view_sql = "ALTER VIEW $view_name AS $new_def_no_bt"; //Note: cannot use $wpdb->prepare because it adds single quotes which cause the ALTER query to fail
            $view_res = $wpdb->query($chg_view_sql);
            if($view_res === false){
                echo '<p class="aio_error_with_icon">'.sprintf( __('Update of the following MySQL view definition failed: %s', 'all-in-one-wp-security-and-firewall'),$old_def).'</p>';
                $aio_wp_security->debug_logger->log_debug("Update of the following MySQL view definition failed: ".$old_def,4);//Log the highly unlikely event of DB error
            }else{
                $view_count++;
            }
        }
        if($view_count > 0){
            echo '<p class="aio_success_with_icon">'.sprintf( __('%s view definitions were updated successfully!', 'all-in-one-wp-security-and-firewall'), '<strong>'.$view_count.'</strong>').'</p>';
        }
        
        return;
    }
    
} //end class