<?php
class AIOWPSecurity_Backup
{
    var $last_backup_file_name;//Stores the name of the last backup file when execute_backup function is called
    var $last_backup_file_path;
    var $last_backup_file_dir_multisite;
    
    function __construct() 
    {
        add_action('aiowps_perform_scheduled_backup_tasks', array(&$this, 'aiowps_scheduled_backup_handler'));
        add_action('aiowps_perform_db_cleanup_tasks', array(&$this, 'aiowps_scheduled_db_cleanup_handler'));
    }
    
    /**
     * This function will perform a database backup
     */
    function execute_backup() 
    {
        global $wpdb, $aio_wp_security;
        $is_multi_site = false;
        
        @ini_set( 'auto_detect_line_endings', true );
        if (function_exists('is_multisite') && is_multisite()) 
        {
            //Let's get the current site's table prefix
            $site_pref = esc_sql($wpdb->prefix);
            $db_query = "SHOW TABLES LIKE '".$site_pref."%'";
            $tables = $wpdb->get_results( $db_query, ARRAY_N );
            $is_multi_site = true;
        }
        else
        {
            //get all of the tables
            $tables = $wpdb->get_results( 'SHOW TABLES', ARRAY_N );
            if(empty($tables)){
                $aio_wp_security->debug_logger->log_debug("execute_backup() - no tables found!",4);
                return FALSE;
            }
        }

        $return = '';

        //cycle through each table
        foreach($tables as $table) 
        {
            $result = $wpdb->get_results( 'SELECT * FROM `' . $table[0] . '`;', ARRAY_N );
            $num_fields = sizeof( $wpdb->get_results( 'DESCRIBE `' . $table[0] . '`;' ) );

            $return.= 'DROP TABLE IF EXISTS `' . $table[0] . '`;';
            $row2 = $wpdb->get_row( 'SHOW CREATE TABLE `' . $table[0] . '`;', ARRAY_N );
            if(empty($row2)){
                $aio_wp_security->debug_logger->log_debug("execute_backup() - get_row returned NULL for table: ".$table[0],4);
            }
            $return.= PHP_EOL . PHP_EOL . $row2[1] . ";" . PHP_EOL . PHP_EOL;

            foreach( $result as $row ) 
            {
                $return .= 'INSERT INTO `' . $table[0] . '` VALUES(';

                for( $j=0; $j < $num_fields; $j++ ) {

                    $row[$j] = addslashes( $row[$j] );
                    //$row[$j] = ereg_replace( PHP_EOL, "\n", $row[$j] ); //deprecated!
                    $row[$j] = preg_replace( "/".PHP_EOL."/", "\n", $row[$j] );

                    if ( isset( $row[$j] ) ) { 
                            $return .= '"' . $row[$j] . '"' ; 
                    } else { 
                            $return.= '""'; 
                    }

                    if ( $j < ( $num_fields - 1 ) ) { 
                            $return .= ','; 
                    }

                }
                $return .= ");" . PHP_EOL;
            }
            $return .= PHP_EOL . PHP_EOL;
        }
        $return .= PHP_EOL . PHP_EOL;

        //Check to see if the main "backups" directory exists - create it otherwise
        
        $aiowps_backup_dir = WP_CONTENT_DIR.'/'.AIO_WP_SECURITY_BACKUPS_DIR_NAME;
        $aiowps_backup_url = content_url().'/'.AIO_WP_SECURITY_BACKUPS_DIR_NAME;
        if (!AIOWPSecurity_Utility_File::create_dir($aiowps_backup_dir))
        {
            $aio_wp_security->debug_logger->log_debug("Creation of DB backup directory failed!",4);
            return false;
        }

        //Generate a random prefix for more secure filenames
        $random_suffix = AIOWPSecurity_Utility::generate_alpha_numeric_random_string(10);

        if ($is_multi_site)
        {
            global $current_blog;
            $blog_id = $current_blog->blog_id;
            //Get the current site name string for use later
            $site_name = get_bloginfo('name');

            $site_name = strtolower($site_name);
            
            //make alphaunermic
            $site_name = preg_replace("/[^a-z0-9_\s-]/", "", $site_name);
            
            //Cleanup multiple instances of dashes or whitespaces
            $site_name = preg_replace("/[\s-]+/", " ", $site_name);
            
            //Convert whitespaces and underscore to dash
            $site_name = preg_replace("/[\s_]/", "-", $site_name);

            $file = 'database-backup-site-name-' . $site_name . '-' . current_time( 'Ymd-His' ) . '-' . $random_suffix;

            //We will create a sub dir for the blog using its blog id
            $dirpath = $aiowps_backup_dir . '/blogid_' . $blog_id;

            //Create a subdirectory for this blog_id
            if (!AIOWPSecurity_Utility_File::create_dir($dirpath))
            {
                $aio_wp_security->debug_logger->log_debug("Creation failed of DB backup directory for the following multisite blog ID: ".$blog_id,4);
                return false;
            }
        }
        else
        {
            $dirpath = $aiowps_backup_dir;
            $file = 'database-backup-' . current_time( 'Ymd-His' ) . '-' . $random_suffix;
        }

        $handle = @fopen( $dirpath . '/' . $file . '.sql', 'w+' );

        $fw_res = @fwrite( $handle, $return );
        if (!$fw_res)
        {
            $aio_wp_security->debug_logger->log_debug("execute_backup() - Write to DB backup file failed",4); 
            return false;
        }
        @fclose( $handle );

        //zip the file
        if ( class_exists( 'ZipArchive' ) ) 
        {
            $zip = new ZipArchive();
            $archive = $zip->open($dirpath . '/' . $file . '.zip', ZipArchive::CREATE);
            $zip->addFile($dirpath . '/' . $file . '.sql', $file . '.sql' );
            $zip->close();

            //delete .sql and keep zip
            @unlink( $dirpath . '/' . $file . '.sql' );
            $fileext = '.zip';
        } else 
        {
            $fileext = '.sql';
        }
        $this->last_backup_file_name = $file . $fileext;//database-backup-YYYYMMDD-HHIISS-<random-string>.zip or database-backup-YYYYMMDD-HHIISS-<random-string>.sql
        $this->last_backup_file_path = $dirpath . '/' . $file . $fileext;
        if ($is_multi_site)
        {
            $this->last_backup_file_dir_multisite = $aiowps_backup_dir . '/blogid_' . $blog_id; 
        }
        
        $this->aiowps_send_backup_email(); //Send backup file via email if applicable
        $this->aiowps_delete_backup_files();
        return true;
    }
    
    function aiowps_send_backup_email()
    {
        global $aio_wp_security;
        if ( $aio_wp_security->configs->get_value('aiowps_send_backup_email_address') == '1' ) 
        {
            //Get the right email address.
            if ( is_email( $aio_wp_security->configs->get_value('aiowps_backup_email_address') ) ) 
            {
                    $toaddress = $aio_wp_security->configs->get_value('aiowps_backup_email_address');
            } else 
            {
                    $toaddress = get_site_option( 'admin_email' );
            }

            $to = $toaddress;
            $site_title = get_bloginfo( 'name' );
            $from_name = empty($site_title)?'WordPress':$site_title;
            
            $headers = 'From: ' . $from_name . ' <' . get_option('admin_email') . '>' . PHP_EOL;
            $subject = __( 'All In One WP Security - Site Database Backup', 'all-in-one-wp-security-and-firewall' ) . ' ' . date( 'l, F jS, Y \a\\t g:i a', current_time( 'timestamp' ) );
            $attachment = array( $this->last_backup_file_path );
            $message = __( 'Attached is your latest DB backup file for site URL', 'all-in-one-wp-security-and-firewall' ) . ' ' . get_option( 'siteurl' ) . __( ' generated on', 'all-in-one-wp-security-and-firewall' ) . ' ' . date( 'l, F jS, Y \a\\t g:i a', current_time( 'timestamp' ) );

            $sendMail = wp_mail( $to, $subject, $message, $headers, $attachment );
            if(FALSE === $sendMail){
                $aio_wp_security->debug_logger->log_debug("Backup notification email failed to send to ".$to,4);
            }
        }
    }
    
    function aiowps_delete_backup_files()
    {
        global $aio_wp_security;
        if ( $aio_wp_security->configs->get_value('aiowps_backup_files_stored') > 0 ) 
        {
            $path_parts = pathinfo($this->last_backup_file_path);
            $backups_path = $path_parts['dirname'];
            $files = AIOWPSecurity_Utility_File::scan_dir_sort_date( $backups_path );
            $count = 0;

            foreach ( $files as $file ) 
            {
                if ( strpos( $file, 'database-backup' ) !== false )
                {
                    if ( $count >= $aio_wp_security->configs->get_value('aiowps_backup_files_stored') ) 
                    {
                            @unlink( $backups_path . '/' . $file );
                    }
                    $count++;
                }

            }
        }
    }
    
    function aiowps_scheduled_backup_handler()
    {
        global $aio_wp_security;
        if($aio_wp_security->configs->get_value('aiowps_enable_automated_backups')=='1')
        {
            $aio_wp_security->debug_logger->log_debug_cron("DB Backup - Scheduled backup is enabled. Checking if a backup needs to be done now...");
            $current_time = strtotime(current_time('mysql'));
            $backup_frequency = $aio_wp_security->configs->get_value('aiowps_db_backup_frequency'); //Number of hours or days or months interval per backup
            $interval_setting = $aio_wp_security->configs->get_value('aiowps_db_backup_interval'); //Hours/Days/Months
            switch($interval_setting)
            {
                case '0':
                    $interval = 'hours';
                    break;
                case '1':
                    $interval = 'days';
                    break;
                case '2':
                    $interval = 'weeks';
                    break;
            }
            $last_backup_time = $aio_wp_security->configs->get_value('aiowps_last_backup_time');
            if ($last_backup_time != NULL)
            {
                $last_backup_time = strtotime($aio_wp_security->configs->get_value('aiowps_last_backup_time'));
                $next_backup_time = strtotime("+".abs($backup_frequency).$interval, $last_backup_time);
                if ($next_backup_time <= $current_time)
                {
                    //It's time to do a backup
                    $result = $this->execute_backup();
                    if ($result)
                    {
                        $aio_wp_security->configs->set_value('aiowps_last_backup_time', current_time('mysql'));
                        $aio_wp_security->configs->save_config();
                        $aio_wp_security->debug_logger->log_debug_cron("DB Backup - Scheduled backup was successfully completed.");
                    } 
                    else
                    {
                        $aio_wp_security->debug_logger->log_debug_cron("DB Backup - Scheduled backup operation failed!",4);
                    }
                }
            } 
            else
            {
                //Set the last backup time to now so it can trigger for the next scheduled period
                $aio_wp_security->configs->set_value('aiowps_last_backup_time', current_time('mysql'));
                $aio_wp_security->configs->save_config();
            }
        }
    }
    

    function aiowps_scheduled_db_cleanup_handler()
    {
        global $aio_wp_security;

        $aio_wp_security->debug_logger->log_debug_cron("DB Cleanup - checking if a cleanup needs to be done now...");
        //Check the events table because this can grow quite large especially when 404 events are being logged
        $events_table_name = AIOWPSEC_TBL_EVENTS;
        $max_rows_event_table = '5000'; //Keep a max of 5000 rows in the events table
        $max_rows_event_table = apply_filters( 'aiowps_max_rows_event_table', $max_rows_event_table );
        AIOWPSecurity_Utility::cleanup_table($events_table_name, $max_rows_event_table);

        //Check the failed logins table
        $failed_logins_table_name = AIOWPSEC_TBL_FAILED_LOGINS;
        $max_rows_failed_logins_table = '5000'; //Keep a max of 5000 rows in the events table
        $max_rows_failed_logins_table = apply_filters( 'aiowps_max_rows_failed_logins_table', $max_rows_failed_logins_table );
        AIOWPSecurity_Utility::cleanup_table($failed_logins_table_name, $max_rows_failed_logins_table);

        //Check the login activity table
        $login_activity_table_name = AIOWPSEC_TBL_USER_LOGIN_ACTIVITY;
        $max_rows_login_activity_table = '5000'; //Keep a max of 5000 rows in the events table
        $max_rows_login_activity_table = apply_filters( 'aiowps_max_rows_login_attempts_table', $max_rows_login_activity_table );
        AIOWPSecurity_Utility::cleanup_table($login_activity_table_name, $max_rows_login_activity_table);

        //Check the global meta table
        $global_meta_table_name = AIOWPSEC_TBL_GLOBAL_META_DATA;
        $max_rows_global_meta_table = '5000'; //Keep a max of 5000 rows in this table
        $max_rows_global_meta_table = apply_filters( 'aiowps_max_rows_global_meta_table', $max_rows_global_meta_table );
        AIOWPSecurity_Utility::cleanup_table($global_meta_table_name, $max_rows_global_meta_table);


        //Keep adding other DB cleanup tasks as they arise...
    }
}