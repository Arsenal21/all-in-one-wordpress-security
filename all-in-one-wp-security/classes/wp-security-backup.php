<?php
if(!defined('ABSPATH')){
    exit;//Exit if accessed directly
}

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
     * Add slashes, sanitize end-of-line characters (?), wrap $value in quotation marks.
     * @param string $value
     * @return string
     */
    function sanitize_db_field($value) {
        return '"' . preg_replace( "/".PHP_EOL."/", "\n", addslashes($value) ) . '"';
    }

    /**
     * Write sql dump of $tables to backup file identified by $handle.
     * @global wpdb $wpdb WordPress database abstraction object.
     * @global AIO_WP_Security $aio_wp_security
     * @param resource $handle
     * @param array $tables
     * @return boolean True, if database tables dump have been successfully written to the backup file, false otherwise.
     */
    function write_db_backup_file($handle, $tables)
    {
        global $wpdb, $aio_wp_security;

        $preamble
            = "-- All In One WP Security & Firewall {$aio_wp_security->version}" . PHP_EOL
            . '-- MySQL dump' . PHP_EOL
            . '-- ' . date('Y-m-d H:i:s') . PHP_EOL . PHP_EOL
            // When importing the backup, tell database server that our data is in UTF-8...
            . "SET NAMES utf8;" . PHP_EOL
            // ...and that foreign key checks should be ignored.
            . "SET foreign_key_checks = 0;" . PHP_EOL . PHP_EOL
        ;
        if ( !@fwrite( $handle, $preamble ) ) { return false; }

        // Loop through each table
        foreach ( $tables as $table )
        {
            $table_name = $table[0];

            $result_create_table = $wpdb->get_row( 'SHOW CREATE TABLE `' . $table_name . '`;', ARRAY_N );
            if ( empty($result_create_table) ) {
                $aio_wp_security->debug_logger->log_debug(__METHOD__ . " - get_row returned NULL for table: ".$table_name, 4);
                return false; // Avoid incomplete backups
            }

            // Drop/create table preamble
            $drop_and_create = 'DROP TABLE IF EXISTS `' . $table_name . '`;' . PHP_EOL . PHP_EOL
                . $result_create_table[1] . ";" . PHP_EOL . PHP_EOL
            ;
            if ( !@fwrite( $handle, $drop_and_create ) ) { return false; }

            // Dump table contents
            // Fetch results as row of objects to spare memory.
            $result = $wpdb->get_results( 'SELECT * FROM `' . $table_name . '`;', OBJECT );
            foreach ( $result as $object_row )
            {
                // Convert object row to array row: this is what $wpdb->get_results()
                // internally does when invoked with ARRAY_N param, but in the process
                // it creates new copy of entire results array that eats a lot of memory.
                $row = array_values(get_object_vars($object_row));
                // Start INSERT statement
                if ( !@fwrite( $handle, 'INSERT INTO `' . $table_name . '` VALUES(' ) ) { return false; }
                // Loop through all fields and echo them out
                foreach ( $row as $idx => $field ) {
                    // Echo fields separator (except for first loop)
                    if ( ($idx > 0) && !@fwrite( $handle, ',' ) ) { return false; }
                    // Echo field content (sanitized)
                    if ( !@fwrite( $handle, $this->sanitize_db_field($field) ) ) { return false; }
                }
                // Finish INSERT statement
                if ( !@fwrite( $handle, ");" . PHP_EOL ) ) { return false; }
            }
            // Place two-empty lines after table data
            if ( !@fwrite( $handle, PHP_EOL . PHP_EOL ) ) { return false; }
        }

        return true;
    }

    /**
     * This function will perform a database backup
     */
    function execute_backup() 
    {
        global $wpdb, $aio_wp_security;
        $is_multi_site = function_exists('is_multisite') && is_multisite();

        @ini_set( 'auto_detect_line_endings', true );
        @ini_set( 'memory_limit', '512M' );
        if ( $is_multi_site )
        {
            //Let's get the current site's table prefix
            $site_pref = esc_sql($wpdb->prefix);
            $db_query = "SHOW TABLES LIKE '".$site_pref."%'";
            $tables = $wpdb->get_results( $db_query, ARRAY_N );
        }
        else
        {
            //get all of the tables
            $tables = $wpdb->get_results( 'SHOW TABLES', ARRAY_N );
        }

        if ( empty($tables) ) {
            $aio_wp_security->debug_logger->log_debug(__METHOD__ . " - no tables found!",4);
            return false;
        }

        //Check to see if the main "backups" directory exists - create it otherwise
        
        $aiowps_backup_dir = WP_CONTENT_DIR.'/'.AIO_WP_SECURITY_BACKUPS_DIR_NAME;
        if (!AIOWPSecurity_Utility_File::create_dir($aiowps_backup_dir))
        {
            $aio_wp_security->debug_logger->log_debug(__METHOD__ . " - Creation of DB backup directory failed!",4);
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
            
            //make alphanumeric
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

        if ( $handle === false ) {
            $aio_wp_security->debug_logger->log_debug("Cannot create DB backup file: {$dirpath}/{$file}.sql", 4);
            return false;
        }

        // Delete old backup files now to avoid polluting backups directory
        // with incomplete backups on websites where max execution time is too
        // low for database content to be written to a file:
        // https://github.com/Arsenal21/all-in-one-wordpress-security/issues/62
        $this->aiowps_delete_backup_files($dirpath);

        $fw_res = $this->write_db_backup_file($handle, $tables);
        @fclose( $handle );

        if (!$fw_res)
        {
            @unlink( $dirpath . '/' . $file . '.sql' );
            $aio_wp_security->debug_logger->log_debug(__METHOD__ . " - Write to DB backup file failed",4);
            return false;
        }

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

    function aiowps_delete_backup_files($backups_dir)
    {
        global $aio_wp_security;
        $files_to_keep = absint($aio_wp_security->configs->get_value('aiowps_backup_files_stored'));
        if ( $files_to_keep > 0 )
        {
            $aio_wp_security->debug_logger->log_debug(sprintf('DB Backup - Deleting all but %d latest backup file(s) in %s directory.', $files_to_keep, $backups_dir));
            $files = AIOWPSecurity_Utility_File::scan_dir_sort_date( $backups_dir );
            $count = 0;

            foreach ( $files as $file )
            {
                if ( strpos( $file, 'database-backup' ) !== false )
                {
                    if ( $count >= $files_to_keep )
                    {
                        @unlink( $backups_dir . '/' . $file );
                    }
                    $count++;
                }
            }
        }
        else
        {
            $aio_wp_security->debug_logger->log_debug('DB Backup - Backup configuration prevents removal of old backup files!', 3);
        }
    }
    
    function aiowps_scheduled_backup_handler()
    {
        global $aio_wp_security;
        if($aio_wp_security->configs->get_value('aiowps_enable_automated_backups')=='1')
        {
            $aio_wp_security->debug_logger->log_debug_cron("DB Backup - Scheduled backup is enabled. Checking if a backup needs to be done now...");
            $time_now = current_time( 'mysql' );
            $current_time = strtotime($time_now);
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
                default: 
                    // Fall back to default value, if config is corrupted for some reason.
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
                        $aio_wp_security->configs->set_value('aiowps_last_backup_time', $time_now);
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
                $aio_wp_security->configs->set_value('aiowps_last_backup_time', $time_now);
                $aio_wp_security->configs->save_config();
            }
        }
    }


    function aiowps_scheduled_db_cleanup_handler()
    {
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

        //Delete any expired _aiowps_captcha_string_info_xxxx transients
        AIOWPSecurity_Utility::delete_expired_captcha_transients();

        //Keep adding other DB cleanup tasks as they arise...
    }
}