<?php
if(!defined('ABSPATH')){
    exit;//Exit if accessed directly
}

class AIOWPSecurity_Scan
{

    function __construct() 
    {
        add_action('aiowps_perform_fcd_scan_tasks', array(&$this, 'aiowps_scheduled_fcd_scan_handler'));
    }
    
    /**
     * This function will recursively scan through all directories starting from the specified location
     * It will store the path/filename, last_modified and filesize values in a multi-dimensional associative array
     */
    function execute_file_change_detection_scan() 
    {
        global $aio_wp_security;
        $scan_result = array();
        if($this->has_scan_data()){
            $scanned_data = $this->do_file_change_scan(); //Scan the filesystem and get details
            $last_scan_data = $this->get_last_scan_data();
            $scan_result = $this->compare_scan_data($last_scan_data,$scanned_data);
            $scan_result['initial_scan'] = '';
            $this->save_scan_data_to_db($scanned_data, 'update', $scan_result);
            if (!empty($scan_result['files_added']) || !empty($scan_result['files_removed']) || !empty($scan_result['files_changed'])){
                //This means there was a change detected
                $aio_wp_security->configs->set_value('aiowps_fcds_change_detected', TRUE);
                $aio_wp_security->configs->save_config();
                $aio_wp_security->debug_logger->log_debug("File Change Detection Feature: change to filesystem detected!");

                $this->aiowps_send_file_change_alert_email($scan_result); //Send file change scan results via email if applicable
            } else {
                //Reset the change flag
                $aio_wp_security->configs->set_value('aiowps_fcds_change_detected', FALSE);
                $aio_wp_security->configs->save_config();
            }
            return $scan_result;
        }
        else{
            $scanned_data = $this->do_file_change_scan();
            $this->save_scan_data_to_db($scanned_data);
            $scan_result['initial_scan'] = '1';
            return $scan_result;
        }
    }

    /**
     * Send email with notification about file changes detected by last scan.
     * @global AIO_WP_Security $aio_wp_security
     * @param array $scan_result Array with scan result returned by compare_scan_data() method.
     */
    function aiowps_send_file_change_alert_email($scan_result)
    {
        global $aio_wp_security;
        if ( $aio_wp_security->configs->get_value('aiowps_send_fcd_scan_email') == '1' ) 
        {
            $site_title = get_bloginfo( 'name' );
            $from_name = empty($site_title)?'WordPress':$site_title;
            
            $headers = 'From: ' . $from_name . ' <' . get_option('admin_email') . '>' . PHP_EOL;
            $subject = __( 'All In One WP Security - File change detected!', 'all-in-one-wp-security-and-firewall' ) . ' ' . date( 'l, F jS, Y \a\\t g:i a', current_time( 'timestamp' ) );
            //$attachment = array();
            $message = __( 'A file change was detected on your system for site URL', 'all-in-one-wp-security-and-firewall' ) . ' ' . get_option( 'siteurl' ) . __( '. Scan was generated on', 'all-in-one-wp-security-and-firewall' ) . ' ' . date( 'l, F jS, Y \a\\t g:i a', current_time( 'timestamp' ) );
            $message .= "\r\n\r\n".__( 'A summary of the scan results is shown below:', 'all-in-one-wp-security-and-firewall' );
            $message .= "\r\n\r\n";
            $message .= self::get_file_change_summary($scan_result);
            $message .= "\r\n".__( 'Login to your site to view the scan details.', 'all-in-one-wp-security-and-firewall' );

            // Get the email address(es).
            $addresses = $aio_wp_security->configs->get_value('aiowps_fcd_scan_email_address');
            // If no explicit email address(es) are given, send email to site admin.
            $to = empty( $addresses ) ? array( get_site_option('admin_email') ) : explode(PHP_EOL, $addresses);
            if ( !wp_mail( $to, $subject, $message, $headers ) ) {
                $aio_wp_security->debug_logger->log_debug("File change notification email failed to send.",4);
            }

        }
    }
    
    function aiowps_scheduled_fcd_scan_handler()
    {
        global $aio_wp_security;
        if($aio_wp_security->configs->get_value('aiowps_enable_automated_fcd_scan')=='1')
        {
            $aio_wp_security->debug_logger->log_debug_cron("Filescan - Scheduled fcd_scan is enabled. Checking now to see if scan needs to be done...");
            $time_now = current_time( 'mysql' );
            $current_time = strtotime($time_now);
            $fcd_scan_frequency = $aio_wp_security->configs->get_value('aiowps_fcd_scan_frequency'); //Number of hours or days or months interval
            $interval_setting = $aio_wp_security->configs->get_value('aiowps_fcd_scan_interval'); //Hours/Days/Months
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
            $last_fcd_scan_time = $aio_wp_security->configs->get_value('aiowps_last_fcd_scan_time');
            if ($last_fcd_scan_time != NULL)
            {
                $last_fcd_scan_time = strtotime($aio_wp_security->configs->get_value('aiowps_last_fcd_scan_time'));
                $next_fcd_scan_time = strtotime("+".abs($fcd_scan_frequency).$interval, $last_fcd_scan_time);
                if ($next_fcd_scan_time <= $current_time)
                {
                    //It's time to do a filescan
                    $result = $this->execute_file_change_detection_scan(ABSPATH);
//                    if ($result)
//                    {
                        $aio_wp_security->configs->set_value('aiowps_last_fcd_scan_time', $time_now);
                        $aio_wp_security->configs->save_config();
                        $aio_wp_security->debug_logger->log_debug_cron("Filescan - Scheduled filescan was successfully completed.");
//                    } 
//                    else
//                    {
//                        $aio_wp_security->debug_logger->log_debug_cron("Filescan - Scheduled filescan operation failed!",4);
//                    }
                }
            }
            else
            {
                //Set the last scan time to now so it can trigger for the next scheduled period
                $aio_wp_security->configs->set_value('aiowps_last_fcd_scan_time', $time_now);
                $aio_wp_security->configs->save_config();
            }
        }
    }
    
    /* Returns true if there is at least one previous scaned data in the DB. False otherwise */
    function has_scan_data()
    {
        global $wpdb;
        //For scanned data the meta_key1 column valu is 'file_change_detection', meta_value1 column value is 'file_scan_data'. Then the data is stored in meta_value4 column.
        $aiowps_global_meta_tbl_name = AIOWPSEC_TBL_GLOBAL_META_DATA;
        $sql = $wpdb->prepare("SELECT * FROM $aiowps_global_meta_tbl_name WHERE meta_key1=%s AND meta_value1=%s", 'file_change_detection', 'file_scan_data');
        $resultset = $wpdb->get_row($sql, OBJECT);
        if($resultset){
            $scan_data = maybe_unserialize($resultset->meta_value4);
            if(!empty($scan_data)){
                return true;
            }
        }
        return false;
    }
    
    function get_last_scan_data()
    {
        global $wpdb;
        //For scanned data the meta_key1 column valu is 'file_change_detection', meta_value1 column value is 'file_scan_data'. Then the data is stored in meta_value4 column.
        $aiowps_global_meta_tbl_name = AIOWPSEC_TBL_GLOBAL_META_DATA;
        $sql = $wpdb->prepare("SELECT * FROM $aiowps_global_meta_tbl_name WHERE meta_key1=%s AND meta_value1=%s", 'file_change_detection', 'file_scan_data');
        $resultset = $wpdb->get_row($sql, OBJECT);
        if($resultset){
            $scan_data = maybe_unserialize($resultset->meta_value4);
            return $scan_data;
        }
        return array(); //return empty array if no old scan data
    }
    
    function save_scan_data_to_db($scanned_data, $save_type = 'insert', $scan_result = array())
    {
        global $wpdb, $aio_wp_security;
        $result = '';
        //For scanned data the meta_key1 column value is 'file_change_detection', meta_value1 column value is 'file_scan_data'. Then the data is stored in meta_value4 column.
        $aiowps_global_meta_tbl_name = AIOWPSEC_TBL_GLOBAL_META_DATA;
        $payload = maybe_serialize($scanned_data);
        $scan_result = maybe_serialize($scan_result);
        $date_time = current_time( 'mysql' );
        $data = array('date_time' => $date_time, 'meta_key1' => 'file_change_detection', 'meta_value1' => 'file_scan_data', 'meta_value4' => $payload, 'meta_key5' => 'last_scan_result', 'meta_value5' => $scan_result);
        if($save_type == 'insert'){
            $result = $wpdb->insert($aiowps_global_meta_tbl_name, $data);
        }
        else{
            $where = array('meta_key1' => 'file_change_detection', 'meta_value1' => 'file_scan_data');
            $result = $wpdb->update($aiowps_global_meta_tbl_name, $data, $where);
            
        }
        if ($result === false){
            $aio_wp_security->debug_logger->log_debug("save_scan_data_to_db() - Error inserting data to DB!",4);
            return false;
        }else{
            return true;
        }
    }

    /**
     * Recursively scan the entire $start_dir directory and return file size
     * and last modified date of every regular file. Ignore files and file
     * types specified in file scanner settings.
     * @global AIO_WP_Security $aio_wp_security
     * @param string $start_dir
     * @return array
     */
    function do_file_change_scan($start_dir=ABSPATH)
    {
        global $aio_wp_security;
        $filescan_data = array();
        // Iterator key is absolute file path, iterator value is SplFileInfo object,
        // iteration skips '..' and '.' records, because we're not interested in directories.
        $dit = new RecursiveDirectoryIterator(
            $start_dir, FilesystemIterator::KEY_AS_PATHNAME | FilesystemIterator::CURRENT_AS_FILEINFO | FilesystemIterator::SKIP_DOTS
        );
        $rit = new RecursiveIteratorIterator(
            $dit, RecursiveIteratorIterator::SELF_FIRST, RecursiveIteratorIterator::CATCH_GET_CHILD
        );

        // Grab files/directories to skip
        $files_to_skip = AIOWPSecurity_Utility::explode_trim_filter_empty($aio_wp_security->configs->get_value('aiowps_fcd_exclude_files'));
        // Grab (lowercased) file types to skip
        $file_types_to_skip = AIOWPSecurity_Utility::explode_trim_filter_empty(strtolower($aio_wp_security->configs->get_value('aiowps_fcd_exclude_filetypes')));

        $start_dir_length = strlen($start_dir);

        foreach ($rit as $filename => $fileinfo) {

            if ( !file_exists($filename) || is_dir($filename) ) {
                continue; // if file doesn't exist or is a directory move on to next iteration
            }

            if ( $fileinfo->getFilename() == 'wp-security-log-cron-job.txt' || $fileinfo->getFilename() == 'wp-security-log.txt' ) {
                continue; // skip aiowps log files
            }

            // Let's omit any file types from the scan which were specified in the settings if necessary
            if ( !empty($file_types_to_skip) ) {
                //$current_file_ext = strtolower($fileinfo->getExtension()); //getExtension() only available on PHP 5.3.6 or higher
                $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
                if (in_array($ext, $file_types_to_skip) ) { continue; }
            }

            // Let's omit specific files or directories from the scan which were specified in the settings
            if ( !empty($files_to_skip) ) {

                $skip_this = false;
                foreach ($files_to_skip as $f_or_dir) {
                    // Expect files/dirs to be specified relatively to $start_dir,
                    // so start searching at $start_dir_length offset.
                    if (strpos($filename, $f_or_dir, $start_dir_length) !== false) {
                        $skip_this = true;
                        break; // !
                    }
                }
                if ($skip_this) { continue; }
            }

            $filescan_data[$filename] = array(
                'last_modified' => $fileinfo->getMTime(),
                'filesize'      => $fileinfo->getSize(),
            );

        }
        return $filescan_data; 
    }
    
    function compare_scan_data($last_scan_data, $new_scanned_data)
    {
        // Identify new files added: get all files which are in the new scan but not present in the old scan
        $files_added = @array_diff_key( $new_scanned_data, $last_scan_data );
        // Identify files deleted: get all files which are in the old scan but not present in the new scan
        $files_removed = @array_diff_key( $last_scan_data, $new_scanned_data );
        // Identify existing files: get all files which are in new scan, but were not added
        $files_kept = @array_diff_key( $new_scanned_data, $files_added );

        $files_changed = array();

        // Loop through existing files and determine, if they have been changed
        foreach ( $files_kept as $filename => $new_scan_meta ) {
            $last_scan_meta = $last_scan_data[$filename];
            // Check filesize and last_modified values
            if ( ($new_scan_meta['last_modified'] !== $last_scan_meta['last_modified'])
                || ($new_scan_meta['filesize'] !== $last_scan_meta['filesize']) )
            {
                $files_changed[$filename] = $new_scan_meta;
            }
        }

        // Create single array of all changes
        return array(
            'files_added' => $files_added,
            'files_removed' => $files_removed,
            'files_changed' => $files_changed,
        );
    }

    static function get_file_change_data()
    {
        global $wpdb, $aio_wp_security;
        //Let's get the results array from the DB
        $tbl_name = AIOWPSEC_TBL_GLOBAL_META_DATA;
        $key = 'file_change_detection';
        $sql_prep = $wpdb->prepare("SELECT * FROM $tbl_name WHERE meta_key1 = %s", $key);
        $scan_db_data = $wpdb->get_row($sql_prep, ARRAY_A);
        if ($scan_db_data === NULL)
        {
            $aio_wp_security->debug_logger->log_debug("display_last_scan_results() - DB query for scan results data from global meta table returned NULL!",4);
            return FALSE;
        }
        $date_last_scan = $scan_db_data['date_time'];
        $scan_results_unserialized = maybe_unserialize($scan_db_data['meta_value5']);
        if (empty($scan_results_unserialized['files_added']) && empty($scan_results_unserialized['files_removed']) && empty($scan_results_unserialized['files_changed'])){
            //No file change detected
            return FALSE;
        }else{
            return $scan_results_unserialized;
        }

    }

    static function get_file_change_summary($scan_result)
    {
        $scan_summary = "";
        if (!empty($scan_result['files_added']))
        {
            //Output of files added
            $scan_summary .= "\r\n".__('The following files were added to your host', 'all-in-one-wp-security-and-firewall').":\r\n";
            foreach ($scan_result['files_added'] as $key=>$value) {
                $scan_summary .= "\r\n".$key.' ('.__('modified on: ', 'all-in-one-wp-security-and-firewall').date('Y-m-d H:i:s',$value['last_modified']).')';
            }
            $scan_summary .= "\r\n======================================\r\n";
        }
        if (!empty($scan_result['files_removed']))
        {
            //Output of files removed
            $scan_summary .= "\r\n".__('The following files were removed from your host', 'all-in-one-wp-security-and-firewall').":\r\n";
            foreach ($scan_result['files_removed'] as $key=>$value) {
                $scan_summary .= "\r\n".$key.' ('.__('modified on: ', 'all-in-one-wp-security-and-firewall').date('Y-m-d H:i:s',$value['last_modified']).')';
            }
            $scan_summary .= "\r\n======================================\r\n";
        }

        if (!empty($scan_result['files_changed']))
        {
            //Output of files changed
            $scan_summary .= "\r\n".__('The following files were changed on your host', 'all-in-one-wp-security-and-firewall').":\r\n";
            foreach ($scan_result['files_changed'] as $key=>$value) {
                $scan_summary .= "\r\n".$key.' ('.__('modified on: ', 'all-in-one-wp-security-and-firewall').date('Y-m-d H:i:s',$value['last_modified']).')';
            }
            $scan_summary .= "\r\n======================================\r\n";
        }

        return $scan_summary;
    }

}