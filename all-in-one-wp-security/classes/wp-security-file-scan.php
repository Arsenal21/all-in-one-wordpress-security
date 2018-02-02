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

    function execute_db_scan()
    {
        global $aio_wp_security;
        global $wpdb;
        
        //$aio_wp_security->admin_init->filescan_menu->start_buffer();
        ob_start();
        
        $info_msg_string = '<p class="aio_info_with_icon">'.__('Starting DB scan.....please wait while the plugin scans your database.......', 'all-in-one-wp-security-and-firewall').'</p>';
        echo $info_msg_string;
        
        //Options table
        echo '<p class="aio_info_with_icon">'.__('Scanning options table.........', 'all-in-one-wp-security-and-firewall').'</p>';
        $options_table = $wpdb->prefix . 'options';
        $sql= "SELECT option_id,option_value,option_name
        FROM $options_table WHERE 
        INSTR(LCASE(option_name), 'class_generic_support') +
        INSTR(LCASE(option_name), 'widget_generic_support') +
        INSTR(LCASE(option_name), 'fwp') +
        INSTR(LCASE(option_name), 'wp_check_hash') +
        INSTR(LCASE(option_name), 'ftp_credentials') +
        INSTR(LCASE(option_name), 'page_option') +
        INSTR(LCASE(option_value), '<script') +
        INSTR(LCASE(option_value), 'display:none') +
        INSTR(LCASE(option_value), 'networkads') +
        INSTR(option_value, 'eval(') +
        INSTR(LCASE(option_value), 'javascript:') >0
        ";
        
        $results = $wpdb->get_results($sql, ARRAY_A);
        $sus_options_entry_found = false;

        $found_options = '';
                
	if ($results) {
            foreach ($results as $entry) {
                $found_options = '';
                $known_pharma_hack = false;
                $option_id = $entry['option_id'];
                $option_name = $entry['option_name'];
                $option_value = $entry['option_value'];
                
                if (strpos(strtolower($option_name),'class_generic_support')!==false){
                    $known_pharma_hack = true;
                    $found_options.="Known WP Pharma Hack Entry: class_generic_support ";
                }
                if (strpos(strtolower($option_name),'widget_generic_support')!==false){
                    $known_pharma_hack = true;
                    $found_options.="Known WP Pharma Hack Entry: widget_generic_support ";
                }
                if (strpos(strtolower($option_name),'fwp')!==false){
                    $known_pharma_hack = true;
                    $found_options.="Known WP Pharma Hack Entry: fwp ";
                }
                if (strpos(strtolower($option_name),'wp_check_hash')!==false){
                    $known_pharma_hack = true;
                    $found_options.="Known WP Pharma Hack Entry: wp_check_hash ";
                }
                if (strpos(strtolower($option_name),'ftp_credentials')!==false){
                    $known_pharma_hack = true;
                    $found_options.="Known WP Pharma Hack Entry: ftp_credentials ";
                }
                if (strpos(strtolower($option_name),'page_option')!==false){
                    $known_pharma_hack = true;
                    $found_options.="Known WP Pharma Hack Entry: page_option ";
                }
                
                
                //Turned off for false positive
//                if (strpos($option_name,'rss_')!==false) {
//                    if($option_name == 'rss_use_language' || $option_name == 'rss_use_excerpt' || $option_name == 'rss_excerpt_length'){
//                        //any one of these entries are ok.
//                        continue;
//                    }else{
//                        $known_pharma_hack = true;
//                        $found_options.="Known WP Pharma Hack Entry found in options table with option_name: ".$option_name;
//                    }
//                }
                
                //If known pharma hack entry was found delete it
                if($known_pharma_hack){
                    echo '<p class="aio_error_with_icon">'.sprintf( __('%s and option_id: %s', 'all-in-one-wp-security-and-firewall'), $found_options, $entry['option_id']).'</p>';
                    $delete_sql = $wpdb->delete($options_table, array('option_name'=>$option_name));
                    if($delete_sql === FALSE){
                        echo '<p class="aio_error_with_icon">'.sprintf( __('Deletion of known pharma hack entry for option_name %s failed. Please delete this entry manually!', 'all-in-one-wp-security-and-firewall'), $entry['option_name']).'</p>';
                    }else{
                        echo '<p class="aio_success_with_icon">'.sprintf( __('The options table entry with known pharma hack for option_id %s with option_name %s was successfully deleted', 'all-in-one-wp-security-and-firewall'), $entry['option_id'], $entry['option_name']).'</p>';
                    }
                    
                }
                
//                if (strpos($option_name, '_transient_feed') !== false){
//                    continue;
//                }
                if (strpos(strtolower($option_value),'<script')!==false && strpos(strtolower($option_name),'_transient_feed')!==false) continue; //this is a known legit WP entry
                if (strpos(strtolower($option_value),'<script')!==false) $found_options.="&lt;script&gt; tags found in the option_value field for option_name: ".$option_name;
                if (strpos(strtolower($option_value),'display:none')!==false) $found_options.="display:none found in the option_value field for option_name: ".$option_name;
                if (strpos(strtolower($option_value),'networkads')!==false) $found_options.="networkads found in the option_value field for option_name: ".$option_name;
                if (strpos(strtolower($option_value),'eval(')!==false) $found_options.="eval() statement found in the option_value field for option_name: ".$option_name;
                if (strpos(strtolower($option_value),'javascript:')!==false) $found_options.="javascript statement found in the option_value field for option_name: ".$option_name;
                echo '<p class="aio_error_with_icon">'.sprintf( __('Possible suspicious entry found (for option_id: %s) - %s ', 'all-in-one-wp-security-and-firewall'), $entry['option_id'], $found_options).'</p>';

                if($found_options != ''){
                    $sus_options_entry_found = true;
                }
            }
	}
        
        if(!$sus_options_entry_found){
            echo '<p class="aio_success_with_icon">'.__('No suspicious entries found in options table', 'all-in-one-wp-security-and-firewall').'</p>';
	}        
        
        //Posts table
        echo '<p class="aio_info_with_icon">'.__('Scanning posts table.........', 'all-in-one-wp-security-and-firewall').'</p>';
        $posts_table = $wpdb->prefix . 'posts';
        $sql= "SELECT ID,post_author,post_title,post_name,guid,post_content,post_mime_type
        FROM $posts_table WHERE 
        INSTR(LCASE(post_author), '<script') +
        INSTR(LCASE(post_title), '<script') +
        INSTR(LCASE(post_name), '<script') +
        INSTR(LCASE(guid), '<script') +
        INSTR(LCASE(post_author), 'eval(') +
        INSTR(LCASE(post_title), 'eval(') +
        INSTR(LCASE(post_name), 'eval(') +
        INSTR(LCASE(guid), 'eval(') +
        INSTR(LCASE(post_content), 'eval(') +
        INSTR(LCASE(post_content), 'document.write(unescape(') +
        INSTR(LCASE(post_content), 'try{window.onload') +
        INSTR(LCASE(post_content), 'setAttribute(\'src\'') +
        INSTR(LCASE(post_mime_type), 'script') >0
        ";
        
        $results = $wpdb->get_results($sql, ARRAY_A);
        $sus_posts_entry_found = false;
        $found_posts = '';
	if ($results) {
            foreach ($results as $entry) {
                $found_posts = '';
                if (strpos(strtolower($entry['post_author']),'<script')!==false) $found_posts.="post_author: &lt;script "; 
                if (strpos(strtolower($entry['post_title']),'<script')!==false) $found_posts.="post_title: &lt;script "; 
                if (strpos(strtolower($entry['post_name']),'<script')!==false) $found_posts.="post_name: &lt;script "; 
                if (strpos(strtolower($entry['guid']),'<script')!==false) $found_posts.="guid: &lt;script "; 

                if (strpos(strtolower($entry['post_author']),'eval(')!==false) $found_posts.="post_author: eval() "; 
                if (strpos(strtolower($entry['post_title']),'eval(')!==false) $found_posts.="post_title: eval() "; 
                if (strpos(strtolower($entry['post_name']),'eval(')!==false) $found_posts.="post_name: eval() "; 
                if (strpos(strtolower($entry['guid']),'eval(')!==false) $found_posts.="guid: eval() "; 
                if (strpos(strtolower($entry['post_content']),'eval(')!==false) $found_posts.="post_content: eval() "; 

                if (strpos(strtolower($entry['post_content']),'document.write(unescape(')!==false) $found_posts.="post_content: document.write(unescape( "; 
                if (strpos(strtolower($entry['post_content']),'try{window.onload')!==false) $found_posts.="post_content: try{window.onload "; 
                if (strpos(strtolower($entry['post_content']),"setAttribute('src'")!==false) $found_posts.="post_content: setAttribute('src' "; 
                if (strpos(strtolower($entry['post_mime_type']),'script')!==false) $found_posts.="post_mime_type: script "; 
                echo '<p class="aio_error_with_icon">'.sprintf( __('Possible suspicious entry found (for Post ID: %s) in the following column - %s ', 'all-in-one-wp-security-and-firewall'), $entry['ID'], $found_posts).'</p>';
                
                if($found_options != ''){
                    $sus_posts_entry_found = true;
                }
            }
	}
        
        if(!$sus_posts_entry_found){
            echo '<p class="aio_success_with_icon">'.__('No suspicious entries found in posts table', 'all-in-one-wp-security-and-firewall').'</p>';
	}        
        
        //Links table
        echo '<p class="aio_info_with_icon">'.__('Scanning links table.........', 'all-in-one-wp-security-and-firewall').'</p>';
        $links_table = $wpdb->prefix . 'links';
        $sql= "SELECT link_id,link_url,link_image,link_description,link_notes,link_rel,link_rss
        FROM $links_table WHERE 
        INSTR(LCASE(link_url), '<script') +
        INSTR(LCASE(link_image), '<script') +
        INSTR(LCASE(link_description), '<script') +
        INSTR(LCASE(link_notes), '<script') +
        INSTR(LCASE(link_rel), '<script') +
        INSTR(LCASE(link_rss), '<script') +
        INSTR(LCASE(link_url), 'eval(') +
        INSTR(LCASE(link_image), 'eval(') +
        INSTR(LCASE(link_description), 'eval(') +
        INSTR(LCASE(link_notes), 'eval(') +
        INSTR(LCASE(link_rel), 'eval(') +
        INSTR(LCASE(link_rss), 'eval(') +
        INSTR(LCASE(link_url), 'javascript:') >0
        ";
        
        $results = $wpdb->get_results($sql, ARRAY_A);
        $sus_links_entry_found = false;
        $found_links = '';
	if ($results) {
            foreach ($results as $entry) {
                $found_links = '';
                if (strpos(strtolower($entry['link_url']),'<script')!==false) $found_links.="&lt;script&gt; tags found in the link_url field for link_id: ".$entry['link_id'];
                if (strpos(strtolower($entry['link_image']),'<script')!==false) $found_links.="&lt;script&gt; tags found in the link_image field for link_id: ".$entry['link_id'];
                if (strpos(strtolower($entry['link_description']),'<script')!==false) $found_links.="&lt;script&gt; tags found in the link_description field for link_id: ".$entry['link_id'];
                if (strpos(strtolower($entry['link_notes']),'<script')!==false) $found_links.="&lt;script&gt; tags found in the link_notes field for link_id: ".$entry['link_id'];
                if (strpos(strtolower($entry['link_rel']),'<script')!==false) $found_links.="&lt;script&gt; tags found in the link_rel field for link_id: ".$entry['link_id'];
                if (strpos(strtolower($entry['link_rss']),'<script')!==false) $found_links.="&lt;script&gt; tags found in the link_rss field for link_id: ".$entry['link_id'];

                if (strpos(strtolower($entry['link_url']),'eval(')!==false) $found_links.="eval() statement found in the link_url field for link_id: ".$entry['link_id'];
                if (strpos(strtolower($entry['link_image']),'eval(')!==false) $found_links.="eval() statement found in the link_image field for link_id: ".$entry['link_id'];
                if (strpos(strtolower($entry['link_description']),'eval(')!==false) $found_links.="eval() statement found in the link_description field for link_id: ".$entry['link_id'];
                if (strpos(strtolower($entry['link_notes']),'eval(')!==false) $found_links.="eval() statement found in the link_notes field for link_id: ".$entry['link_id'];
                if (strpos(strtolower($entry['link_rel']),'eval(')!==false) $found_links.="eval() statement found in the link_rel field for link_id: ".$entry['link_id'];
                if (strpos(strtolower($entry['link_rss']),'eval(')!==false) $found_links.="eval() statement found in the link_rss field for link_id: ".$entry['link_id'];

                echo '<p class="aio_error_with_icon">'.sprintf( __('Possible suspicious entry - %s ', 'all-in-one-wp-security-and-firewall'), $found_links).'</p>';
                
                if($found_options != ''){
                    $sus_links_entry_found = true;
                }
            }
	}
        
        if(!$sus_links_entry_found) {
            echo '<p class="aio_success_with_icon">'.__('No suspicious entries found in links table', 'all-in-one-wp-security-and-firewall').'</p>';
	}        

        //Comments table
        echo '<p class="aio_info_with_icon">'.__('Scanning comments table.........', 'all-in-one-wp-security-and-firewall').'</p>';
        $comments_table = $wpdb->prefix . 'comments';
        $sql= "SELECT comment_ID,comment_author_url,comment_agent,comment_author,comment_author_email,comment_content
        FROM $comments_table WHERE 
        INSTR(LCASE(comment_author_url), '<script') +
        INSTR(LCASE(comment_agent), '<script') +
        INSTR(LCASE(comment_author), '<script') +
        INSTR(LCASE(comment_author_email), '<script') +
        INSTR(LCASE(comment_content), '<script') +
        INSTR(LCASE(comment_author_url), 'eval(') +
        INSTR(LCASE(comment_agent), 'eval(') +
        INSTR(LCASE(comment_author), 'eval(') +
        INSTR(LCASE(comment_author_email), 'eval(') +
        INSTR(LCASE(comment_content), 'eval(') +
        INSTR(LCASE(comment_content), 'document.write(unescape(') +
        INSTR(LCASE(comment_content), 'try{window.onload') +
        INSTR(LCASE(comment_content), 'setAttribute(\'src\'') +
        INSTR(LCASE(comment_author_url), 'javascript:') >0
        ";
        
        $results = $wpdb->get_results($sql, ARRAY_A);
        $sus_comments_entry_found = false;
        $found_comments = '';
	if ($results) {
            foreach ($results as $entry) {
                $found_comments = '';
                if (strpos(strtolower($entry['comment_author']),'<script')!==false) $found_comments.="&lt;script&gt; tags found in the comment_author field for link_id: ".$entry['comment_ID'];
                if (strpos(strtolower($entry['comment_author_url']),'<script')!==false) $found_comments.="&lt;script&gt; tags found in the comment_author_url field for link_id: ".$entry['comment_ID'];
                if (strpos(strtolower($entry['comment_agent']),'<script')!==false) $found_comments.="&lt;script&gt; tags found in the comment_agent field for link_id: ".$entry['comment_ID'];
                if (strpos(strtolower($entry['comment_author_email']),'<script')!==false) $found_comments.="&lt;script&gt; tags found in the comment_author_email field for link_id: ".$entry['comment_ID'];
                if (strpos(strtolower($entry['comment_content']),'<script')!==false) $found_comments.="&lt;script&gt; tags found in the comment_content field for link_id: ".$entry['comment_ID'];

                if (strpos(strtolower($entry['comment_author']),'eval(')!==false) $found_comments.="eval() statement found in the comment_author field for link_id: ".$entry['comment_ID'];
                if (strpos(strtolower($entry['comment_author_url']),'eval(')!==false) $found_comments.="eval() statement found in the comment_author_url field for link_id: ".$entry['comment_ID'];
                if (strpos(strtolower($entry['comment_agent']),'eval(')!==false) $found_comments.="eval() statement found in the comment_agent field for link_id: ".$entry['comment_ID'];
                if (strpos(strtolower($entry['comment_author_email']),'eval(')!==false) $found_comments.="eval() statement found in the comment_author_email field for link_id: ".$entry['comment_ID'];
                if (strpos(strtolower($entry['comment_content']),'eval(')!==false) $found_comments.="eval() statement found in the comment_content field for link_id: ".$entry['comment_ID'];

                echo '<p class="aio_error_with_icon">'.sprintf( __('Possible suspicious entry - %s ', 'all-in-one-wp-security-and-firewall'), $found_comments).'</p>';
                
                if($found_comments != ''){
                    $sus_comments_entry_found = true;
                }
            }
	}
        
        if(!$sus_comments_entry_found) {
            echo '<p class="aio_success_with_icon">'.__('No suspicious entries found in comments table', 'all-in-one-wp-security-and-firewall').'</p>';
	}        
        
        //postmeta table
        echo '<p class="aio_info_with_icon">'.__('Scanning postmeta table.........', 'all-in-one-wp-security-and-firewall').'</p>';
        $postmeta_table = $wpdb->prefix . 'postmeta';
        $sql= "SELECT meta_id,meta_value
        FROM $postmeta_table WHERE 
        INSTR(LCASE(meta_value), 'eval(')>0
        ";
        
        $results = $wpdb->get_results($sql, ARRAY_A);
        $sus_postmeta_entry_found = false;
        $found_postmeta = '';
	if ($results) {
            foreach ($results as $entry) {
                $found_postmeta = '';
                if (strpos(strtolower($entry['meta_value']),'eval(')!==false) $found_postmeta.="eval() statement found in the meta_value field for meta_id: ".$entry['meta_id'];

                echo '<p class="aio_error_with_icon">'.sprintf( __('Possible suspicious entry - %s ', 'all-in-one-wp-security-and-firewall'), $found_postmeta).'</p>';
                
                if($found_postmeta != ''){
                    $sus_postmeta_entry_found = true;
                }
            }
	}
        
        if(!$sus_postmeta_entry_found) {
            echo '<p class="aio_success_with_icon">'.__('No suspicious entries found in postmeta table', 'all-in-one-wp-security-and-firewall').'</p>';
	}        

        //usermeta table
        echo '<p class="aio_info_with_icon">'.__('Scanning usermeta table.........', 'all-in-one-wp-security-and-firewall').'</p>';
        $usermeta_table = $wpdb->prefix . 'usermeta';
        $sql= "SELECT umeta_id,meta_value
        FROM $usermeta_table WHERE 
        INSTR(LCASE(meta_value), 'eval(')>0
        ";
        
        $results = $wpdb->get_results($sql, ARRAY_A);
        $sus_usermeta_entry_found = false;
        $found_usermeta = '';
	if ($results) {
            foreach ($results as $entry) {
                $found_usermeta = '';
                if (strpos(strtolower($entry['meta_value']),'eval(')!==false) $found_usermeta.="eval() statement found in the meta_value field for meta_id: ".$entry['umeta_id'];

                echo '<p class="aio_error_with_icon">'.sprintf( __('Possible suspicious entry - %s ', 'all-in-one-wp-security-and-firewall'), $found_usermeta).'</p>';
                
                if($found_usermeta != ''){
                    $sus_usermeta_entry_found = true;
                }
            }
	}
        
        if(!$sus_usermeta_entry_found) {
            echo '<p class="aio_success_with_icon">'.__('No suspicious entries found in usermeta table', 'all-in-one-wp-security-and-firewall').'</p>';
	}        

        //users table
        echo '<p class="aio_info_with_icon">'.__('Scanning users table.........', 'all-in-one-wp-security-and-firewall').'</p>';
        $users_table = $wpdb->prefix . 'users';
        $sql= "SELECT ID,user_login,user_nicename,user_email,user_url,display_name
        FROM $users_table WHERE 
        INSTR(LCASE(user_login), '<script') +
        INSTR(LCASE(user_nicename), '<script') +
        INSTR(LCASE(user_email), '<script') +
        INSTR(LCASE(user_url), '<script') +
        INSTR(LCASE(display_name), '<script') +
        INSTR(user_login, 'eval(') +
        INSTR(user_nicename, 'eval(') +
        INSTR(user_email, 'eval(') +
        INSTR(user_url, 'eval(') +
        INSTR(display_name, 'eval(') +
        INSTR(LCASE(user_url), 'javascript:') +
        INSTR(LCASE(user_email), 'javascript:')>0
        ";
        
        $results = $wpdb->get_results($sql, ARRAY_A);
        $sus_users_entry_found = false;
        $found_users = '';
	if ($results) {
            foreach ($results as $entry) {
                $found_users = '';
                if (strpos(strtolower($entry['user_login']),'<script')!==false) $found_users.="&lt;script&gt; tags found in the user_login field for user ID: ".$entry['ID'];
                if (strpos(strtolower($entry['user_nicename']),'<script')!==false) $found_users.="&lt;script&gt; tags found in the user_nicename field for user ID: ".$entry['ID'];
                if (strpos(strtolower($entry['user_email']),'<script')!==false) $found_users.="&lt;script&gt; tags found in the user_email field for user ID: ".$entry['ID'];
                if (strpos(strtolower($entry['user_url']),'<script')!==false) $found_users.="&lt;script&gt; tags found in the user_url field for user ID: ".$entry['ID'];
                if (strpos(strtolower($entry['display_name']),'<script')!==false) $found_users.="&lt;script&gt; tags found in the display_name field for user ID: ".$entry['ID'];

                if (strpos(strtolower($entry['user_login']),'eval(')!==false) $found_users.="eval() statement found in the user_login field for user ID: ".$entry['ID'];
                if (strpos(strtolower($entry['user_nicename']),'eval(')!==false) $found_users.="eval() statement found in the user_nicename field for user ID: ".$entry['ID'];
                if (strpos(strtolower($entry['user_email']),'eval(')!==false) $found_users.="eval() statement found in the user_email field for user ID: ".$entry['ID'];
                if (strpos(strtolower($entry['user_url']),'eval(')!==false) $found_users.="eval() statement found in the user_url field for user ID: ".$entry['ID'];
                if (strpos(strtolower($entry['display_name']),'eval(')!==false) $found_users.="eval() statement found in the display_name field for user ID: ".$entry['ID'];

                echo '<p class="aio_error_with_icon">'.sprintf( __('Possible suspicious entry - %s ', 'all-in-one-wp-security-and-firewall'), $found_users).'</p>';
                
                if($found_users != ''){
                    $sus_users_entry_found = true;
                }
            }
	}
        
        if(!$sus_users_entry_found) {
            echo '<p class="aio_success_with_icon">'.__('No suspicious entries found in users table', 'all-in-one-wp-security-and-firewall').'</p>';
	}        

        $output = ob_get_contents();
        ob_end_clean();

        if($found_options != '' || $found_posts != '' || $found_links != '' || $found_comments != '' || $found_postmeta != '' || $found_usermeta != '' || $found_users != ''){
            $error_msg = '<div id="message" class="error"><p><strong><p>'.__('The plugin has detected that there are some potentially suspicious entries in your database.', 'all-in-one-wp-security-and-firewall').'</p>';
            $error_msg .= '<p>'.__('Please verify the results listed below to confirm whether the entries detected are genuinely suspicious or if they are false positives.', 'all-in-one-wp-security-and-firewall').'</p>';
            $error_msg .= '</strong></p></div>';
            
            //Display a yellow box disclaimer stating that if no suspicious entries found does not necessarily mean site is not currently hacked
            $malware_scan_tab_link = '<a href="admin.php?page='.AIOWPSEC_FILESCAN_MENU_SLUG.'&tab=tab2" target="_blank">Malware Scan</a>';
            $info_msg = '<strong>'.__('Disclaimer:').'</strong><br />';
            $info_msg .= __('Even though this database scan has revealed some suspicious entries, this does not necessarily mean that other parts of your DB or site are also not compromised.', 'all-in-one-wp-security-and-firewall').'<br />';
            $info_msg .= __('Please note that database scan performed by this feature is basic and looks for common malicious entries. Since hackers are continually evolving their methods this scan is not meant to be a guaranteed catch-all for malware.', 'all-in-one-wp-security-and-firewall').'<br />';
            $info_msg .= sprintf( __('It is your responsibility to do the due diligence and perform a robust %s on your site if you wish to be more certain that your site is clean.', 'all-in-one-wp-security-and-firewall'), $malware_scan_tab_link);
            $disclaimer = '<div class="aio_yellow_box"><p>'.$info_msg.'</p></div>';
            
            return $error_msg.$disclaimer.$output;

        }else{
            $scan_complete_msg = '<div id="message" class="updated fade"><p><strong>';
            $scan_complete_msg .= __('DB Scan was completed successfully. No suspicious entries found.');
            $scan_complete_msg .= '</strong></p></div>';

            //Display a yellow box disclaimer stating that if no suspicious entries found does not necessarily mean site is not currently hacked
            $malware_scan_tab_link = '<a href="admin.php?page='.AIOWPSEC_FILESCAN_MENU_SLUG.'&tab=tab2" target="_blank">Malware Scan</a>';
            $info_msg = '<strong>'.__('Disclaimer:').'</strong><br />';
            $info_msg .= __('Even though the database scan has not revealed any suspicious entries, this does not necessarily mean that your site is actually completely clean or not compromised.', 'all-in-one-wp-security-and-firewall').'<br />';
            $info_msg .= __('Please note that database scan performed by this feature is basic and looks for common malicious entries. Since hackers are continually evolving their methods this scan is not meant to be a guaranteed catch-all for malware.', 'all-in-one-wp-security-and-firewall').'<br />';
            $info_msg .= sprintf( __('It is your responsibility to do the due diligence and perform a robust %s on your site if you wish to be more certain that your site is clean.', 'all-in-one-wp-security-and-firewall'), $malware_scan_tab_link);
            $disclaimer = '<div class="aio_yellow_box"><p>'.$info_msg.'</p></div>';
            
            return $scan_complete_msg.$disclaimer.$output;
        }
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