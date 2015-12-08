<?php

class AIOWPSecurity_Utility_File
{
    
    /* This variable will be an array which will contain all of the files and/or directories we wish to check permissions for */
    public $files_and_dirs_to_check;
    
    function __construct(){
         /* Let's initiliaze our class variable array with all of the files and/or directories we wish to check permissions for.
         * NOTE: we can add to this list in future if we wish
         */

        //Get wp-config.php file path
        $wp_config_path = AIOWPSecurity_Utility_File::get_wp_config_file_path();

        $this->files_and_dirs_to_check = array(
            array('name'=>'root directory','path'=>ABSPATH,'permissions'=>'0755'),
            array('name'=>'wp-includes/','path'=>ABSPATH."wp-includes",'permissions'=>'0755'),
            array('name'=>'.htaccess','path'=>ABSPATH.".htaccess",'permissions'=>'0644'),
            array('name'=>'wp-admin/index.php','path'=>ABSPATH."wp-admin/index.php",'permissions'=>'0644'),
            array('name'=>'wp-admin/js/','path'=>ABSPATH."wp-admin/js/",'permissions'=>'0755'),
            array('name'=>'wp-content/themes/','path'=>ABSPATH."wp-content/themes",'permissions'=>'0755'),
            array('name'=>'wp-content/plugins/','path'=>ABSPATH."wp-content/plugins",'permissions'=>'0755'),
            array('name'=>'wp-admin/','path'=>ABSPATH."wp-admin",'permissions'=>'0755'),
            array('name'=>'wp-content/','path'=>ABSPATH."wp-content",'permissions'=>'0755'),
            array('name'=>'wp-config.php','path'=>$wp_config_path,'permissions'=>'0644')
            //Add as many files or dirs as needed by following the convention above
        );

    }
    
    static function get_wp_config_file_path()
    {
        $wp_config_file = ABSPATH . 'wp-config.php';
        if(file_exists($wp_config_file)){
            return $wp_config_file;
        }
        else if (file_exists(dirname( ABSPATH ) . '/wp-config.php')){       
            return dirname( ABSPATH ) . '/wp-config.php';
        }
        return $wp_config_file;
    }
    
    static function write_content_to_file($file_path, $new_contents)
    {
        @chmod($file_path, 0777);
        if (is_writeable($file_path))
        {
            $handle = fopen($file_path, 'w');
            foreach( $new_contents as $line ) {
                fwrite($handle, $line);
            }
            fclose($handle);
            @chmod($file_path, 0644); //Let's change the file back to a secure permission setting
            return true;
	} else {
            return false;
	}
    }
    
    static function backup_a_file($src_file_path, $suffix = 'backup')
    {
        $backup_file_path = $src_file_path . '.' . $suffix;
        if (!copy($src_file_path, $backup_file_path)) {
            //Failed to make a backup copy
            return false;
        }
        return true;
    }

    static function backup_and_rename_wp_config($src_file_path, $prefix = 'backup')
    {
        global $aio_wp_security;
        
        //Check to see if the main "backups" directory exists - create it otherwise
        $aiowps_backup_dir = WP_CONTENT_DIR.'/'.AIO_WP_SECURITY_BACKUPS_DIR_NAME;
        if (!AIOWPSecurity_Utility_File::create_dir($aiowps_backup_dir))
        {
            $aio_wp_security->debug_logger->log_debug("backup_and_rename_wp_config - Creation of backup directory failed!",4);
            return false;
        }
        
        $src_parts = pathinfo($src_file_path);
        $backup_file_name = $prefix . '.' . $src_parts['basename'];
        
        $backup_file_path = $aiowps_backup_dir . '/' . $backup_file_name;
        if (!copy($src_file_path, $backup_file_path)) {
            //Failed to make a backup copy
            return false;
        }
        return true;
    }
    
    static function backup_and_rename_htaccess($src_file_path, $suffix = 'backup')
    {
        global $aio_wp_security;
        
        //Check to see if the main "backups" directory exists - create it otherwise
        $aiowps_backup_dir = WP_CONTENT_DIR.'/'.AIO_WP_SECURITY_BACKUPS_DIR_NAME;
        if (!AIOWPSecurity_Utility_File::create_dir($aiowps_backup_dir))
        {
            $aio_wp_security->debug_logger->log_debug("backup_and_rename_htaccess - Creation of backup directory failed!",4);
            return false;
        }
        
        $src_parts = pathinfo($src_file_path);
        $backup_file_name = $src_parts['basename'] . '.' . $suffix;
        
        $backup_file_path = $aiowps_backup_dir . '/' . $backup_file_name;
        if (!copy($src_file_path, $backup_file_path)) {
            //Failed to make a backup copy
            return false;
        }
        return true;
    }

    //Function which reads entire contents of a file and stores serialized contents into our global_meta table
    static function backup_file_contents_to_db($src_file_path, $key_description)
    {
        global $wpdb, $aio_wp_security;
        $file_contents = AIOWPSecurity_Utility_File::get_file_contents($src_file_path);
        
        $payload = serialize($file_contents);
        $date_time = current_time('mysql');
        $data = array('date_time' => $date_time, 'meta_key1' => $key_description, 'meta_value2' => $payload);

        //First check if a backup entry already exists in the global_meta table
        $aiowps_global_meta_tbl_name = AIOWPSEC_TBL_GLOBAL_META_DATA;
        $resultset = $wpdb->get_row("SELECT * FROM $aiowps_global_meta_tbl_name WHERE meta_key1 = '$key_description'", OBJECT);
        if($resultset){
            $where = array('meta_key1' => $key_description);
            $res = $wpdb->update($aiowps_global_meta_tbl_name, $data, $where);
        }else{
            $res = $wpdb->insert($aiowps_global_meta_tbl_name, $data);
        }

        if($res === false)
        {
            $aio_wp_security->debug_logger->log_debug("AIOWPSecurity_Utility_File::backup_file_contents_to_db() - Unable to write entry to DB",4);
        }
        return;
    }
    
    
    static function recursive_file_search($pattern='*', $flags = 0, $path='')
    {
        $paths=glob($path.'*', GLOB_MARK|GLOB_ONLYDIR|GLOB_NOSORT);
        if ($paths === FALSE){
            return FALSE;
        }
        $files=glob($path.$pattern, $flags);
        if ($files === FALSE){
            return FALSE;
        }
        foreach ($paths as $path) { $files=array_merge($files,AIOWPSecurity_Utility_File::recursive_file_search($pattern, $flags, $path)); }
        return $files;
    }
    
    /*
     * Useful when wanting to echo file contents to screen with <br /> tags
     */
    static function get_file_contents_with_br($src_file)
    {
        $file_contents = file_get_contents($src_file);        
        return nl2br($file_contents);
    }

    /*
     * Useful when wanting to echo file contents inside textarea
     */
    static function get_file_contents($src_file)
    {
        $file_contents = file_get_contents($src_file);        
        return $file_contents;
    }
    
    /*
     * Returns the file's permission value eg, "0755"
     */
    static function get_file_permission($filepath)
    {
        if (!function_exists('fileperms')) 
        {
            $perms = '-1';
        }
        else 
        {
            clearstatcache();
            $perms = substr(sprintf("%o", @fileperms($filepath)), -4);
        }
        return $perms;
    }

    /*
     * Checks if a write operation is possible for the file in question
     */
    static function is_file_writable($filepath)
    {
        $test_string = ""; //We will attempt to append an empty string at the end of the file for the test
        $write_result = @file_put_contents($filepath, $test_string, FILE_APPEND | LOCK_EX);
        if ($write_result === false)
        {
            return false;
        } 
        else
        {
            return true;
        }
    }

    static function download_a_file_option1($file_path, $file_name = '')
    {
        $file = $file_path;//Full ABS path to the file
        if(empty($file_name)){$file_name = basename($file);}

        header('Content-Description: File Transfer');
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename='.$file_name);
        header('Content-Transfer-Encoding: binary');
        header('Expires: 0');
        header('Cache-Control: must-revalidate');
        header('Pragma: public');
        header('Content-Length: ' . filesize($file));
        //ob_clean();
        //flush();
        readfile($file);
        exit;
    }
    
    static function download_content_to_a_file($output, $file_name = '')
    {
        if(empty($file_name)){$file_name = "aiowps_" . date("Y-m-d_H-i", time()).".txt";}

        header("Content-Encoding: UTF-8");
        header("Cache-Control: must-revalidate, post-check=0, pre-check=0");
        header("Content-Description: File Transfer");
        header("Content-type: application/octet-stream");
        header("Content-disposition: attachment; filename=" . $file_name);
        header("Content-Transfer-Encoding: binary");
        header("Content-Length: " . strlen($output));
        echo $output;
        exit;
    }
    
    /*
     * This function will compare the current permission value for a file or dir with the recommended value.
     * It will compare the individual "execute", "write" and "read" bits for the "public", "group" and "owner" permissions.
     * If the permissions for an actual bit value are greater than the recommended value it returns '0' (=less secure)
     * Otherwise it returns '1' which means it is secure
     * Accepts permission value parameters in octal, ie, "0777" or "777"
     */
    static function is_file_permission_secure($recommended, $actual)
    {
        $result = 1; //initialize return result

        //Check "public" permissions
        $public_value_actual = substr($actual,-1,1); //get dec value for actual public permission
        $public_value_rec = substr($recommended,-1,1); //get dec value for recommended public permission

        $pva_bin = decbin($public_value_actual); //Convert value to binary
        $pvr_bin = decbin($public_value_rec); //Convert value to binary
        //Compare the "executable" bit values for the public actual versus the recommended
        if (substr($pva_bin,-1,1)<=substr($pvr_bin,-1,1))
        {
            //The "execute" bit is the same or less as the recommended value
            $result = 1*$result;
        }else
        {
            //The "execute" bit is switched on for the actual value - meaning it is less secure
            $result = 0*$result;
        }
        
        //Compare the "write" bit values for the public actual versus the recommended
        if (substr($pva_bin,-2,1)<=substr($pvr_bin,-2,1))
        {
            //The "write" bit is the same or less as the recommended value
            $result = 1*$result;
        }else
        {
            //The "write" bit is switched on for the actual value - meaning it is less secure
            $result = 0*$result;
        }

        //Compare the "read" bit values for the public actual versus the recommended
        if (substr($pva_bin,-3,1)<=substr($pvr_bin,-3,1))
        {
            //The "read" bit is the same or less as the recommended value
            $result = 1*$result;
        }else
        {
            //The "read" bit is switched on for the actual value - meaning it is less secure
            $result = 0*$result;
        }

        //Check "group" permissions
        $group_value_actual = substr($actual,-2,1);
        $group_value_rec = substr($recommended,-2,1);
        $gva_bin = decbin($group_value_actual); //Convert value to binary
        $gvr_bin = decbin($group_value_rec); //Convert value to binary

        //Compare the "executable" bit values for the group actual versus the recommended
        if (substr($gva_bin,-1,1)<=substr($gvr_bin,-1,1))
        {
            //The "execute" bit is the same or less as the recommended value
            $result = 1*$result;
        }else
        {
            //The "execute" bit is switched on for the actual value - meaning it is less secure
            $result = 0*$result;
        }

        //Compare the "write" bit values for the public actual versus the recommended
        if (substr($gva_bin,-2,1)<=substr($gvr_bin,-2,1))
        {
            //The "write" bit is the same or less as the recommended value
            $result = 1*$result;
        }else
        {
            //The "write" bit is switched on for the actual value - meaning it is less secure
            $result = 0*$result;
        }

        //Compare the "read" bit values for the public actual versus the recommended
        if (substr($gva_bin,-3,1)<=substr($gvr_bin,-3,1))
        {
            //The "read" bit is the same or less as the recommended value
            $result = 1*$result;
        }else
        {
            //The "read" bit is switched on for the actual value - meaning it is less secure
            $result = 0*$result;
        }
        
        //Check "owner" permissions
        $owner_value_actual = substr($actual,-3,1);
        $owner_value_rec = substr($recommended,-3,1);
        $ova_bin = decbin($owner_value_actual); //Convert value to binary
        $ovr_bin = decbin($owner_value_rec); //Convert value to binary

        //Compare the "executable" bit values for the group actual versus the recommended
        if (substr($ova_bin,-1,1)<=substr($ovr_bin,-1,1))
        {
            //The "execute" bit is the same or less as the recommended value
            $result = 1*$result;
        }else
        {
            //The "execute" bit is switched on for the actual value - meaning it is less secure
            $result = 0*$result;
        }

        //Compare the "write" bit values for the public actual versus the recommended
        if (substr($ova_bin,-2,1)<=substr($ovr_bin,-2,1))
        {
            //The "write" bit is the same or less as the recommended value
            $result = 1*$result;
        }else
        {
            //The "write" bit is switched on for the actual value - meaning it is less secure
            $result = 0*$result;
        }

        //Compare the "read" bit values for the public actual versus the recommended
        if (substr($ova_bin,-3,1)<=substr($ovr_bin,-3,1))
        {
            //The "read" bit is the same or less as the recommended value
            $result = 1*$result;
        }else
        {
            //The "read" bit is switched on for the actual value - meaning it is less secure
            $result = 0*$result;
        }

        return $result;
    }

    /*
     * Checks if a directory exists and creates one if it does not
     */
    static function create_dir($dirpath='')
    {
        $res = true;
        if ($dirpath != '')
        {
            //TODO - maybe add some checks to make sure someone is not passing a path with a filename, ie, something which has ".<extenstion>" at the end
            //$path_parts = pathinfo($dirpath);
            //$dirpath = $path_parts['dirname'] . '/' . $path_parts['basename'];
            if (!file_exists($dirpath))
            {
                $res = mkdir($dirpath, 0755);
            }
        }
        return $res;
    }

    static function get_attachment_id_from_url($attachment_url = '')
    {
        global $wpdb;
        $attachment_id = false;

        // If there is no url, return.
        if ('' == $attachment_url)return;

        // Get the upload directory paths
        $upload_dir_paths = wp_upload_dir();

        // Make sure the upload path base directory exists in the attachment URL, to verify that we're working with a media library image
        if (false !== strpos($attachment_url, $upload_dir_paths['baseurl'])) {
            // Remove the upload path base directory from the attachment URL
            $attachment_url = str_replace( $upload_dir_paths['baseurl'] . '/', '', $attachment_url );
            // Now run custom database query to get attachment ID from attachment URL
            $attachment_id = $wpdb->get_var( $wpdb->prepare( "SELECT wposts.ID FROM $wpdb->posts wposts, $wpdb->postmeta wpostmeta WHERE wposts.ID = wpostmeta.post_id AND wpostmeta.meta_key = '_wp_attached_file' AND wpostmeta.meta_value = '%s' AND wposts.post_type = 'attachment'", $attachment_url ) );
        }
        return $attachment_id;
    }


    /**
     * Will return an indexed array of files sorted by last modified timestamp
     * @param $dir
     * @param string $sort (ASC, DESC)
     * @return array|bool
     */
    static function scan_dir_sort_date($dir, $sort='DESC') {
        $files = array();
        foreach (scandir($dir) as $file) {
            $files[$file] = filemtime($dir . '/' . $file);
        }

        arsort($files);
        $files = array_keys($files);
        if($sort == 'ASC'){
            $files = array_reverse($files);
        }
        return ($files) ? $files : false;
    }



}
