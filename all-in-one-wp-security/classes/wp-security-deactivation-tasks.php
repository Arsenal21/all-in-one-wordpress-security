<?php

class AIOWPSecurity_Deactivation
{
    static function run_deactivation_tasks()
    {	
        global $wpdb;
        if (function_exists('is_multisite') && is_multisite()) 
        {
            // check if it is a network activation - if so, run the activation function for each blog id
            if (isset($_GET['networkwide']) && ($_GET['networkwide'] == 1)) 
            {
                $old_blog = $wpdb->blogid;
                // Get all blog ids
                $blogids = $wpdb->get_col("SELECT blog_id FROM $wpdb->blogs");
                foreach ($blogids as $blog_id) {
                    switch_to_blog($blog_id);
                }
                switch_to_blog($old_blog);
                return;
            }
        }

        //Let's backup .htaccess contents when AIOWPS was active
        $ht_file = ABSPATH . '.htaccess';
        $key_desc_ht_backup = 'aiowps_htaccess_backup'; //This will be the key to decribe the entry we are inserting into the global_meta table
        AIOWPSecurity_Utility_File::backup_file_contents_to_db($ht_file, $key_desc_ht_backup); //Store the original htaccess contents in our global_meta table (ie, before AIOWPS was active) 

        //Let's backup wp_config.php contents
        $wp_config_file = ABSPATH . 'wp-config.php';
        $key_desc_wp_config_backup = 'aiowps_wp_config_php_backup'; //This will be the key to decribe the entry we are inserting into the global_meta table
        AIOWPSecurity_Utility_File::backup_file_contents_to_db($wp_config_file, $key_desc_wp_config_backup); //Store the original htaccess contents in our global_meta table (ie, before AIOWPS was active)
        
        //Restore original contents of .htaccess file upon deactivation
        $htaccess_file_contents = AIOWPSecurity_Deactivation::get_original_file_contents('original_htaccess_backup');
        if ($htaccess_file_contents)
        {
            if (file_put_contents($ht_file, $htaccess_file_contents) === false)
            {
                //File write failed
                $aio_wp_security->debug_logger->log_debug("AIOWPSecurity_Deactivation::run_deactivation_tasks() - Failed to write to .htaccess file",4);
            }
        }
        
        //Restore original contents of wp-config.php file upon deactivation
        $wp_config_file_contents = AIOWPSecurity_Deactivation::get_original_file_contents('original_wp_config_php_backup');
        if ($wp_config_file_contents)
        {
            if (file_put_contents($wp_config_file, $wp_config_file_contents) === false)
            {
                //File write failed
                $aio_wp_security->debug_logger->log_debug("AIOWPSecurity_Deactivation::run_deactivation_tasks() - Failed to write to wp-config.php file",4);
            }
        }
    }
    
    static function get_original_file_contents($key_description)
    {
        global $wpdb;
        $aiowps_global_meta_tbl_name = AIOWPSEC_TBL_GLOBAL_META_DATA;
        $resultset = $wpdb->get_row("SELECT * FROM $aiowps_global_meta_tbl_name WHERE meta_key1 = '$key_description'", OBJECT);
        if($resultset){
            $file_contents = maybe_unserialize($resultset->meta_value2);
            return $file_contents;
        }
        else
        {
            return false;
        }
    }
}
