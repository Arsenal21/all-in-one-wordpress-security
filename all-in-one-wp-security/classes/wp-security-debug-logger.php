<?php
/* 
 * Logs debug data to a file. Here is an example usage
 * global $aio_wp_security;
 * $aio_wp_security->debug_logger->log_debug("Log messaged goes here");
 */
class AIOWPSecurity_Logger
{
    var $log_folder_path;
    var $default_log_file = 'wp-security-log.txt';
    var $default_log_file_cron = 'wp-security-log-cron-job.txt';
    var $debug_enabled = false;
    var $debug_status = array('SUCCESS','STATUS','NOTICE','WARNING','FAILURE','CRITICAL');
    var $section_break_marker = "\n----------------------------------------------------------\n\n";
    var $log_reset_marker = "-------- Log File Reset --------\n";

    /**
     * @param bool $debug_enabled Should the logger log anything?
     */
    function __construct($debug_enabled)
    {
        $this->debug_enabled = $debug_enabled;
        $this->log_folder_path = WP_CONTENT_DIR . '/aiowps_logs';
        if ( $debug_enabled ) {
            $this->prepare_log_dir();
        }
    }

    function prepare_log_dir() {
        if ( !is_dir($this->log_folder_path) ) {
            @mkdir($this->log_folder_path, 0775);
            @chmod($this->log_folder_path, 0775);
            // Forbid direct access to folder contents
            $htaccess = $this->log_folder_path . '/.htaccess';
            @file_put_contents($htaccess, <<<APACHE
<IfModule !mod_authz_core.c>
    Order deny,allow
    Deny from all
</IfModule>
<IfModule mod_authz_core.c>
    Require all denied
</IfModule>
APACHE
            );
            @chmod($htaccess, 0664);
            // Prevent directory listing
            $index = $this->log_folder_path . '/index.html';
            @file_put_contents($index, '');
            @chmod($index, 0664);
        }
    }

    function is_valid_log_file($filename) {
        return $filename === $this->default_log_file || $filename === $this->default_log_file_cron;
    }
    
    function get_debug_timestamp()
    {
        return '['.date('m/d/Y g:i A').'] - ';
    }
    
    function get_debug_status($level)
    {
        return isset($this->debug_status[$level]) ? $this->debug_status[$level] : 'UNKNOWN';
    }
    
    function get_section_break($section_break)
    {
        if ($section_break) {
            return $this->section_break_marker;
        }
        return "";
    }
    
    function append_to_file($content,$file_name)
    {
        if(empty($file_name))$file_name = $this->default_log_file;
        $debug_log_file = $this->log_folder_path.'/'.$file_name;
        $fp=fopen($debug_log_file,'a');
        fwrite($fp, $content);
        fclose($fp);
    }
    
    function reset_log_file($file_name='')
    {
        if(empty($file_name))$file_name = $this->default_log_file;
        $debug_log_file = $this->log_folder_path.'/'.$file_name;
        $content = $this->get_debug_timestamp().$this->log_reset_marker;
        $fp=fopen($debug_log_file,'w');
        fwrite($fp, $content);
        fclose($fp);
    }

    function log_debug($message,$level=0,$section_break=false,$file_name='')
    {
        if (!$this->debug_enabled) return;
        $content = $this->get_debug_timestamp();//Timestamp
        $content .= $this->get_debug_status($level);//Debug status
        $content .= ' : ';
        $content .= $message . "\n";
        $content .= $this->get_section_break($section_break);
        $this->append_to_file($content, $file_name);
    }

    function log_debug_cron($message,$level=0,$section_break=false)
    {
        $this->log_debug($message, $level, $section_break, $this->default_log_file_cron);
    }

}