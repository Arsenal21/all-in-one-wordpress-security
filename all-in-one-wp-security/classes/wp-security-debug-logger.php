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
    
    function __construct()
    {
        $this->log_folder_path = AIO_WP_SECURITY_PATH . '/logs';
    }
    
    function get_debug_timestamp()
    {
        return '['.date('m/d/Y g:i A').'] - ';
    }
    
    function get_debug_status($level)
    {
        $size = count($this->debug_status);
        if($level >= $size){
            return 'UNKNOWN';
        }
        else{
            return $this->debug_status[$level];
        }
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
        global $aio_wp_security;
        $debug_config = $aio_wp_security->configs->get_value('aiowps_enable_debug');
        $this->debug_enabled = empty($debug_config)?false:true;

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
        global $aio_wp_security;
        $debug_config = $aio_wp_security->configs->get_value('aiowps_enable_debug');
        $this->debug_enabled = empty($debug_config)?false:true;

        if (!$this->debug_enabled) return;
        $content = $this->get_debug_timestamp();//Timestamp
        $content .= $this->get_debug_status($level);//Debug status
        $content .= ' : ';
        $content .= $message . "\n";
        $content .= $this->get_section_break($section_break);
        //$file_name = $this->default_log_file_cron;
        $this->append_to_file($content, $this->default_log_file_cron);
    }
    
    //TODO - this function need to be completed
    static function log_debug_st($message,$level=0,$section_break=false,$file_name='')
    {
        $content = "\n". $message . "\n";
        $debug_log_file = 'wp-security-log-static.txt';
        //$debug_log_file =  AIO_WP_SECURITY_PATH .'/wp-security-log.txt';
        $fp=fopen($debug_log_file,'a');
        fwrite($fp, $content);
        fclose($fp);
    }
}