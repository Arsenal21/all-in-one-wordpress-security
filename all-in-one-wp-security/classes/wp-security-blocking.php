<?php

class AIOWPSecurity_Blocking
{
    function __construct(){
        //NOP
    }

    /**
     * Will return an array of blocked IPs in the AIOWPSEC_TBL_PERM_BLOCK table
     * @param string $block_reason - spam, etc
     * @param string $output_type
     * @return single dimensional array
     */
    static function get_list_blocked_ips($block_reason='', $output_type='ARRAY_A')
    {
        global $wpdb;
        $blocked_ip_array = array();
        if(empty($block_reason)){
            $sql = 'SELECT blocked_ip FROM '.AIOWPSEC_TBL_PERM_BLOCK;
        }else{
            $sql = $wpdb->prepare('SELECT blocked_ip FROM '.AIOWPSEC_TBL_PERM_BLOCK.' WHERE block_reason=%s',$block_reason);
        }

        $result = $wpdb->get_results($sql,$output_type);
        //The result returned by wp function is multi-dim array. Let's return a simple single dimensional array of ip addresses
        if(!empty($result)){
            foreach($result as $item){
                $blocked_ip_array[] = $item['blocked_ip'];
            }
        }
        return $blocked_ip_array;
    }

    /**
     * Checks if an IP address is blocked permanently
     * @param $ip_address
     * @return bool
     */
    static function is_ip_blocked($ip_address)
    {
        global $wpdb;
        $blocked_record = $wpdb->get_row($wpdb->prepare('SELECT * FROM '.AIOWPSEC_TBL_PERM_BLOCK.' WHERE blocked_ip=%s', $ip_address));
        if(empty($blocked_record)){
            return false;
        }else{
            return true;
        }
    }

    /**
     * Will add an IP address to the permament block list
     * @param $ip_address
     * @param string $reason
     * @return bool - TRUE or FALSE on error
     */
    static function add_ip_to_block_list($ip_address, $reason='')
    {
        global $wpdb, $aio_wp_security;
        //Check if this IP address is already in the block list
        $blocked = AIOWPSecurity_Blocking::is_ip_blocked($ip_address);
        $time_now = current_time( 'mysql' );
        if(empty($blocked)){
            //Add this IP to the blocked table
            $data = array(
                'blocked_ip'=>$ip_address,
                'block_reason'=>$reason,
                'blocked_date'=>$time_now
            );
            $data = apply_filters('pre_add_to_permanent_block', $data);
            $res = $wpdb->insert(AIOWPSEC_TBL_PERM_BLOCK, $data);
            if($res === false){
                $aio_wp_security->debug_logger->log_debug("AIOWPSecurity_Blocking::add_ip_to_block_list - Error inserting record into AIOWPSEC_TBL_PERM_BLOCK table for IP ".$ip_address);
                return false;
            }
            return true;
        }
        return true;
    }

    static function unblock_ip($ip_address)
    {
        global $wpdb;
        $where = array('blocked_ip'=>$ip_address);
        $result = $wpdb->delete(AIOWPSEC_TBL_PERM_BLOCK,$where);
        return $result;
    }

    /**
     * Will check the current visitor IP against the blocked table
     * If IP present will block the visitor from viewing the site
     */
    static function check_visitor_ip_and_perform_blocking()
    {
        global $aio_wp_security, $wpdb;
        $visitor_ip = AIOWPSecurity_Utility_IP::get_user_ip_address();
        $ip_type = WP_Http::is_ip_address($visitor_ip);
        if(empty($ip_type)){
            $aio_wp_security->debug_logger->log_debug("do_general_ip_blocking_tasks: ".$visitor_ip." is not a valid IP!",4);
            return;
        }

        //Check if this IP address is in the block list
        $blocked = AIOWPSecurity_Blocking::is_ip_blocked($visitor_ip);
        //TODO - future feature: add blocking whitelist and check

        if(empty($blocked)){
            return; //Visitor IP is not blocked - allow page to load
        }else{
            //block this visitor!!
            AIOWPSecurity_Utility::redirect_to_url('http://127.0.0.1');
        }
        return;

    }

}