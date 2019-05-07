<?php
if(!defined('ABSPATH')){
    exit;//Exit if accessed directly
}

class AIOWPSecurity_Utility_IP
{
    function __construct(){
        //NOP
    }
    
    static function get_user_ip_address()
    {
        global $aio_wp_security;

        //check if user configured custom IP retrieval method
        $ip_method = $aio_wp_security->configs->get_value('aiowps_ip_retrieve_method');
        $visitor_ip = ''; //set default
        if(!empty($ip_method)){
            //means user has configured non default IP retrieval
            if($ip_method == 1 && !empty($_SERVER['HTTP_CF_CONNECTING_IP'])){
                $visitor_ip = $_SERVER['HTTP_CF_CONNECTING_IP'];
            }else if($ip_method == 2 && !empty($_SERVER['HTTP_X_FORWARDED_FOR'])){
                $visitor_ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
            }else if($ip_method == 3 && !empty($_SERVER['HTTP_X_FORWARDED'])){
                $visitor_ip = $_SERVER['HTTP_X_FORWARDED'];
            }else if($ip_method == 4 && !empty($_SERVER['HTTP_CLIENT_IP'])){
                $visitor_ip = $_SERVER['HTTP_CLIENT_IP'];
            }
        }
        
        //Check if multiple IPs were given - these will be present as comma-separated list
        
        if(stristr($visitor_ip, ',')){
            $visitor_ip = trim(reset((explode(',', $visitor_ip)))); //get first address because this will likely be the original connecting IP
        }
        
        //Now remove port portion if applicable
        if(strpos($visitor_ip, '.') !== FALSE && strpos($visitor_ip, ':') !== FALSE){
            //likely ipv4 address with port
            $visitor_ip = preg_replace('/:\d+$/', '', $visitor_ip); //Strip off port
        }

        if(filter_var($visitor_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {    
            return $visitor_ip;
        }else if(filter_var($visitor_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)){
            return $visitor_ip;
        }else{
            $visitor_ip = !empty($_SERVER['REMOTE_ADDR'])?$_SERVER['REMOTE_ADDR']:'';
            return $visitor_ip;
        }
    }
    
     /*
     * Returns the first three octets of a sanitized IP address so it can used as an IP address range
     */
    static function get_sanitized_ip_range($ip)
    {
        global $aio_wp_security;
        $ip_range = '';
        $valid_ip = filter_var($ip, FILTER_VALIDATE_IP); //Sanitize the IP address
        if ($valid_ip)
        {
            $ip_type = WP_Http::is_ip_address($ip); //returns 4 or 6 if ipv4 or ipv6 or false if invalid
            if($ip_type == 6 || $ip_type === false) return ''; // for now return empty if ipv6 or invalid IP
            $ip_range = substr($valid_ip, 0 , strrpos ($valid_ip, ".")); //strip last portion of address to leave an IP range
        }
        else
        {
            //Write log if the 'REMOTE_ADDR' contains something which is not an IP
            $aio_wp_security->debug_logger->log_debug("AIOWPSecurity_Utility_IP - Invalid IP received ".$ip,4);
        }
        return $ip_range;
    }

    
    static function create_ip_list_array_from_string_with_newline($ip_addresses)
    {
        $ip_list_array = preg_split("/\R/", $ip_addresses);
        return $ip_list_array;
    }
    
    static function validate_ip_list($ip_list_array, $list_type='')
    {
        @ini_set('auto_detect_line_endings', true);
        $errors = '';

        //validate list
        $submitted_ips = $ip_list_array;
        $list = array();

        if(!empty($submitted_ips))
        {
            foreach($submitted_ips as $item) 
            {
                $item = filter_var($item, FILTER_SANITIZE_STRING);
                if (strlen( $item ) > 0) 
                {
                    //ipv6 - for now we will support only whole ipv6 addresses, NOT ranges
                    if(strpos($item, ':') !== false){
                        //possible ipv6 addr
                        $res = WP_Http::is_ip_address($item);
                        if(FALSE === $res){
                            $errors .= "\n".$item.__(' is not a valid ip address format.', 'all-in-one-wp-security-and-firewall');
                        }else if($res == '6'){
                            $list[] = trim($item);
                        }
                        continue;
                    }

                    $ipParts = explode('.', $item);
                    $isIP = 0;
                    $partcount = 1;
                    $goodip = true;
                    $foundwild = false;
                    
                    if (count($ipParts) < 2)
                    {
                        $errors .= "\n".$item.__(' is not a valid ip address format.', 'all-in-one-wp-security-and-firewall');
                        continue;
                    }

                    foreach ($ipParts as $part) 
                    {
                        if ($goodip == true) 
                        {
                            if ((is_numeric(trim($part)) && trim($part) <= 255 && trim($part) >= 0) || trim($part) == '*') 
                            {
                                $isIP++;
                            }

                            switch ($partcount) 
                            {
                                case 1:
                                    if (trim($part) == '*') 
                                    {
                                        $goodip = false;
                                        $errors .= "\n".$item.__(' is not a valid ip address format.', 'all-in-one-wp-security-and-firewall');
                                    }
                                    break;
                                case 2:
                                    if (trim($part) == '*')
                                    {
                                        $foundwild = true;
                                    }
                                    break;
                                default:
                                    if (trim($part) != '*') 
                                    {
                                        if ($foundwild == true) 
                                        {
                                            $goodip = false;
                                            $errors .= "\n".$item.__(' is not a valid ip address format.', 'all-in-one-wp-security-and-firewall');
                                        }
                                    }
                                    else 
                                    {
                                        $foundwild = true;	
                                    }
                                    break;
                            }

                            $partcount++;
                        }
                    }
                    if (ip2long(trim(str_replace('*', '0', $item))) == false) 
                    { //invalid ip 
                        $errors .= "\n".$item.__(' is not a valid ip address format.', 'all-in-one-wp-security-and-firewall');
                    } 
                    elseif (strlen($item) > 4 && !in_array($item, $list)) 
                    {
                        $current_user_ip = AIOWPSecurity_Utility_IP::get_user_ip_address();
                        if ($current_user_ip == $item && $list_type == 'blacklist')
                        {
                            //You can't ban your own IP
                            $errors .= "\n".__('You cannot ban your own IP address: ', 'all-in-one-wp-security-and-firewall').$item;
                        }
                        else
                        {
                            $list[] = trim($item);
                        }
                    }
                }
            }
        }
        else{
            //This function was called with an empty IP address array list
        }

        if (strlen($errors)> 0)
        {
            $return_payload = array(-1, array($errors));
            return $return_payload;
        }
        
        if (sizeof($list) >= 1) 
        {
            sort($list);
            $list = array_unique($list, SORT_STRING);
            
            $return_payload = array(1, $list);
            return $return_payload;
	}

        $return_payload = array(1, array());
        return $return_payload;
    }
    
    
    /**
     * Checks if IP address matches against the specified whitelist of IP addresses or IP ranges
     * @global type $aio_wp_security
     * @param type $ip_address
     * @param type $whitelisted_ips (newline separated string of IPs)
     * @return boolean
     */
    static function is_ip_whitelisted($ip_address, $whitelisted_ips){
        global $aio_wp_security;
        if(empty($ip_address) || empty($whitelisted_ips)) return false;
        
        $ip_list_array = AIOWPSecurity_Utility_IP::create_ip_list_array_from_string_with_newline($whitelisted_ips);
        
        if(empty($ip_list_array)) return false;
        
        $visitor_ipParts = explode('.', $ip_address);
        foreach ($ip_list_array as $white_ip){
            $ipParts = explode('.', $white_ip);
            $found = array_search('*', $ipParts);
            if($found !== false){
                //Means we have a whitelisted IP range so do some checks
                if($found == 1){
                    //means last 3 octets are wildcards - check if visitor IP falls inside this range
                    if($visitor_ipParts[0] == $ipParts[0]){return true;}
                }elseif($found == 2){
                    //means last 2 octets are wildcards - check if visitor IP falls inside this range
                    if($visitor_ipParts[0] == $ipParts[0] && $visitor_ipParts[1] == $ipParts[1]){return true;}
                }elseif($found == 3){
                    //means last octet is wildcard - check if visitor IP falls inside this range
                    if($visitor_ipParts[0] == $ipParts[0] && $visitor_ipParts[1] == $ipParts[1] && $visitor_ipParts[2] == $ipParts[2]){return true;}
                }
            }elseif($white_ip == $ip_address){
                return true;
            }
        }
        return false;
    }

}