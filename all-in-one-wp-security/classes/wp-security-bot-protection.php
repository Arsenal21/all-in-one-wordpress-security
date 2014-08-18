<?php

/*
 * This class handles all bot related tasks and protection mechanisms.
 * 
 */

class AIOWPSecurity_Fake_Bot_Protection
{
    function __construct() 
    {
        //NOP
    }

    static function block_fake_googlebots()
    {
        $user_agent = (isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '');
        if (preg_match('/Googlebot/i', $user_agent, $matches)){
            //If user agent says it is googlebot start doing checks
            $ip = AIOWPSecurity_Utility_IP::get_user_ip_address();
            $name = gethostbyaddr($ip); //let's get the internet hostname using the given IP address
            //TODO - maybe add check if gethostbyaddr() fails 
            $host_ip = gethostbyname($name); //Reverse lookup - let's get the IP using the name
            if(preg_match('/Googlebot/i', $name, $matches)){
                if ($host_ip == $ip){
                    //Genuine googlebot allow it through....
                }else{
                    //fake googlebot - block it!
                    exit();
                }
            }else{
                //fake googlebot - block it!
                exit();
            }
        }
    }
    
}