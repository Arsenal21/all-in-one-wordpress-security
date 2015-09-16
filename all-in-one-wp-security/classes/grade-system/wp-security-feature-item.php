<?php

class AIOWPSecurity_Feature_Item
{
    var $feature_id;//Example "user-accounts-tab1-change-admin-user"
    var $feature_name;
    var $item_points;
    var $security_level;//1, 2 or 3
    
    var $feature_status;//active, inactive, partial
    
    function __construct($feature_id,$feature_name,$item_points,$security_level){
        $this->feature_id = $feature_id;
        $this->feature_name = $feature_name;
        $this->item_points = $item_points;
        $this->security_level = $security_level;
    }
    
    function set_feature_status($status)
    {
        $this->feature_status = $status;
    }
    
    function get_security_level_string($level)
    {
        $level_string = "";
        if($level == "1"){
            $level_string = __('Basic', 'all-in-one-wp-security-and-firewall');
        }
        else if($level == "2"){
            $level_string = __('Intermediate', 'all-in-one-wp-security-and-firewall');
        }
        else if($level == "3"){
            $level_string = __('Advanced', 'all-in-one-wp-security-and-firewall');
        }
        return $level_string;
    }
    
}

