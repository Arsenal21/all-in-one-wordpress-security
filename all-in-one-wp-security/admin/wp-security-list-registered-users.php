<?php

class AIOWPSecurity_List_Registered_Users extends AIOWPSecurity_List_Table {

    function __construct(){
        global $status, $page;
                
        //Set parent defaults
        parent::__construct( array(
            'singular'  => 'item',     //singular name of the listed records
            'plural'    => 'items',    //plural name of the listed records
            'ajax'      => false        //does this table support ajax?
        ) );
        
    }

    function column_default($item, $column_name){
    	return $item[$column_name];
    }

    function column_ID($item){
        //$tab = strip_tags($_REQUEST['tab']);
        $delete_url = sprintf('admin.php?page=%s&action=%s&user_id=%s', AIOWPSEC_USER_REGISTRATION_MENU_SLUG, 'delete_acct', $item['ID']);
        //Add nonce to delete URL
        $delete_url_nonce = wp_nonce_url($delete_url, "delete_user_acct", "aiowps_nonce");

        $block_ip = sprintf('admin.php?page=%s&action=%s&ip_address=%s', AIOWPSEC_USER_REGISTRATION_MENU_SLUG, 'block_ip', $item['ip_address']);
        //Add nonce to block IP
        $block_ip_nonce = wp_nonce_url($block_ip, "block_ip", "aiowps_nonce");

        //Build row actions
        $actions = array(
            'view' => sprintf('<a href="user-edit.php?user_id=%s" target="_blank">View</a>',$item['ID']),
            'approve_acct' => sprintf('<a href="admin.php?page=%s&action=%s&user_id=%s" onclick="return confirm(\'Are you sure you want to approve this account?\')">Approve</a>',AIOWPSEC_USER_REGISTRATION_MENU_SLUG,'approve_acct',$item['ID']),
            'delete_acct' => '<a href="'.$delete_url_nonce.'" onclick="return confirm(\'Are you sure you want to delete this account?\')">Delete</a>',
            'block_ip' => '<a href="'.$block_ip_nonce.'" onclick="return confirm(\'Are you sure you want to block this IP address?\')">Block IP</a>',
        );
        
        //Return the user_login contents
        return sprintf('%1$s <span style="color:silver"></span>%2$s',
            /*$1%s*/ $item['ID'],
            /*$2%s*/ $this->row_actions($actions)
        );
    }

    function column_ip_address($item){
        if (AIOWPSecurity_Blocking::is_ip_blocked($item['ip_address'])){
            return $item['ip_address'].'<br /><span class="aiowps-label aiowps-label-success">'.__('blocked','WPS').'</span>';
        } else{
            return $item['ip_address'];
        }
    }

    function column_cb($item){
        return sprintf(
            '<input type="checkbox" name="%1$s[]" value="%2$s" />',
            /*$1%s*/ $this->_args['singular'],  //Let's simply repurpose the table's singular label
            /*$2%s*/ $item['ID']                //The value of the checkbox should be the record's id
       );
    }
    
   
    function get_columns(){
        $columns = array(
            'cb' => '<input type="checkbox" />', //Render a checkbox
            'ID' => 'User ID',
            'user_login' => 'Login Name',
            'user_email' => 'Email',
            'user_registered' => 'Register Date',
            'account_status' => 'Account Status',
            'ip_address' => 'IP Address'
        );
        return $columns;
    }
    
    function get_sortable_columns() {
        $sortable_columns = array(
//            'ID' => array('ID',false),
//            'user_login' => array('user_login',false),
//            'user_email' => array('user_email',false),
//            'user_registered' => array('user_registered',false),
//            'account_status' => array('account_status',false),
        );
        return $sortable_columns;
    }
    
    function get_bulk_actions() {
        $actions = array(
            'approve' => 'Approve',
            'delete' => 'Delete',
            'block' => 'Block IP'
        );
        return $actions;
    }

    function process_bulk_action() {
        if('approve'===$this->current_action()) 
        {//Process approve bulk actions
            if(!isset($_REQUEST['item']))
            {
                AIOWPSecurity_Admin_Menu::show_msg_error_st(__('Please select some records using the checkboxes','all-in-one-wp-security-and-firewall'));
            }else 
            {            
                $this->approve_selected_accounts(($_REQUEST['item']));
            }
        }
        
        if('delete'===$this->current_action()) 
        {//Process delete bulk actions
            if(!isset($_REQUEST['item']))
            {
                AIOWPSecurity_Admin_Menu::show_msg_error_st(__('Please select some records using the checkboxes','all-in-one-wp-security-and-firewall'));
            }else 
            {            
                $this->delete_selected_accounts(($_REQUEST['item']));
            }
        }

        if('block'===$this->current_action())
        {//Process block bulk actions
            if(!isset($_REQUEST['item']))
            {
                AIOWPSecurity_Admin_Menu::show_msg_error_st(__('Please select some records using the checkboxes','all-in-one-wp-security-and-firewall'));
            }else
            {
                $this->block_selected_ips(($_REQUEST['item']));
            }
        }

    }

    function approve_selected_accounts($entries)
    {
        global $wpdb, $aio_wp_security;
        $meta_key = 'aiowps_account_status';
        $meta_value = 'approved'; //set account status
        $failed_accts = ''; //string to store comma separated accounts which failed to update
        $at_least_one_updated = false;
        if (is_array($entries))
        {
            //Let's go through each entry and approve
            foreach($entries as $user_id)
            {
                $result = update_user_meta($user_id, $meta_key, $meta_value);
                if($result === false)
                {
                    $failed_accts .= ' '.$user_id.',';
                    $aio_wp_security->debug_logger->log_debug("AIOWPSecurity_List_Registered_Users::approve_selected_accounts() - could not approve account ID: $user_id",4);
                }else{
                    $at_least_one_updated = true;
                    $user = get_user_by('id', $user_id);
                    if($user === false){
                        //don't send mail
                    }else{
                        $email_msg = '';
                        $to_email_address = $user->user_email;
                        $subject = '['.get_option('siteurl').'] '. __('Your account is now active','all-in-one-wp-security-and-firewall');
                        $email_msg .= __('Your account with user ID:','all-in-one-wp-security-and-firewall').$user->ID.__(' is now active','all-in-one-wp-security-and-firewall')."\n";
                        $site_title = get_bloginfo( 'name' );
                        $from_name = empty($site_title)?'WordPress':$site_title;
                        $email_header = 'From: '.$from_name.' <'.get_bloginfo('admin_email').'>' . "\r\n\\";
                        $sendMail = wp_mail($to_email_address, $subject, $email_msg, $email_header);
                        if(FALSE === $sendMail){
                            $aio_wp_security->debug_logger->log_debug("Manual account approval notification email failed to send to ".$to_email_address,4);
                        }

                    }
                }
            }
            if ($at_least_one_updated){
                AIOWPSecurity_Admin_Menu::show_msg_updated_st(__('The selected accounts were approved successfully!','all-in-one-wp-security-and-firewall'));
            }
            if ($failed_accts != ''){//display any failed account updates
                rtrim($failed_accts);
                AIOWPSecurity_Admin_Menu::show_msg_error_st(__('The following accounts failed to update successfully: ','all-in-one-wp-security-and-firewall').$failed_accts);
            }
        } elseif ($entries != NULL)
        {
            //Approve single account
            $result = update_user_meta($entries, $meta_key, $meta_value);
            if($result)
            {
                AIOWPSecurity_Admin_Menu::show_msg_updated_st(__('The selected account was approved successfully!','all-in-one-wp-security-and-firewall'));
                $user = get_user_by('id', $entries);
                $to_email_address = $user->user_email;
                $email_msg = '';
                $subject = '['.get_option('siteurl').'] '. __('Your account is now active','all-in-one-wp-security-and-firewall');
                $email_msg .= __('Your account with username: ','all-in-one-wp-security-and-firewall').$user->user_login.__(' is now active','all-in-one-wp-security-and-firewall')."\n";
                $site_title = get_bloginfo( 'name' );
                $from_name = empty($site_title)?'WordPress':$site_title;
                $email_header = 'From: '.$from_name.' <'.get_bloginfo('admin_email').'>' . "\r\n\\";
                $sendMail = wp_mail($to_email_address, $subject, $email_msg, $email_header);
                if(FALSE === $sendMail){
                    $aio_wp_security->debug_logger->log_debug("Manual account approval notification email failed to send to ".$to_email_address,4);
                }

                
            }else if($result === false){
                $aio_wp_security->debug_logger->log_debug("AIOWPSecurity_List_Registered_Users::approve_selected_accounts() - could not approve account ID: $user_id",4);
            }
        }
    }

    function delete_selected_accounts($entries)
    {
        global $wpdb, $aio_wp_security;
        if (is_array($entries))
        {
            if (isset($_REQUEST['_wp_http_referer']))
            {
                //Let's go through each entry and delete account
                foreach($entries as $user_id)
                {
                    $result = wp_delete_user($user_id);
                    if($result !== true)
                    {
                        $aio_wp_security->debug_logger->log_debug("AIOWPSecurity_List_Registered_Users::delete_selected_accounts() - could not delete account ID: $user_id",4);
                    }
                }
                AIOWPSecurity_Admin_Menu::show_msg_updated_st(__('The selected accounts were deleted successfully!','all-in-one-wp-security-and-firewall'));
            }
        } elseif ($entries != NULL)
        {
            $nonce=isset($_GET['aiowps_nonce'])?$_GET['aiowps_nonce']:'';
            if (!isset($nonce) ||!wp_verify_nonce($nonce, 'delete_user_acct'))
            {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed for delete registered user account operation!",4);
                die(__('Nonce check failed for delete registered user account operation!','all-in-one-wp-security-and-firewall'));
            }
            
            //Delete single account

            $result = wp_delete_user($entries);
            if($result === true)
            {
                AIOWPSecurity_Admin_Menu::show_msg_updated_st(__('The selected account was deleted successfully!','all-in-one-wp-security-and-firewall'));
            }
            else
            {
                $aio_wp_security->debug_logger->log_debug("AIOWPSecurity_List_Registered_Users::delete_selected_accounts() - could not delete account ID: $entries",4);
            }
        }
    }

    function block_selected_ips($entries)
    {
        global $wpdb, $aio_wp_security;
        if (is_array($entries))
        {
            if (isset($_REQUEST['_wp_http_referer']))
            {
                //Let's go through each entry and block IP
                foreach($entries as $id)
                {
                    $ip_address = get_user_meta($id, 'aiowps_registrant_ip', true);
                    $result = AIOWPSecurity_Blocking::add_ip_to_block_list($ip_address, 'registration_spam');
                    if($result === false)
                    {
                        $aio_wp_security->debug_logger->log_debug("AIOWPSecurity_List_Registered_Users::block_selected_ips() - could not block IP : $ip_address",4);
                    }
                }
                $msg = __('The selected IP addresses were successfully added to the permanent block list!','all-in-one-wp-security-and-firewall');
                $msg .= ' <a href="admin.php?page='.AIOWPSEC_MAIN_MENU_SLUG.'&tab=tab4" target="_blank">'.__('View Blocked IPs','all-in-one-wp-security-and-firewall').'</a>';
                AIOWPSecurity_Admin_Menu::show_msg_updated_st($msg);
            }
        } elseif ($entries != NULL)
        {
            $nonce=isset($_GET['aiowps_nonce'])?$_GET['aiowps_nonce']:'';
            if (!isset($nonce) ||!wp_verify_nonce($nonce, 'block_ip'))
            {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed for block IP operation of registered user!",4);
                die(__('Nonce check failed for block IP operation of registered user!','all-in-one-wp-security-and-firewall'));
            }

            //Block single IP
            $result = AIOWPSecurity_Blocking::add_ip_to_block_list($entries, 'registration_spam');
            if($result === true)
            {
                $msg = __('The selected IP was successfully added to the permanent block list!','all-in-one-wp-security-and-firewall');
                $msg .= ' <a href="admin.php?page='.AIOWPSEC_MAIN_MENU_SLUG.'&tab=tab4" target="_blank">'.__('View Blocked IPs','all-in-one-wp-security-and-firewall').'</a>';
                AIOWPSecurity_Admin_Menu::show_msg_updated_st($msg);
            }
            else
            {
                $aio_wp_security->debug_logger->log_debug("AIOWPSecurity_List_Registered_Users::block_selected_ips() - could not block IP: $entries",4);
            }
        }
    }

    function prepare_items() {
        //First, lets decide how many records per page to show
        $per_page = 20;
        $columns = $this->get_columns();
        $hidden = array();
        $sortable = $this->get_sortable_columns();

        $this->_column_headers = array($columns, $hidden, $sortable);
        
        $this->process_bulk_action();
    	
        //Get registered users which have the special 'aiowps_account_status' meta key set to 'pending'
        $data = $this->get_registered_user_data('pending');
        
        $current_page = $this->get_pagenum();
        $total_items = count($data);
        $data = array_slice($data,(($current_page-1)*$per_page),$per_page);
        $this->items = $data;
        $this->set_pagination_args( array(
            'total_items' => $total_items,                  //WE have to calculate the total number of items
            'per_page'    => $per_page,                     //WE have to determine how many items to show on a page
            'total_pages' => ceil($total_items/$per_page)   //WE have to calculate the total number of pages
        ));
    }
    
    //Returns all users who have the special 'aiowps_account_status' meta key
    function get_registered_user_data($status='')
    {
        $user_fields = array( 'ID', 'user_login', 'user_email', 'user_registered');
        $user_query = new WP_User_Query(array('meta_key' => 'aiowps_account_status', 'meta_value' => $status, 'fields' => $user_fields));
        $user_results = $user_query->results;

        $final_data = array();
        foreach ($user_results as $user)
        {
            $temp_array = get_object_vars($user); //Turn the object into array
            $temp_array['account_status'] = get_user_meta($temp_array['ID'], 'aiowps_account_status', true);
            $ip = get_user_meta($temp_array['ID'], 'aiowps_registrant_ip', true);
            $temp_array['ip_address'] = empty($ip)?'':$ip;
            $final_data[] = $temp_array;
        }
        return $final_data;
    }
}