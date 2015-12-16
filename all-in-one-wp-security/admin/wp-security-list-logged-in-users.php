<?php

class AIOWPSecurity_List_Logged_In_Users extends AIOWPSecurity_List_Table {

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
        
    function column_user_id($item){
        $tab = strip_tags($_REQUEST['tab']);
        $force_logout_url = sprintf('admin.php?page=%s&tab=%s&action=%s&logged_in_id=%s&ip_address=%s', AIOWPSEC_USER_LOGIN_MENU_SLUG, $tab, 'force_user_logout', $item['user_id'], $item['ip_address']);
        //Add nonce to URL
        $force_logout_nonce = wp_nonce_url($force_logout_url, "force_user_logout", "aiowps_nonce");
        
        //Build row actions
        $actions = array(
            'logout' => '<a href="'.$force_logout_nonce.'" onclick="return confirm(\'Are you sure you want to force this user to be logged out of this session?\')">Force Logout</a>',
        );
        
        //Return the user_login contents
        return sprintf('%1$s <span style="color:silver"></span>%2$s',
            /*$1%s*/ $item['user_id'],
            /*$2%s*/ $this->row_actions($actions)
        );
    }
   
    function get_columns(){
        $columns = array(
            'user_id' => 'User ID',
            'username' => 'Login Name',
            'ip_address' => 'IP Address',
        );
        return $columns;
    }
    
    function get_sortable_columns() {
        $sortable_columns = array(
            'user_id' => array('user_id',false),
            'username' => array('username',false),
            'ip_address' => array('ip_address',false),
        );
        return $sortable_columns;
    }
    
    function get_bulk_actions() {
        return array();
    }

    function process_bulk_action() {
    }
    
    /*
     * This function will force a selected user to be logged out.
     * The function accepts either an array of IDs or a single ID (TODO - bulk actions not implemented yet!)
     */
    function force_user_logout($user_id, $ip_addr)
    {
        global $wpdb, $aio_wp_security;
        if (is_array($user_id))
        {
            if (isset($_REQUEST['_wp_http_referer']))
            {
                //TODO - implement bulk action in future release!
            }
        } 
        elseif ($user_id != NULL)
        {
            $nonce=isset($_GET['aiowps_nonce'])?$_GET['aiowps_nonce']:'';
            if (!isset($nonce) ||!wp_verify_nonce($nonce, 'force_user_logout'))
            {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed for force user logout operation!",4);
                die(__('Nonce check failed for force user logout operation!','all-in-one-wp-security-and-firewall'));
            }
            //Force single user logout
            $user_id = absint($user_id);
            $manager = WP_Session_Tokens::get_instance( $user_id );
            $manager->destroy_all();
            //
            $aio_wp_security->user_login_obj->update_user_online_transient($user_id, $ip_addr);
//            if($result != NULL)
//            {
                $success_msg = '<div id="message" class="updated fade"><p><strong>';
                $success_msg .= __('The selected user was logged out successfully!','all-in-one-wp-security-and-firewall');
                $success_msg .= '</strong></p></div>';
                _e($success_msg);
//            }
        }
    }
    
    
    function prepare_items() {
        //First, lets decide how many records per page to show
        $per_page = 20;
        $columns = $this->get_columns();
        $hidden = array();
        $sortable = $this->get_sortable_columns();

        $this->_column_headers = array($columns, $hidden, $sortable);
        
        //$this->process_bulk_action();
    	
    	global $wpdb;
        global $aio_wp_security;

        $logged_in_users = (AIOWPSecurity_Utility::is_multisite_install() ? get_site_transient('users_online') : get_transient('users_online'));
        if($logged_in_users !== FALSE){
            foreach ($logged_in_users as $key=>$val)
            {
                $userdata = get_userdata($val['user_id']);
                $username = $userdata->user_login;
                $val['username'] = $username;
                $logged_in_users[$key] = $val;
            }
        }else{
            $logged_in_users = array(); //If no transient found set to empty array
        }
        $data = $logged_in_users;
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
}