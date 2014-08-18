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
        /* -- Ordering parameters -- */
	//Parameters that are going to be used to order the result
	$orderby = !empty($_GET["orderby"]) ? mysql_real_escape_string($_GET["orderby"]) : 'user_id';
	$order = !empty($_GET["order"]) ? mysql_real_escape_string($_GET["order"]) : 'DESC';

        $logged_in_users = (AIOWPSecurity_Utility::is_multisite_install() ? get_site_transient('users_online') : get_transient('users_online'));
        
        foreach ($logged_in_users as $key=>$val)
        {
            $userdata = get_userdata($val['user_id']);
            $username = $userdata->user_login;
            $val['username'] = $username;
            $logged_in_users[$key] = $val;
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