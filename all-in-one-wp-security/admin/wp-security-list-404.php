<?php
class AIOWPSecurity_List_404 extends AIOWPSecurity_List_Table {
    
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
        
    function column_id($item){
        $tab = strip_tags($_REQUEST['tab']);
        $ip = $item['ip_or_host'];
        
        $blocked_ips_tab = 'tab3';
        //Check if this IP address is locked
        $is_locked = AIOWPSecurity_Utility::check_locked_ip($ip);
        if($is_locked){
            //Build row actions
            $actions = array(
                'unblock' => sprintf('<a href="admin.php?page=%s&tab=%s">Unblock</a>',AIOWPSEC_MAIN_MENU_SLUG,$blocked_ips_tab),
                'delete' => sprintf('<a href="admin.php?page=%s&tab=%s&action=%s&id=%s" onclick="return confirm(\'Are you sure you want to delete this item?\')">Delete</a>',AIOWPSEC_FIREWALL_MENU_SLUG,$tab,'delete_event_log',$item['id']),
            );
            
        }else{
            //Build row actions
            $actions = array(
                'temp_block' => sprintf('<a href="admin.php?page=%s&tab=%s&action=%s&ip_address=%s&username=%s" onclick="return confirm(\'Are you sure you want to block this IP address?\')">Temp Block</a>',AIOWPSEC_FIREWALL_MENU_SLUG,$tab,'temp_block',$item['ip_or_host'],$item['username']),
                'delete' => sprintf('<a href="admin.php?page=%s&tab=%s&action=%s&id=%s" onclick="return confirm(\'Are you sure you want to delete this item?\')">Delete</a>',AIOWPSEC_FIREWALL_MENU_SLUG,$tab,'delete_event_log',$item['id']),
            );
        }
        
        //Return the user_login contents
        return sprintf('%1$s <span style="color:silver"></span>%2$s',
            /*$1%s*/ $item['id'],
            /*$2%s*/ $this->row_actions($actions)
        );
    }

    function column_status($item){
        $ip = $item['ip_or_host'];
        //Check if this IP address is locked
        $is_locked = AIOWPSecurity_Utility::check_locked_ip($ip);
        if($is_locked){
            return 'temporarily blocked';
        }else{
            return '';
        }
    }
    
    function column_cb($item){
        return sprintf(
            '<input type="checkbox" name="%1$s[]" value="%2$s" />',
            /*$1%s*/ $this->_args['singular'],  //Let's simply repurpose the table's singular label
            /*$2%s*/ $item['id']                //The value of the checkbox should be the record's id
       );
    }
    
    function get_columns(){
        $columns = array(
            'cb' => '<input type="checkbox" />', //Render a checkbox
            'id' => 'ID',
            'event_type' => 'Event Type',
            'ip_or_host' => 'IP Address',
            'url' => 'Attempted URL',
            'referer_info' => 'Referer',
            'event_date' => 'Date',
            'status' => 'Lock Status',
        );
        return $columns;
    }
    
    function get_sortable_columns() {
        $sortable_columns = array(
            'id' => array('id',false),
            'event_type' => array('event_type',false),
            'ip_or_host' => array('ip_or_host',false),
            'url' => array('url',false),
            'referer_info' => array('referer_info',false),
            'event_date' => array('event_date',false),
            'status' => array('status',false),
        );
        return $sortable_columns;
    }
    
    function get_bulk_actions() {
        $actions = array(
            //'unlock' => 'Unlock',
            'delete' => 'Delete'
        );
        return $actions;
    }

    function process_bulk_action() {
        if('delete'===$this->current_action()) 
        {//Process delete bulk actions
            if(!isset($_REQUEST['item']))
            {
                AIOWPSecurity_Admin_Menu::show_msg_error_st(__('Please select some records using the checkboxes','aiowpsecurity'));
            }else 
            {            
                $this->delete_404_event_records(($_REQUEST['item']));
            }
        }
    }
    
    
    /*
     * This function will lock an IP address by adding it to the "login_lockdown" table
     */
    function block_ip($entries, $username='')
    {
        global $wpdb;
        $events_table = AIOWPSEC_TBL_LOGIN_LOCKDOWN;
        if (is_array($entries))
        {
            //lock multiple records
            $ip_list = "(" .implode(",",$entries) .")"; //Create comma separate list for DB operation
            //TODO
        } elseif ($entries != NULL)
        {
            //Block single record
            AIOWPSecurity_Utility::lock_IP($entries, '404', $username);
        }
    }
    
    /*
     * This function will delete selected 404 records from the "events" table.
     * The function accepts either an array of IDs or a single ID
     */
    function delete_404_event_records($entries)
    {
        global $wpdb;
        $events_table = AIOWPSEC_TBL_EVENTS;
        if (is_array($entries))
        {
            //Delete multiple records
            $id_list = "(" .implode(",",$entries) .")"; //Create comma separate list for DB operation
            $delete_command = "DELETE FROM ".$events_table." WHERE id IN ".$id_list;
            $result = $wpdb->query($delete_command);
            if($result != NULL)
            {
                AIOWPSecurity_Admin_Menu::show_msg_record_deleted_st();
            }
        } 
        elseif ($entries != NULL)
        {
            //Delete single record
            $delete_command = "DELETE FROM ".$events_table." WHERE id = '".absint($entries)."'";
            $result = $wpdb->query($delete_command);
            if($result != NULL)
            {
                AIOWPSecurity_Admin_Menu::show_msg_record_deleted_st();
            }
        }
    }
    
    function prepare_items() {
        /**
         * First, lets decide how many records per page to show
         */
        $per_page = 20;
        $columns = $this->get_columns();
        $hidden = array();
        $sortable = $this->get_sortable_columns();

        $this->_column_headers = array($columns, $hidden, $sortable);
        
        $this->process_bulk_action();
    	
    	global $wpdb;
        $events_table_name = AIOWPSEC_TBL_EVENTS;

	/* -- Ordering parameters -- */
	    //Parameters that are going to be used to order the result
	$orderby = !empty($_GET["orderby"]) ? mysql_real_escape_string($_GET["orderby"]) : 'id';
	$order = !empty($_GET["order"]) ? mysql_real_escape_string($_GET["order"]) : 'DESC';

	$data = $wpdb->get_results("SELECT * FROM $events_table_name ORDER BY $orderby $order", ARRAY_A);
        $new_data = array();
        foreach($data as $row){
            //lets insert an empty "status" column - we will use later
            $row['status'] = '';
            $new_data[] = $row;
        }
        $current_page = $this->get_pagenum();
        $total_items = count($new_data);
        $new_data = array_slice($new_data,(($current_page-1)*$per_page),$per_page);
        $this->items = $new_data;
        $this->set_pagination_args( array(
            'total_items' => $total_items,                  //WE have to calculate the total number of items
            'per_page'    => $per_page,                     //WE have to determine how many items to show on a page
            'total_pages' => ceil($total_items/$per_page)   //WE have to calculate the total number of pages
        ) );
    }
}