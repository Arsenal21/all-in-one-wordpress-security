<?php
class AIOWPSecurity_List_Locked_IP extends AIOWPSecurity_List_Table {
    
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
        
    function column_failed_login_ip($item){
        $tab = isset($_REQUEST['tab'])?strip_tags($_REQUEST['tab']):'';
        $delete_lockdown_record = sprintf('admin.php?page=%s&tab=%s&action=%s&lockdown_id=%s', AIOWPSEC_MAIN_MENU_SLUG, $tab, 'delete_blocked_ip', $item['id']);
        //Add nonce to delete URL
        $delete_lockdown_record_nonce = wp_nonce_url($delete_lockdown_record, "delete_lockdown_record", "aiowps_nonce");

        $unlock_ip_url = sprintf('admin.php?page=%s&tab=%s&action=%s&lockdown_id=%s', AIOWPSEC_MAIN_MENU_SLUG, $tab, 'unlock_ip', $item['id']);
        //Add nonce to unlock IP URL
        $unlock_ip_nonce = wp_nonce_url($unlock_ip_url, "unlock_ip", "aiowps_nonce");
        
        //Build row actions
        $actions = array(
            'unlock' => '<a href="'.$unlock_ip_nonce.'" onclick="return confirm(\'Are you sure you want to unlock this address range?\')">Unlock</a>',
            'delete' => '<a href="'.$delete_lockdown_record_nonce.'" onclick="return confirm(\'Are you sure you want to delete this item?\')">Delete</a>',
        );
        
        //Return the user_login contents
        return sprintf('%1$s <span style="color:silver"></span>%2$s',
            /*$1%s*/ $item['failed_login_ip'],
            /*$2%s*/ $this->row_actions($actions)
        );
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
            'failed_login_ip' => 'Locked IP/Range',
            'user_id' => 'User ID',
            'user_login' => 'Username',
            'lock_reason' => 'Reason',
            'lockdown_date' => 'Date Locked',
            'release_date' => 'Release Date'
        );
        return $columns;
    }
    
    function get_sortable_columns() {
        $sortable_columns = array(
            'failed_login_ip' => array('failed_login_ip',false),
            'user_id' => array('user_id',false),
            'user_login' => array('user_login',false),
            'lock_reason' => array('lock_reason',false),
            'lockdown_date' => array('lockdown_date',false),
            'release_date' => array('release_date',false)
        );
        return $sortable_columns;
    }
    
    function get_bulk_actions() {
        $actions = array(
            'unlock' => 'Unlock',
            'delete' => 'Delete'
        );
        return $actions;
    }

    function process_bulk_action() {
        if('delete'===$this->current_action()) 
        {//Process delete bulk actions
            if(!isset($_REQUEST['item']))
            {
                AIOWPSecurity_Admin_Menu::show_msg_error_st(__('Please select some records using the checkboxes','all-in-one-wp-security-and-firewall'));
            }else 
            {            
                $this->delete_lockdown_records(($_REQUEST['item']));
            }
        }

        if('unlock'===$this->current_action()) 
        {//Process unlock bulk actions
            if(!isset($_REQUEST['item']))
            {
                AIOWPSecurity_Admin_Menu::show_msg_error_st(__('Please select some records using the checkboxes','all-in-one-wp-security-and-firewall'));
            }else 
            {            
                $this->unlock_ip_range(($_REQUEST['item']));
            }
        }
    }
    
    
    /*
     * This function will unlock an IP range by modifying the "release_date" column of a record in the "login_lockdown" table
     */
    function unlock_ip_range($entries)
    {
        global $wpdb,$aio_wp_security;
        $lockdown_table = AIOWPSEC_TBL_LOGIN_LOCKDOWN;
        if (is_array($entries))
        {
            if (isset($_REQUEST['_wp_http_referer']))
            {
                //Unlock multiple records
                $entries = array_filter($entries, 'is_numeric'); //discard non-numeric ID values
                $id_list = "(" .implode(",",$entries) .")"; //Create comma separate list for DB operation
                $unlock_command = "UPDATE ".$lockdown_table." SET release_date = now() WHERE id IN ".$id_list;
                $result = $wpdb->query($unlock_command);
                if($result != NULL)
                {
                    AIOWPSecurity_Admin_Menu::show_msg_updated_st(__('The selected IP entries were unlocked successfully!','all-in-one-wp-security-and-firewall'));
                }
            }
        } elseif ($entries != NULL)
        {
            $nonce=isset($_GET['aiowps_nonce'])?$_GET['aiowps_nonce']:'';
            if (!isset($nonce) ||!wp_verify_nonce($nonce, 'unlock_ip'))
            {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed for unlock IP operation!",4);
                die(__('Nonce check failed for unlock IP operation!','all-in-one-wp-security-and-firewall'));
            }
            
            //Unlock single record
            $unlock_command = $wpdb->prepare( "UPDATE ".$lockdown_table." SET release_date = now() WHERE id = %d", absint($entries) );
            $result = $wpdb->query($unlock_command);
            if($result != NULL)
            {
                AIOWPSecurity_Admin_Menu::show_msg_updated_st(__('The selected IP entry was unlocked successfully!','all-in-one-wp-security-and-firewall'));
            }
        }
    }
    
    /*
     * This function will delete selected records from the "login_lockdown" table.
     * The function accepts either an array of IDs or a single ID
     */
    function delete_lockdown_records($entries)
    {
        global $wpdb, $aio_wp_security;
        $lockdown_table = AIOWPSEC_TBL_LOGIN_LOCKDOWN;
        if (is_array($entries))
        {
            if (isset($_REQUEST['_wp_http_referer']))
            {
                //Delete multiple records
                $entries = array_filter($entries, 'is_numeric'); //discard non-numeric ID values
                $id_list = "(" .implode(",",$entries) .")"; //Create comma separate list for DB operation
                $delete_command = "DELETE FROM ".$lockdown_table." WHERE id IN ".$id_list;
                $result = $wpdb->query($delete_command);
                if($result != NULL)
                {
                    AIOWPSecurity_Admin_Menu::show_msg_record_deleted_st();
                }
            }
        } 
        elseif ($entries != NULL)
        {
            $nonce=isset($_GET['aiowps_nonce'])?$_GET['aiowps_nonce']:'';
            if (!isset($nonce) ||!wp_verify_nonce($nonce, 'delete_lockdown_record'))
            {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed for delete lockdown record operation!",4);
                die(__('Nonce check failed for delete lockdown record operation!','all-in-one-wp-security-and-firewall'));
            }
            //Delete single record
            $delete_command = "DELETE FROM ".$lockdown_table." WHERE id = '".absint($entries)."'";
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
        $lockdown_table_name = AIOWPSEC_TBL_LOGIN_LOCKDOWN;

	/* -- Ordering parameters -- */
	    //Parameters that are going to be used to order the result
        isset($_GET["orderby"]) ? $orderby = strip_tags($_GET["orderby"]): $orderby = '';
        isset($_GET["order"]) ? $order = strip_tags($_GET["order"]): $order = '';

	$orderby = !empty($orderby) ? esc_sql($orderby) : 'lockdown_date';
	$order = !empty($order) ? esc_sql($order) : 'DESC';

        $orderby = AIOWPSecurity_Utility::sanitize_value_by_array($orderby, $sortable);
        $order = AIOWPSecurity_Utility::sanitize_value_by_array($order, array('DESC' => '1', 'ASC' => '1'));
        
	$data = $wpdb->get_results($wpdb->prepare("SELECT * FROM $lockdown_table_name WHERE (lock_reason=%s OR lock_reason=%s) AND release_date > now() ORDER BY $orderby $order", 'login_fail', '404'), ARRAY_A);
        $current_page = $this->get_pagenum();
        $total_items = count($data);
        $data = array_slice($data,(($current_page-1)*$per_page),$per_page);
        $this->items = $data;
        $this->set_pagination_args( array(
            'total_items' => $total_items,                  //WE have to calculate the total number of items
            'per_page'    => $per_page,                     //WE have to determine how many items to show on a page
            'total_pages' => ceil($total_items/$per_page)   //WE have to calculate the total number of pages
        ) );
    }
}