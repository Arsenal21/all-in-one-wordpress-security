<?php
if(!defined('ABSPATH')){
    exit;//Exit if accessed directly
}

class AIOWPSecurity_List_404 extends AIOWPSecurity_List_Table {

    function __construct() {
        global $status, $page;

        //Set parent defaults
        parent::__construct(array(
            'singular' => 'item', //singular name of the listed records
            'plural' => 'items', //plural name of the listed records
            'ajax' => false        //does this table support ajax?
        ));
    }

    function column_default($item, $column_name) {
        return $item[$column_name];
    }

    function column_id($item) {
        $tab = strip_tags($_REQUEST['tab']);
        $ip = $item['ip_or_host'];

        $blocked_ips_tab = 'tab3';
        //Check if this IP address is locked
        $is_locked = AIOWPSecurity_Utility::check_locked_ip($ip);
        $delete_url = sprintf('admin.php?page=%s&tab=%s&action=%s&id=%s', AIOWPSEC_FIREWALL_MENU_SLUG, $tab, 'delete_event_log', $item['id']);
        //Add nonce to delete URL
        $delete_url_nonce = wp_nonce_url($delete_url, "delete_404_log", "aiowps_nonce");
        if ($is_locked) {
            //Build row actions
            $actions = array(
                'unblock' => sprintf('<a href="admin.php?page=%s&tab=%s">Unblock</a>', AIOWPSEC_MAIN_MENU_SLUG, $blocked_ips_tab),
                'delete' => '<a href="'.$delete_url_nonce.'" onclick="return confirm(\'Are you sure you want to delete this item?\')">Delete</a>',
            );
        } else {
            //Build row actions
            $actions = array(
                'temp_block' => sprintf('<a href="admin.php?page=%s&tab=%s&action=%s&ip_address=%s&username=%s" onclick="return confirm(\'Are you sure you want to block this IP address?\')">Temp Block</a>', AIOWPSEC_FIREWALL_MENU_SLUG, $tab, 'temp_block', $item['ip_or_host'], $item['username']),
                'blacklist_ip' => sprintf('<a href="admin.php?page=%s&tab=%s&action=%s&ip_address=%s&username=%s" onclick="return confirm(\'Are you sure you want to permanently block this IP address?\')">Blacklist IP</a>', AIOWPSEC_FIREWALL_MENU_SLUG, $tab, 'blacklist_ip', $item['ip_or_host'], $item['username']),
                'delete' => '<a href="'.$delete_url_nonce.'" onclick="return confirm(\'Are you sure you want to delete this item?\')">Delete</a>',
            );
        }

        //Return the user_login contents
        return sprintf('%1$s <span style="color:silver"></span>%2$s',
                /* $1%s */ $item['id'],
                /* $2%s */ $this->row_actions($actions)
        );
    }

    function column_status($item) {
        global $aio_wp_security;
        $ip = $item['ip_or_host'];
        //Check if this IP address is locked
        $is_locked = AIOWPSecurity_Utility::check_locked_ip($ip);
        $blacklisted_string = $aio_wp_security->configs->get_value('aiowps_banned_ip_addresses');
        $banned = strpos($blacklisted_string, $ip);
        
        if ($banned !== false) {
            return 'blacklisted';
        } else if ($is_locked) {
            return 'temporarily blocked';
        } else {
            return '';
        }
    }

    function column_cb($item) {
        return sprintf(
                '<input type="checkbox" name="%1$s[]" value="%2$s" />',
                /* $1%s */ $this->_args['singular'], //Let's simply repurpose the table's singular label
                /* $2%s */ $item['id']                //The value of the checkbox should be the record's id
        );
    }

    function get_columns() {
        $columns = array(
            'cb' => '<input type="checkbox" />', //Render a checkbox
            'id' => 'ID',
            'event_type' => __('Event Type','all-in-one-wp-security-and-firewall'),
            'ip_or_host' => __('IP Address','all-in-one-wp-security-and-firewall'),
            'url' => __('Attempted URL','all-in-one-wp-security-and-firewall'),
            'referer_info' => __('Referer','all-in-one-wp-security-and-firewall'),
            'event_date' => __('Date','all-in-one-wp-security-and-firewall'),
            'status' => __('Lock Status','all-in-one-wp-security-and-firewall'),
        );
        $columns = apply_filters('list_404_get_columns', $columns);
        return $columns;
    }

    function get_sortable_columns() {
        $sortable_columns = array(
            'id' => array('id', false),
            'event_type' => array('event_type', false),
            'ip_or_host' => array('ip_or_host', false),
            'url' => array('url', false),
            'referer_info' => array('referer_info', false),
            'event_date' => array('event_date', false),
        );
        $sortable_columns = apply_filters('list_404_get_sortable_columns', $sortable_columns);
        return $sortable_columns;
    }

    function get_bulk_actions() {
        $actions = array(
            //'unlock' => 'Unlock',
            'bulk_block_ip' => 'Temp Block IP',
            'bulk_blacklist_ip' => 'Blacklist IP',
            'delete' => 'Delete'
        );
        return $actions;
    }

    function process_bulk_action() {
        if ('bulk_block_ip' === $this->current_action()) {//Process delete bulk actions
            if (!isset($_REQUEST['item'])) {
                AIOWPSecurity_Admin_Menu::show_msg_error_st(__('Please select some records using the checkboxes', 'all-in-one-wp-security-and-firewall'));
            } else {
                $this->block_ip(($_REQUEST['item']));
            }
        }

        if ('bulk_blacklist_ip' === $this->current_action()) {//Process delete bulk actions
            if (!isset($_REQUEST['item'])) {
                AIOWPSecurity_Admin_Menu::show_msg_error_st(__('Please select some records using the checkboxes', 'all-in-one-wp-security-and-firewall'));
            } else {
                $this->blacklist_ip_address(($_REQUEST['item']));
            }
        }
        if ('delete' === $this->current_action()) {//Process delete bulk actions
            if (!isset($_REQUEST['item'])) {
                AIOWPSecurity_Admin_Menu::show_msg_error_st(__('Please select some records using the checkboxes', 'all-in-one-wp-security-and-firewall'));
            } else {
                $this->delete_404_event_records(($_REQUEST['item']));
            }
        }
    }

    /*
     * This function will lock an IP address by adding it to the "login_lockdown" table
     */

    function block_ip($entries, $username = '') {
        global $wpdb;
        $events_table = AIOWPSEC_TBL_LOGIN_LOCKDOWN;
        if (is_array($entries)) {
            //lock multiple records
            $entries = array_filter($entries, 'is_numeric'); //discard non-numeric ID values
            $id_list = "(" .implode(",",$entries) .")"; //Create comma separate list for DB operation
            $events_table = AIOWPSEC_TBL_EVENTS;
            $query = "SELECT ip_or_host FROM $events_table WHERE ID IN ".$id_list;
            $results = $wpdb->get_col($query);
            if(empty($results)){
                AIOWPSecurity_Admin_Menu::show_msg_error_st(__('Could not process the request because the IP addresses for the selected entries could not be found!', 'WPS'));
                return false;
            }else{
                foreach($results as $entry){
                    if(filter_var($entry, FILTER_VALIDATE_IP)){
                        AIOWPSecurity_Utility::lock_IP($entry, '404', $username);
                    }
                }
            }
            AIOWPSecurity_Admin_Menu::show_msg_updated_st(__('The selected IP addresses are now temporarily blocked!', 'WPS'));
        } elseif ($entries != NULL) {
            //Block single record
            if(filter_var($entries, FILTER_VALIDATE_IP)){
                AIOWPSecurity_Utility::lock_IP($entries, '404', $username);
                AIOWPSecurity_Admin_Menu::show_msg_updated_st(__('The selected IP address is now temporarily blocked!', 'WPS'));
            }else{
                AIOWPSecurity_Admin_Menu::show_msg_error_st(__('The selected entry is not a valid IP address!', 'WPS'));
            }
        }
    }

    /*
     * This function will lock an IP address by adding it to the "login_lockdown" table
     */

    function blacklist_ip_address($entries) {
        global $wpdb, $aio_wp_security;
        $bl_ip_addresses = $aio_wp_security->configs->get_value('aiowps_banned_ip_addresses'); //get the currently saved blacklisted IPs
        $ip_list_array = AIOWPSecurity_Utility_IP::create_ip_list_array_from_string_with_newline($bl_ip_addresses);
        
        if (is_array($entries)) {
            //Get the selected IP addresses
            $entries = array_filter($entries, 'is_numeric'); //discard non-numeric ID values
            $id_list = "(" .implode(",",$entries) .")"; //Create comma separate list for DB operation
            $events_table = AIOWPSEC_TBL_EVENTS;
            $query = "SELECT ip_or_host FROM $events_table WHERE ID IN ".$id_list;
            $results = $wpdb->get_col($query);
            if(empty($results)){
                AIOWPSecurity_Admin_Menu::show_msg_error_st(__('Could not process the request because the IP addresses for the selected entries could not be found!', 'WPS'));
                return false;
            }else{
                foreach($results as $entry){
                    $ip_list_array[] = $entry;
                }
            }
        } elseif ($entries != NULL) {
            //Blacklist single record
            $ip_list_array[] = $entries;
        }
        $payload = AIOWPSecurity_Utility_IP::validate_ip_list($ip_list_array, 'blacklist');
        if($payload[0] == 1){
            //success case
            $result = 1;
            $list = $payload[1];
            $banned_ip_data = implode(PHP_EOL, $list);
            $aio_wp_security->configs->set_value('aiowps_enable_blacklisting','1'); //Force blacklist feature to be enabled
            $aio_wp_security->configs->set_value('aiowps_banned_ip_addresses',$banned_ip_data);
            $aio_wp_security->configs->save_config(); //Save the configuration

            $write_result = AIOWPSecurity_Utility_Htaccess::write_to_htaccess(); //now let's write to the .htaccess file
            if ( $write_result ) {
                AIOWPSecurity_Admin_Menu::show_msg_updated_st(__('The selected IP addresses have been added to the blacklist and will be permanently blocked!', 'WPS'));
            } else {
                AIOWPSecurity_Admin_Menu::show_msg_error_st(__('The plugin was unable to write to the .htaccess file. Please edit file manually.','all-in-one-wp-security-and-firewall'));
                $aio_wp_security->debug_logger->log_debug("AIOWPSecurity_Blacklist_Menu - The plugin was unable to write to the .htaccess file.");
            }
        }
        else{
            $result = -1;
            $error_msg = $payload[1][0];
            AIOWPSecurity_Admin_Menu::show_msg_error_st($error_msg);
        }
    }

    /*
     * This function will delete selected 404 records from the "events" table.
     * The function accepts either an array of IDs or a single ID
     */

    function delete_404_event_records($entries) {
        global $wpdb, $aio_wp_security;
        $events_table = AIOWPSEC_TBL_EVENTS;
        if (is_array($entries)) {
            if (isset($_REQUEST['_wp_http_referer']))
            {
                //Delete multiple records
                $entries = array_map( 'esc_sql', $entries); //escape every array element
                $entries = array_filter($entries, 'is_numeric'); //discard non-numeric ID values
                $id_list = "(" . implode(",", $entries) . ")"; //Create comma separate list for DB operation
                $delete_command = "DELETE FROM " . $events_table . " WHERE id IN " . $id_list;
                $result = $wpdb->query($delete_command);
                if ($result != NULL) {
                    AIOWPSecurity_Admin_Menu::show_msg_record_deleted_st();
                }
            }

        } elseif ($entries != NULL) {
            $nonce=isset($_GET['aiowps_nonce'])?$_GET['aiowps_nonce']:'';
            if (!isset($nonce) ||!wp_verify_nonce($nonce, 'delete_404_log'))
            {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed for delete selected 404 event logs operation!",4);
                die(__('Nonce check failed for delete selected 404 event logs operation!','all-in-one-wp-security-and-firewall'));
            }

            //Delete single record
            $delete_command = "DELETE FROM " . $events_table . " WHERE id = '" . absint($entries) . "'";
            //$delete_command = $wpdb->prepare("DELETE FROM $events_table WHERE id = %s", absint($entries));
            $result = $wpdb->query($delete_command);
            if ($result != NULL) {
                AIOWPSecurity_Admin_Menu::show_msg_record_deleted_st();
            }
        }
    }

    function prepare_items($ignore_pagination=false) {
        /**
         * First, lets decide how many records per page to show
         */
        $per_page = 100;
        $columns = $this->get_columns();
        $hidden = array();
        $sortable = $this->get_sortable_columns();

        $this->_column_headers = array($columns, $hidden, $sortable);

        $this->process_bulk_action();

        global $wpdb;
        $events_table_name = AIOWPSEC_TBL_EVENTS;

        /* -- Ordering parameters -- */
        //Parameters that are going to be used to order the result
        isset($_GET["orderby"]) ? $orderby = strip_tags($_GET["orderby"]): $orderby = '';
        isset($_GET["order"]) ? $order = strip_tags($_GET["order"]): $order = '';

        $orderby = !empty($orderby) ? esc_sql($orderby) : 'id';
        $order = !empty($order) ? esc_sql($order) : 'DESC';
        
        $orderby = AIOWPSecurity_Utility::sanitize_value_by_array($orderby, $sortable);
        $order = AIOWPSecurity_Utility::sanitize_value_by_array($order, array('DESC' => '1', 'ASC' => '1'));

        if (isset($_POST['s'])) {
            $search_term = trim($_POST['s']);
            $data = $wpdb->get_results($wpdb->prepare("SELECT * FROM " . $events_table_name . " WHERE `ip_or_host` LIKE '%%%s%%' OR `url` LIKE '%%%s%%' OR `referer_info` LIKE '%%%s%%'", $search_term, $search_term, $search_term), ARRAY_A);
        } else {
            $data = $wpdb->get_results($wpdb->prepare("SELECT * FROM $events_table_name WHERE event_type=%s ORDER BY $orderby $order",'404'), ARRAY_A);
        }
        $new_data = array();
        foreach ($data as $row) {
            //lets insert an empty "status" column - we will use later
            $row['status'] = '';
            $new_data[] = $row;
        }
        if (!$ignore_pagination) {
            $current_page = $this->get_pagenum();
            $total_items = count($new_data);
            $new_data = array_slice($new_data, (($current_page - 1) * $per_page), $per_page);
            $this->set_pagination_args(array(
                'total_items' => $total_items, //WE have to calculate the total number of items
                'per_page' => $per_page, //WE have to determine how many items to show on a page
                'total_pages' => ceil($total_items / $per_page)   //WE have to calculate the total number of pages
            ));
        }
        $this->items = $new_data;
    }

}