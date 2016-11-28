<?php

class AIOWPSecurity_List_Blocked_IP extends AIOWPSecurity_List_Table
{

    function __construct()
    {
        global $status, $page;

        //Set parent defaults
        parent::__construct(array(
            'singular' => 'item',     //singular name of the listed records
            'plural' => 'items',    //plural name of the listed records
            'ajax' => false        //does this table support ajax?
        ));

    }

    function column_default($item, $column_name)
    {
        return $item[$column_name];
    }

    function column_id($item)
    {
        $tab = isset($_REQUEST['tab']) ? strip_tags($_REQUEST['tab']) : '';
        //Add nonce to delete URL
        $unblock_ip_url = sprintf('admin.php?page=%s&tab=%s&action=%s&blocked_id=%s', AIOWPSEC_MAIN_MENU_SLUG, $tab, 'unblock_ip', $item['id']);
        //Add nonce to unlock IP URL
        $unblock_ip_nonce = wp_nonce_url($unblock_ip_url, "unblock_ip", "aiowps_nonce");

        //Build row actions
        $actions = array(
            'unblock' => '<a href="' . $unblock_ip_nonce . '" onclick="return confirm(\'Are you sure you want to unblock this IP address?\')">Unblock</a>',
        );

        //Return the user_login contents
        return sprintf('%1$s <span style="color:silver"></span>%2$s',
            /*$1%s*/
            $item['id'],
            /*$2%s*/
            $this->row_actions($actions)
        );
    }


    function column_cb($item)
    {
        return sprintf(
            '<input type="checkbox" name="%1$s[]" value="%2$s" />',
            /*$1%s*/
            $this->_args['singular'],  //Let's simply repurpose the table's singular label
            /*$2%s*/
            $item['id']                //The value of the checkbox should be the record's id
        );
    }

    function get_columns()
    {
        $columns = array(
            'cb' => '<input type="checkbox" />', //Render a checkbox
            'id' => 'ID',
            'blocked_ip' => 'Blocked IP',
            'block_reason' => 'Reason',
            'blocked_date' => 'Date'
        );
        return $columns;
    }

    function get_sortable_columns()
    {
        $sortable_columns = array(
            'id' => array('id', false),
            'blocked_ip' => array('blocked_ip', false),
            'block_reason' => array('block_reason', false),
            'blocked_date' => array('blocked_date', false)
        );
        return $sortable_columns;
    }

    function get_bulk_actions()
    {
        $actions = array(
            'unblock' => 'Unblock'
        );
        return $actions;
    }

    function process_bulk_action()
    {
        if ('unblock' === $this->current_action()) {//Process unlock bulk actions
            if (!isset($_REQUEST['item'])) {
                AIOWPSecurity_Admin_Menu::show_msg_error_st(__('Please select some records using the checkboxes', 'all-in-one-wp-security-and-firewall'));
            } else {
                $this->unblock_ip_address(($_REQUEST['item']));
            }
        }
    }


    /*
     * This function will delete selected records from the "AIOWPSEC_TBL_PERM_BLOCK" table.
     * The function accepts either an array of IDs or a single ID
     */
    function unblock_ip_address($entries)
    {
        global $wpdb, $aio_wp_security;
        if (is_array($entries)) {
            if (isset($_REQUEST['_wp_http_referer'])) {
                //Delete multiple records
                $entries = array_filter($entries, 'is_numeric'); //discard non-numeric ID values
                $id_list = "(" . implode(",", $entries) . ")"; //Create comma separate list for DB operation
                $delete_command = "DELETE FROM " . AIOWPSEC_TBL_PERM_BLOCK . " WHERE id IN " . $id_list;
                $result = $wpdb->query($delete_command);
                if ($result != NULL) {
                    AIOWPSecurity_Admin_Menu::show_msg_record_deleted_st();
                }
            }
        } elseif ($entries != NULL) {
            $nonce = isset($_GET['aiowps_nonce']) ? $_GET['aiowps_nonce'] : '';
            if (!isset($nonce) || !wp_verify_nonce($nonce, 'unblock_ip')) {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed for unblock IP operation!", 4);
                die(__('Nonce check failed for unblock IP operation!', 'all-in-one-wp-security-and-firewall'));
            }
            //Delete single record
            $delete_command = "DELETE FROM " . AIOWPSEC_TBL_PERM_BLOCK . " WHERE id = '" . absint($entries) . "'";
            $result = $wpdb->query($delete_command);
            if ($result != NULL) {
                AIOWPSecurity_Admin_Menu::show_msg_record_deleted_st();
            }
        }
    }

    function prepare_items()
    {
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
        $block_table_name = AIOWPSEC_TBL_PERM_BLOCK;

        /* -- Ordering parameters -- */
        //Parameters that are going to be used to order the result
        isset($_GET["orderby"]) ? $orderby = strip_tags($_GET["orderby"]) : $orderby = '';
        isset($_GET["order"]) ? $order = strip_tags($_GET["order"]) : $order = '';

        $orderby = !empty($orderby) ? esc_sql($orderby) : 'id';
        $order = !empty($order) ? esc_sql($order) : 'DESC';

        $orderby = AIOWPSecurity_Utility::sanitize_value_by_array($orderby, $sortable);
        $order = AIOWPSecurity_Utility::sanitize_value_by_array($order, array('DESC' => '1', 'ASC' => '1'));

        if (isset($_POST['s'])) {
            $search_term = trim($_POST['s']);
            $data = $wpdb->get_results($wpdb->prepare("SELECT * FROM " . $block_table_name . " WHERE `blocked_ip` LIKE '%%%s%%' OR `block_reason` LIKE '%%%s%%' OR `country_origin` LIKE '%%%s%%' OR `blocked_date` LIKE '%%%s%%'", $search_term, $search_term, $search_term, $search_term), ARRAY_A);
        } else {
            $data = $wpdb->get_results("SELECT * FROM " . $block_table_name . " ORDER BY $orderby $order", ARRAY_A);
        }

        $current_page = $this->get_pagenum();
        $total_items = count($data);
        $data = array_slice($data, (($current_page - 1) * $per_page), $per_page);
        $this->items = $data;
        $this->set_pagination_args(array(
            'total_items' => $total_items,                  //WE have to calculate the total number of items
            'per_page' => $per_page,                     //WE have to determine how many items to show on a page
            'total_pages' => ceil($total_items / $per_page)   //WE have to calculate the total number of pages
        ));
    }
}