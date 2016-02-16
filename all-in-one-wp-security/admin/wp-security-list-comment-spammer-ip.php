<?php

class AIOWPSecurity_List_Comment_Spammer_IP extends AIOWPSecurity_List_Table {

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
        
    function column_comment_author_IP($item){
        $tab = strip_tags($_REQUEST['tab']);
        //Build row actions
        if (AIOWPSecurity_Utility::is_multisite_install() && get_current_blog_id() != 1){
            //Suppress the block link if site is a multi site AND not the main site
            $actions = array(); //blank array
        }else{
            $block_url = sprintf('admin.php?page=%s&tab=%s&action=%s&spammer_ip=%s', AIOWPSEC_SPAM_MENU_SLUG, $tab, 'block_spammer_ip', $item['comment_author_IP']);
            //Add nonce to block URL
            $block_url_nonce = wp_nonce_url($block_url, "block_spammer_ip", "aiowps_nonce");
            
            $actions = array(
                'block' => '<a href="'.$block_url_nonce.'" onclick="return confirm(\'Are you sure you want to permanently block this IP address?\')">Block</a>',
            );
        }
        
        //Return the user_login contents
        return sprintf('%1$s <span style="color:silver"></span>%2$s',
            /*$1%s*/ $item['comment_author_IP'],
            /*$2%s*/ $this->row_actions($actions)
        );
    }

    
    function column_cb($item){
        return sprintf(
            '<input type="checkbox" name="%1$s[]" value="%2$s" />',
            /*$1%s*/ $this->_args['singular'],  //Let's simply repurpose the table's singular label
            /*$2%s*/ $item['comment_author_IP'] //The value of the checkbox should be the record's id
       );
    }
    
    function get_columns(){
        $columns = array(
            'cb' => '<input type="checkbox" />', //Render a checkbox
            'comment_author_IP' => 'Spammer IP',
            'amount' => 'Number of SPAM Comments From This IP',
            'status' => 'Status',
        );
        return $columns;
    }
    
    function get_sortable_columns() {
        $sortable_columns = array(
            'comment_author_IP' => array('comment_author_IP',false),
            'amount' => array('amount',false),
            'status' => array('status',false),
        );
        return $sortable_columns;
    }
    
    function get_bulk_actions() {
        if (AIOWPSecurity_Utility::is_multisite_install() && get_current_blog_id() != 1){
            //Suppress the block link if site is a multi site AND not the main site
            $actions = array(); //blank array
        }else{
            $actions = array(
                'block' => 'Block'
            );
        }
        return $actions;
    }

    function process_bulk_action() {
            global $aio_wp_security;
            if('block'===$this->current_action())
            {
                //Process block bulk actions
                if(!isset($_REQUEST['item']))
                {
                    $error_msg = '<div id="message" class="error"><p><strong>';
                    $error_msg .= __('Please select some records using the checkboxes','all-in-one-wp-security-and-firewall');
                    $error_msg .= '</strong></p></div>';
                    _e($error_msg);
                } else {
                    $this->block_spammer_ip_records(($_REQUEST['item']));
                }
            }
    }
    
    
    
    /*
     * This function will add the selected IP addresses to the blacklist.
     * The function accepts either an array of IDs or a single ID
     */
    function block_spammer_ip_records($entries)
    {
        global $wpdb, $aio_wp_security;
        if (is_array($entries))
        {
            if (isset($_REQUEST['_wp_http_referer']))
            {
                //Bulk selection using checkboxes were used
                foreach ($entries as $ip_add)
                {
                    AIOWPSecurity_Blocking::add_ip_to_block_list($ip_add, 'spam');
                }
            }
        }
        else if ($entries != NULL)
        {
            $nonce=isset($_GET['aiowps_nonce'])?$_GET['aiowps_nonce']:'';
            if (!isset($nonce) ||!wp_verify_nonce($nonce, 'block_spammer_ip'))
            {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed for delete selected blocked IP operation!",4);
                die(__('Nonce check failed for delete selected blocked IP operation!','all-in-one-wp-security-and-firewall'));
            }

            //individual entry where "block" link was clicked
            AIOWPSecurity_Blocking::add_ip_to_block_list($entries, 'spam');
        }

        AIOWPSecurity_Admin_Menu::show_msg_updated_st(__('The selected IP addresses are now permanently blocked!','all-in-one-wp-security-and-firewall'));
    }

    /*
     * (Old function which uses .htaccess blacklist - replaced by new method which uses php blocking code)
     * This function will add the selected IP addresses to the .htaccess blacklist.
     * The function accepts either an array of IDs or a single ID
     */
    function block_spammer_ip_records_old($entries)
    {
        global $wpdb, $aio_wp_security;
        $raw_banned_ip_list = $aio_wp_security->configs->get_value('aiowps_banned_ip_addresses');
        $currently_banned_ips = explode(PHP_EOL, $aio_wp_security->configs->get_value('aiowps_banned_ip_addresses'));
        if (is_array($entries))
        {
            if (isset($_REQUEST['_wp_http_referer']))
            {
                //Bulk selection using checkboxes were used
                foreach ($entries as $ip_add)
                {
                    if (!empty($currently_banned_ips) && !(sizeof($currently_banned_ips) == 1 && trim($currently_banned_ips[0]) == ''))
                    {
                        //Check if the IP address is already in the blacklist. If not add it to the list.
                        if (!in_array($ip_add, $currently_banned_ips))
                        {
                            $raw_banned_ip_list .= PHP_EOL.$ip_add;
                        }
                    }
                    else
                    {
                        //if blacklist is currently empty just add all IP addresses to the list regardless 
                        $raw_banned_ip_list .= PHP_EOL.$ip_add;
                    }
                }
            }
        } 
        else if ($entries != NULL)
        {
            $nonce=isset($_GET['aiowps_nonce'])?$_GET['aiowps_nonce']:'';
            if (!isset($nonce) ||!wp_verify_nonce($nonce, 'block_spammer_ip'))
            {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed for delete selected blocked IP operation!",4);
                die(__('Nonce check failed for delete selected blocked IP operation!','all-in-one-wp-security-and-firewall'));
            }
            
            //individual entry where "block" link was clicked
            //Check if the IP address is already in the blacklist. If not add it to the list.
            if (!in_array($entries, $currently_banned_ips))
            {
                $raw_banned_ip_list .= PHP_EOL.$entries;
            }
        }
        
        //Let's save the selected IP addresses to the blacklist config
        $aio_wp_security->configs->set_value('aiowps_banned_ip_addresses',$raw_banned_ip_list); //Save the blocked IP address config variable with the newly added addresses
        $aio_wp_security->configs->save_config();
        AIOWPSecurity_Admin_Menu::show_msg_updated_st(__('The selected IP addresses were saved in the blacklist configuration settings.','all-in-one-wp-security-and-firewall'));

        //Let's check if the Enable Blacklisting flag has been set - If so, we will write the new data to the .htaccess file.
        if($aio_wp_security->configs->get_value('aiowps_enable_blacklisting')=='1')
        {
            $write_result = AIOWPSecurity_Utility_Htaccess::write_to_htaccess();
            if ($write_result == -1)
            {
                AIOWPSecurity_Admin_Menu::show_msg_error_st(__('The plugin was unable to write to the .htaccess file. Please edit file manually.','all-in-one-wp-security-and-firewall'));
                $aio_wp_security->debug_logger->log_debug("AIOWPSecurity_Blacklist_Menu - The plugin was unable to write to the .htaccess file.");
            }
            else
            {
                
                AIOWPSecurity_Admin_Menu::show_msg_updated_st(__('The .htaccess file was successfully modified to include the selected IP addresses.','all-in-one-wp-security-and-firewall'));
            }
        }
        else
        {
            $blacklist_settings_link = '<a href="admin.php?page='.AIOWPSEC_BLACKLIST_MENU_SLUG.'">Ban Users</a>';
            $info_msg = '<p>'.__('NOTE: The .htaccess file was not modified because you have disabled the "Enable IP or User Agent Blacklisting" check box.', 'all-in-one-wp-security-and-firewall').
                        '<br />'.sprintf( __('To block these IP addresses you will need to enable the above flag in the %s menu', 'all-in-one-wp-security-and-firewall'), $blacklist_settings_link).'</p>';
            AIOWPSecurity_Admin_Menu::show_msg_updated_st($info_msg);
        }
    }

    function prepare_items()
    {
        //First, lets decide how many records per page to show
        $per_page = 20;
        $columns = $this->get_columns();
        $hidden = array();
        $sortable = $this->get_sortable_columns();

        $this->_column_headers = array($columns, $hidden, $sortable);

        $this->process_bulk_action();

        global $wpdb;
        global $aio_wp_security;
        $minimum_comments_per_ip = $aio_wp_security->configs->get_value('aiowps_spam_ip_min_comments');
        if (empty($minimum_comments_per_ip)) {
            $minimum_comments_per_ip = 5;
        }
        /* -- Ordering parameters -- */
        //Parameters that are going to be used to order the result
        isset($_GET["orderby"]) ? $orderby = strip_tags($_GET["orderby"]) : $orderby = '';
        isset($_GET["order"]) ? $order = strip_tags($_GET["order"]) : $order = '';

        $orderby = !empty($orderby) ? esc_sql($orderby) : 'amount';
        $order = !empty($order) ? esc_sql($order) : 'DESC';

        $orderby = AIOWPSecurity_Utility::sanitize_value_by_array($orderby, $sortable);
        $order = AIOWPSecurity_Utility::sanitize_value_by_array($order, array('DESC' => '1', 'ASC' => '1'));

        $sql = $wpdb->prepare("SELECT   comment_author_IP, COUNT(*) AS amount
                FROM     $wpdb->comments 
                WHERE    comment_approved = 'spam'
                GROUP BY comment_author_IP
                HAVING   amount >= %d
                ORDER BY $orderby $order
                ", $minimum_comments_per_ip);
        $data = $wpdb->get_results($sql, ARRAY_A);

        //Get all permamnetly blocked IP addresses
        $block_list = AIOWPSecurity_Blocking::get_list_blocked_ips();
        if(!empty($block_list)){
            foreach($data as $key=>$value){
                if(in_array($value['comment_author_IP'],$block_list)){
                    $data[$key]['status'] = 'blocked';
                }
            }
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