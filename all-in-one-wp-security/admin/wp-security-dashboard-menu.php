<?php
if(!defined('ABSPATH')){
    exit;//Exit if accessed directly
}

class AIOWPSecurity_Dashboard_Menu extends AIOWPSecurity_Admin_Menu
{
    var $dashboard_menu_page_slug = AIOWPSEC_MAIN_MENU_SLUG;

    var $menu_tabs;

    var $menu_tabs_handler = array(
        'tab1' => 'render_tab1',
        'tab2' => 'render_tab2',
        'tab3' => 'render_tab3',
        'tab4' => 'render_tab4',
        'tab5' => 'render_tab5',
    );

    function __construct()
    {
        $this->render_menu_page();
    }

    function set_menu_tabs()
    {
        $this->menu_tabs = array(
            'tab1' => __('Dashboard', 'all-in-one-wp-security-and-firewall'),
            'tab2' => __('System Info', 'all-in-one-wp-security-and-firewall'),
            'tab3' => __('Locked IP Addresses', 'all-in-one-wp-security-and-firewall'),
            'tab4' => __('Permanent Block List', 'all-in-one-wp-security-and-firewall'),
            'tab5' => __('AIOWPS Logs', 'all-in-one-wp-security-and-firewall'),
        );
    }

    function get_current_tab()
    {
        $tab_keys = array_keys($this->menu_tabs);
        $tab = isset($_GET['tab']) ? sanitize_text_field($_GET['tab']) : $tab_keys[0];
        return $tab;
    }

    /*
     * Renders our tabs of this menu as nav items
     */
    function render_menu_tabs()
    {
        $current_tab = $this->get_current_tab();

        echo '<h2 class="nav-tab-wrapper">';
        foreach ($this->menu_tabs as $tab_key => $tab_caption) {
            $active = $current_tab == $tab_key ? 'nav-tab-active' : '';
            echo '<a class="nav-tab ' . $active . '" href="?page=' . $this->dashboard_menu_page_slug . '&tab=' . $tab_key . '">' . $tab_caption . '</a>';
        }
        echo '</h2>';
    }

    /*
     * The menu rendering goes here
     */
    function render_menu_page()
    {
        echo '<div class="wrap">';
        echo '<h2>' . __('Dashboard', 'all-in-one-wp-security-and-firewall') . '</h2>';//Interface title
        $this->set_menu_tabs();
        $tab = $this->get_current_tab();
        $this->render_menu_tabs();
        ?>        
        <div id="poststuff"><div id="post-body">
        <?php
        call_user_func(array(&$this, $this->menu_tabs_handler[$tab]));
        ?>
        </div></div>
        </div><!-- end of wrap -->
        <?php
    }

    function render_tab1()
    {
        /** Load WordPress dashboard API */
        require_once(ABSPATH . 'wp-admin/includes/dashboard.php');
        $this->wp_dashboard_setup();

        wp_enqueue_script( 'dashboard' );
        add_thickbox();
        if ( wp_is_mobile() )
                wp_enqueue_script( 'jquery-touch-punch' );
        ?>
        <script type='text/javascript' src='https://www.google.com/jsapi'></script>
        <div id="dashboard-widgets-wrap">
	<?php $this->wp_dashboard(); ?>
	</div><!-- dashboard-widgets-wrap -->
	<?php
    }

    function render_tab2()
    {
        global $wpdb;
        ?>
        <div class="postbox">
            <h3 class="hndle"><label for="title"><?php _e('Site Info', 'all-in-one-wp-security-and-firewall');?></label>
            </h3>

            <div class="inside">
                <strong><?php _e('Plugin Version', 'all-in-one-wp-security-and-firewall');?>
                    : </strong><code><?php echo AIO_WP_SECURITY_VERSION;?></code><br/>
                <strong><?php _e('WP Version', 'all-in-one-wp-security-and-firewall');?>
                    : </strong><code><?php echo get_bloginfo("version"); ?></code><br/>
                <strong>WPMU: </strong><code><?php echo (!defined('MULTISITE') || !MULTISITE) ? "No" : "Yes"; ?></code><br/>
                <strong>MySQL <?php _e('Version', 'all-in-one-wp-security-and-firewall');?>
                    : </strong><code><?php echo $wpdb->db_version();?></code><br/>
                <strong>WP <?php _e('Table Prefix', 'all-in-one-wp-security-and-firewall');?>
                    : </strong><code><?php echo $wpdb->prefix; ?></code><br/>
                <strong>PHP <?php _e('Version', 'all-in-one-wp-security-and-firewall');?>
                    : </strong><code><?php echo phpversion(); ?></code><br/>
                <strong><?php _e('Session Save Path', 'all-in-one-wp-security-and-firewall');?>
                    : </strong><code><?php echo ini_get("session.save_path"); ?></code><br/>
                <strong>WP URL: </strong><code><?php echo get_bloginfo('wpurl'); ?></code><br/>
                <strong><?php _e('Server Name', 'all-in-one-wp-security-and-firewall');?>
                    : </strong><code><?php echo $_SERVER['SERVER_NAME']; ?></code><br/>
                <strong><?php _e('Cookie Domain', 'all-in-one-wp-security-and-firewall');?>
                    : </strong><code><?php $cookieDomain = parse_url(strtolower(get_bloginfo('wpurl')));
                    echo $cookieDomain['host']; ?></code><br/>
                <strong>CURL <?php _e('Library Present', 'all-in-one-wp-security-and-firewall');?>
                    : </strong><code><?php echo (function_exists('curl_init')) ? "Yes" : "No"; ?></code><br/>
                <strong><?php _e('Debug File Write Permissions', 'all-in-one-wp-security-and-firewall');?>
                    : </strong><code><?php echo (is_writable(AIO_WP_SECURITY_PATH)) ? "Writable" : "Not Writable"; ?></code><br/>
            </div>
        </div><!-- End of Site Info -->

        <div class="postbox">
            <h3 class="hndle"><label for="title"><?php _e('PHP Info', 'all-in-one-wp-security-and-firewall');?></label>
            </h3>

            <div class="inside">
                <strong><?php _e('PHP Version', 'all-in-one-wp-security-and-firewall'); ?>
                    : </strong><code><?php echo PHP_VERSION; ?></code><br/>
                <strong><?php _e('PHP Memory Usage', 'all-in-one-wp-security-and-firewall'); ?>:
                </strong><code><?php echo round(memory_get_usage() / 1024 / 1024, 2) . __(' MB', 'all-in-one-wp-security-and-firewall'); ?></code>
                <br/>
                <?php
                if (ini_get('memory_limit')) {
                    $memory_limit = filter_var(ini_get('memory_limit'), FILTER_SANITIZE_STRING);
                } else {
                    $memory_limit = __('N/A', 'all-in-one-wp-security-and-firewall');
                }
                ?>
                <strong><?php _e('PHP Memory Limit', 'all-in-one-wp-security-and-firewall'); ?>
                    : </strong><code><?php echo $memory_limit; ?></code><br/>
                <?php
                if (ini_get('upload_max_filesize')) {
                    $upload_max = filter_var(ini_get('upload_max_filesize'), FILTER_SANITIZE_STRING);
                } else {
                    $upload_max = __('N/A', 'all-in-one-wp-security-and-firewall');
                }
                ?>
                <strong><?php _e('PHP Max Upload Size', 'all-in-one-wp-security-and-firewall'); ?>
                    : </strong><code><?php echo $upload_max; ?></code><br/>
                <?php
                if (ini_get('post_max_size')) {
                    $post_max = filter_var(ini_get('post_max_size'), FILTER_SANITIZE_STRING);
                } else {
                    $post_max = __('N/A', 'all-in-one-wp-security-and-firewall');
                }
                ?>
                <strong><?php _e('PHP Max Post Size', 'all-in-one-wp-security-and-firewall'); ?>
                    : </strong><code><?php echo $post_max; ?></code><br/>
                <?php
                if (ini_get('allow_url_fopen')) {
                    $allow_url_fopen = __('On', 'all-in-one-wp-security-and-firewall');
                } else {
                    $allow_url_fopen = __('Off', 'all-in-one-wp-security-and-firewall');
                }
                ?>
                <strong><?php _e('PHP Allow URL fopen', 'all-in-one-wp-security-and-firewall'); ?>
                    : </strong><code><?php echo $allow_url_fopen; ?></code>
                <br/>
                <?php
                if (ini_get('allow_url_include')) {
                    $allow_url_include = __('On', 'all-in-one-wp-security-and-firewall');
                } else {
                    $allow_url_include = __('Off', 'all-in-one-wp-security-and-firewall');
                }
                ?>
                <strong><?php _e('PHP Allow URL Include'); ?>
                    : </strong><code><?php echo $allow_url_include; ?></code><br/>
                <?php
                if (ini_get('display_errors')) {
                    $display_errors = __('On', 'all-in-one-wp-security-and-firewall');
                } else {
                    $display_errors = __('Off', 'all-in-one-wp-security-and-firewall');
                }
                ?>
                <strong><?php _e('PHP Display Errors', 'all-in-one-wp-security-and-firewall'); ?>
                    : </strong><code><?php echo $display_errors; ?></code>
                <br/>
                <?php
                if (ini_get('max_execution_time')) {
                    $max_execute = filter_var(ini_get('max_execution_time'));
                } else {
                    $max_execute = __('N/A', 'all-in-one-wp-security-and-firewall');
                }
                ?>
                <strong><?php _e('PHP Max Script Execution Time', 'all-in-one-wp-security-and-firewall'); ?>
                    : </strong><code><?php echo $max_execute; ?> <?php _e('Seconds'); ?></code><br/>
            </div>
        </div><!-- End of PHP Info -->

        <div class="postbox">
            <h3 class="hndle"><label
                    for="title"><?php _e('Active Plugins', 'all-in-one-wp-security-and-firewall');?></label></h3>

            <div class="inside">
                <?php
                $all_plugins = get_plugins();
                $active_plugins = get_option('active_plugins');
                //var_dump($all_plugins);
                ?>
                <table class="widefat aio_spacer_10_tb">
                    <thead>
                    <tr>
                        <th><?php _e('Name', 'all-in-one-wp-security-and-firewall') ?></th>
                        <th><?php _e('Version', 'all-in-one-wp-security-and-firewall') ?></th>
                        <th><?php _e('Plugin URL', 'all-in-one-wp-security-and-firewall') ?></th>
                    </tr>
                    </thead>
                    <tbody>
                    <?php
                    foreach ($active_plugins as $plugin_key) {
                        $plugin_details = $all_plugins[$plugin_key];
                        echo '<tr><td>' . $plugin_details['Name'] . '</td><td>' . $plugin_details['Version'] . '</td><td>' . $plugin_details['PluginURI'] . '</td></tr>';
                    }
                    ?>
                    </tbody>
                </table>
            </div>
        </div><!-- End of Active Plugins -->
    <?php
    }

    function render_tab3()
    {
        global $wpdb;
        include_once 'wp-security-list-locked-ip.php'; //For rendering the AIOWPSecurity_List_Table in tab1
        $locked_ip_list = new AIOWPSecurity_List_Locked_IP(); //For rendering the AIOWPSecurity_List_Table in tab1

        if (isset($_REQUEST['action'])) //Do list table form row action tasks
        {
            if ($_REQUEST['action'] == 'delete_blocked_ip') { //Delete link was clicked for a row in list table
                $locked_ip_list->delete_lockdown_records(strip_tags($_REQUEST['lockdown_id']));
            }

            if ($_REQUEST['action'] == 'unlock_ip') { //Unlock link was clicked for a row in list table
                $locked_ip_list->unlock_ip_range(strip_tags($_REQUEST['lockdown_id']));
            }
        }

        ?>
        <div class="aio_blue_box">
            <?php
            $login_lockdown_feature_url = '<a href="admin.php?page=' . AIOWPSEC_USER_LOGIN_MENU_SLUG . '&tab=tab1" target="_blank">Login Lockdown</a>';
            echo '<p>' . __('This tab displays the list of all IP addresses which are currently temporarily locked out due to the Login Lockdown feature:', 'all-in-one-wp-security-and-firewall') . '</p>' .
                '<p>' . $login_lockdown_feature_url . '</p>';
            ?>
        </div>

        <div class="postbox">
            <h3 class="hndle"><label
                    for="title"><?php _e('Currently Locked Out IP Addresses and Ranges', 'all-in-one-wp-security-and-firewall');?></label>
            </h3>

            <div class="inside">
                <?php
                //Fetch, prepare, sort, and filter our data...
                $locked_ip_list->prepare_items();
                //echo "put table of locked entries here";
                ?>
                <form id="tables-filter" method="get"
                      onSubmit="return confirm('Are you sure you want to perform this bulk operation on the selected entries?');">
                    <!-- For plugins, we also need to ensure that the form posts back to our current page -->
                    <input type="hidden" name="page" value="<?php echo esc_attr($_REQUEST['page']); ?>"/>
                    <?php
                    if (isset($_REQUEST["tab"])) {
                        echo '<input type="hidden" name="tab" value="' . esc_attr($_REQUEST["tab"]) . '" />';
                    }
                    ?>
                    <!-- Now we can render the completed list table -->
                    <?php $locked_ip_list->display(); ?>
                </form>
            </div>
        </div>

    <?php
    }

    function render_tab4()
    {
        global $wpdb;
        include_once 'wp-security-list-permanent-blocked-ip.php'; //For rendering the AIOWPSecurity_List_Table
        $blocked_ip_list = new AIOWPSecurity_List_Blocked_IP(); //For rendering the AIOWPSecurity_List_Table

        if (isset($_REQUEST['action'])) //Do list table form row action tasks
        {
            if ($_REQUEST['action'] == 'unblock_ip') { //Unblock link was clicked for a row in list table
                $blocked_ip_list->unblock_ip_address(strip_tags($_REQUEST['blocked_id']));
            }
        }

        ?>
        <div class="aio_blue_box">
            <?php
            echo '<p>' . __('This tab displays the list of all permanently blocked IP addresses.', 'all-in-one-wp-security-and-firewall') . '</p>' .
                '<p>' . __('NOTE: This feature does NOT use the .htaccess file to permanently block the IP addresses so it should be compatible with all web servers running WordPress.', 'all-in-one-wp-security-and-firewall') . '</p>';
            ?>
        </div>

        <div class="postbox">
            <h3 class="hndle"><label
                    for="title"><?php _e('Permanently Blocked IP Addresses', 'all-in-one-wp-security-and-firewall');?></label>
            </h3>

            <div class="inside">
                <?php
                //Fetch, prepare, sort, and filter our data...
                $blocked_ip_list->prepare_items();
                ?>
                <form id="tables-filter" method="post">
                    <!-- For plugins, we also need to ensure that the form posts back to our current page -->
                    <input type="hidden" name="page" value="<?php echo esc_attr($_REQUEST['page']); ?>"/>
                    <?php
                    $blocked_ip_list->search_box('Search', 'search_permanent_block');
                    if (isset($_REQUEST["tab"])) {
                        echo '<input type="hidden" name="tab" value="' . esc_attr($_REQUEST["tab"]) . '" />';
                    }
                    ?>
                    <!-- Now we can render the completed list table -->
                    <?php $blocked_ip_list->display(); ?>
                </form>
            </div>
        </div>

    <?php
    }

    function render_tab5()
    {
        global $aio_wp_security;
        $file_selected = filter_input(INPUT_POST, 'aiowps_log_file'); // Get the selected file

        ?>
        <div class="postbox">
            <h3 class="hndle"><label
                    for="title"><?php _e('View Logs for All In WP Security & Firewall Plugin', 'all-in-one-wp-security-and-firewall');?></label>
            </h3>

            <div class="inside">
                <form action="" method="POST">
                    <?php wp_nonce_field('aiowpsec-dashboard-logs-nonce'); ?>
                    <table class="form-table">
                        <tr valign="top">
                            <th scope="row"><?php _e('Log File', 'all-in-one-wp-security-and-firewall')?>:</th>
                            <td>
                                <select id="aiowps_log_file" name="aiowps_log_file">
                                    <option
                                        value=""><?php _e('--Select a file--', 'all-in-one-wp-security-and-firewall')?></option>
                                    <option
                                        value="wp-security-log.txt" <?php selected($file_selected, 'wp-security-log.txt'); ?>>
                                        wp-security-log
                                    </option>
                                    <option
                                        value="wp-security-log-cron-job.txt" <?php selected($file_selected, 'wp-security-log-cron-job.txt'); ?>>
                                        wp-security-log-cron-job
                                    </option>
                                </select>
                                <span
                                    class="description"><?php _e('Select one of the log files to view the contents', 'all-in-one-wp-security-and-firewall'); ?></span>
                            </td>
                        </tr>
                    </table>
                    <input type="submit" name="aiowps_view_logs"
                           value="<?php _e('View Logs', 'all-in-one-wp-security-and-firewall')?>"
                           class="button-primary"/>
                </form>

            </div>
        </div>
        <?php
        if (isset($_POST['aiowps_view_logs']) && $file_selected)//Do form submission tasks
        {
            //Check nonce before doing anything
            $nonce = $_REQUEST['_wpnonce'];
            if (!wp_verify_nonce($nonce, 'aiowpsec-dashboard-logs-nonce')) {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed on dashboard view logs!", 4);
                wp_die("Error! Nonce check failed on dashboard view logs!");
            }

            //Let's make sure that the file selected can only ever be the correct log file of this plugin.
            $valid_aiowps_log_files = array('wp-security-log.txt', 'wp-security-log-cron-job.txt');
            if(!in_array($file_selected, $valid_aiowps_log_files)){
                $file_selected = '';
                unset($_POST['aiowps_view_logs']);
                wp_die(__('Error! The file you selected is not a permitted file. You can only view log files created by this plugin.','all-in-one-wp-security-and-firewall'));
            }
            
            if (!empty($file_selected)) {
                ?>
                <div class="postbox">
                    <h3 class="hndle"><label
                            for="title"><?php echo __('Log File Contents For', 'all-in-one-wp-security-and-firewall') . ': ' . $file_selected;?></label>
                    </h3>

                    <div class="inside">
                        <?php
                        $aiowps_log_dir = AIO_WP_SECURITY_PATH . '/logs';
                        $log_file = $aiowps_log_dir . '/' . $file_selected;
                        if (file_exists($log_file)) {
                            $log_contents = AIOWPSecurity_Utility_File::get_file_contents($log_file);
                        } else {
                            $log_contents = '';
                        }

                        if (empty($log_contents)) {
                            $log_contents = $file_selected . ': ' . __('Log file is empty!', 'all-in-one-wp-security-and-firewall');
                        }
                        ?>
                        <textarea class="aio_text_area_file_output aio_half_width aio_spacer_10_tb" rows="15" readonly><?php echo esc_textarea($log_contents); ?></textarea>

                    </div>
                </div>

            <?php

            }
        }
        ?>



    <?php
    }
    
    function wp_dashboard() {
	$screen = get_current_screen();
	$columns = absint( $screen->get_columns() );
	$columns_css = '';
	if ( $columns ) {
		$columns_css = " columns-$columns";
	}

?>
<div id="dashboard-widgets" class="metabox-holder<?php echo $columns_css; ?>">
    <div id="postbox-container-1" class="postbox-container">
    <?php do_meta_boxes( $screen->id, 'normal', '' ); ?>
    </div>
    <div id="postbox-container-2" class="postbox-container">
    <?php do_meta_boxes( $screen->id, 'side', '' ); ?>
    </div>
    <div id="postbox-container-3" class="postbox-container">
    <?php do_meta_boxes( $screen->id, 'column3', '' ); ?>
    </div>
    <div id="postbox-container-4" class="postbox-container">
    <?php do_meta_boxes( $screen->id, 'column4', '' ); ?>
    </div>
</div>

<?php
	wp_nonce_field( 'closedpostboxes', 'closedpostboxesnonce', false );
	wp_nonce_field( 'meta-box-order', 'meta-box-order-nonce', false );
    }
    
    function wp_dashboard_setup() {
        global $aio_wp_security;
	global $wp_registered_widgets, $wp_registered_widget_controls, $wp_dashboard_control_callbacks;
	$wp_dashboard_control_callbacks = array();
	$screen = get_current_screen();
        
        // Add widgets
        wp_add_dashboard_widget( 'security_strength_meter', __( 'Security Strength Meter' ), array(&$this, 'widget_security_strength_meter') );
        wp_add_dashboard_widget( 'security_points_breakdown', __( 'Security Points Breakdown' ), array(&$this, 'widget_security_points_breakdown') );
        wp_add_dashboard_widget( 'spread_the_word', __( 'Spread the Word' ), array(&$this, 'widget_spread_the_word') );
        wp_add_dashboard_widget( 'know_developers', __( 'Get To Know The Developers' ), array(&$this, 'widget_know_developers') );
        wp_add_dashboard_widget( 'critical_feature_status', __( 'Critical Feature Status' ), array(&$this, 'widget_critical_feature_status') );
        wp_add_dashboard_widget( 'last_5_logins', __( 'Last 5 Logins' ), array(&$this, 'widget_last_5_logins') );
        wp_add_dashboard_widget( 'maintenance_mode_status', __( 'Maintenance Mode Status' ), array(&$this, 'widget_maintenance_mode_status') );
        if ($aio_wp_security->configs->get_value('aiowps_enable_brute_force_attack_prevention') == '1' ||
                $aio_wp_security->configs->get_value('aiowps_enable_rename_login_page') == '1') {
            wp_add_dashboard_widget( 'brute_force', __( 'Brute Force Prevention Login Page' ), array(&$this, 'widget_brute_force') );
        }
        wp_add_dashboard_widget( 'logged_in_users', __( 'Logged In Users' ), array(&$this, 'widget_logged_in_users') );
        wp_add_dashboard_widget( 'locked_ip_addresses', __( 'Locked IP Addresses' ), array(&$this, 'widget_locked_ip_addresses') );

        do_action( 'aiowps_dashboard_setup' );
        $dashboard_widgets = apply_filters( 'aiowps_dashboard_widgets', array() );

	foreach ( $dashboard_widgets as $widget_id ) {
		$name = empty( $wp_registered_widgets[$widget_id]['all_link'] ) ? $wp_registered_widgets[$widget_id]['name'] : $wp_registered_widgets[$widget_id]['name'] . " <a href='{$wp_registered_widgets[$widget_id]['all_link']}' class='edit-box open-box'>" . __('View all') . '</a>';
		wp_add_dashboard_widget( $widget_id, $name, $wp_registered_widgets[$widget_id]['callback'], $wp_registered_widget_controls[$widget_id]['callback'] );
	}

	/** This action is documented in wp-admin/edit-form-advanced.php */
	do_action( 'do_meta_boxes', $screen->id, 'normal', '' );

	/** This action is documented in wp-admin/edit-form-advanced.php */
	do_action( 'do_meta_boxes', $screen->id, 'side', '' );
    }
    
    function widget_security_strength_meter() {
        global $aiowps_feature_mgr;
        global $aio_wp_security;
        $total_site_security_points = $aiowps_feature_mgr->get_total_site_points();
        $total_security_points_achievable = $aiowps_feature_mgr->get_total_achievable_points();

        ?>
        <script type='text/javascript'>
            google.load('visualization', '1', {packages: ['gauge']});
            google.setOnLoadCallback(drawChart);
            function drawChart() {
                var data = google.visualization.arrayToDataTable([
                    ['Label', 'Value'],
                    ['Strength', <?php echo $total_site_security_points; ?>]
                ]);

                var options = {
                    width: 320, height: 200, max: <?php echo $total_security_points_achievable; ?>,
                    greenColor: '8EFA9B', yellowColor: 'F5EE90', redColor: 'FA7373',
                    redFrom: 0, redTo: 10,
                    yellowFrom: 10, yellowTo: 50,
                    greenFrom: 50, greenTo: <?php echo $total_security_points_achievable; ?>,
                    minorTicks: 5
                };

                var chart = new google.visualization.Gauge(document.getElementById('security_strength_chart_div'));
                chart.draw(data, options);
            }
        </script>
        <div id='security_strength_chart_div'></div>
        <div class="aiowps_dashboard_widget_footer">
            <?php
            _e('Total Achievable Points: ', 'all-in-one-wp-security-and-firewall');
            echo '<strong>' . $total_security_points_achievable . '</strong><br />';
            _e('Current Score of Your Site: ', 'all-in-one-wp-security-and-firewall');
            echo '<strong>' . $total_site_security_points . '</strong>';
            ?>
        </div>        
        <?php
    }
    
    function widget_security_points_breakdown() {
        global $aiowps_feature_mgr;
        global $aio_wp_security;
        $feature_mgr = $aiowps_feature_mgr;
        $total_site_security_points = $feature_mgr->get_total_site_points();
        $total_security_points_achievable = $feature_mgr->get_total_achievable_points();
        
                                $feature_items = $feature_mgr->feature_items;
                        $pt_src_chart_data = "";
                        $pt_src_chart_data .= "['Feature Name', 'Points'],";
                        foreach ($feature_items as $item) {
                            if ($item->feature_status == $feature_mgr->feature_active) {
                                $pt_src_chart_data .= "['" . $item->feature_name . "', " . $item->item_points . "],";
                            }
                        }

                        ?>
                        <script type="text/javascript">
                            google.load("visualization", "1", {packages: ["corechart"]});
                            google.setOnLoadCallback(drawChart);
                            function drawChart() {
                                var data = google.visualization.arrayToDataTable([
                                    <?php echo $pt_src_chart_data; ?>
                                ]);

                                var options = {
//                                    height: '250',
//                                    width: '450',
                                    backgroundColor: 'F6F6F6',
                                    pieHole: 0.4,
                                    chartArea: {
                                        width: '95%',
                                        height: '95%',
                                    }
                                };

                                var chart = new google.visualization.PieChart(document.getElementById('points_source_breakdown_chart_div'));
                                chart.draw(data, options);
                            }
                        </script>
                        <div id='points_source_breakdown_chart_div'></div>
<?php
    }
    
    function widget_spread_the_word() {
?>
        <p><?php _e('We are working hard to make your WordPress site more secure. Please support us, here is how:', 'all-in-one-wp-security-and-firewall');?></p>
        <p><a href="https://plus.google.com/+Tipsandtricks-hq/" target="_blank">Follow us on
                Google+</a>
        </p>
        <p>
            <a href="http://twitter.com/intent/tweet?url=https://www.tipsandtricks-hq.com/wordpress-security-and-firewall-plugin&text=I love the All In One WP Security and Firewall plugin!"
               target="_blank" class="aio_tweet_link">Post to Twitter</a>
        </p>
        <p>
            <a href="http://wordpress.org/support/view/plugin-reviews/all-in-one-wp-security-and-firewall/"
               target="_blank" class="aio_rate_us_link">Give us a Good Rating</a>
        </p>                        
<?php                        
    }
    
    function widget_know_developers() {
?>
        <p><?php _e('Wanna know more about the developers behind this plugin?', 'all-in-one-wp-security-and-firewall');?></p>
        <p><a href="https://wpsolutions-hq.com/" target="_blank">WPSolutions</a></p>
        <p><a href="https://www.tipsandtricks-hq.com/" target="_blank">Tips and Tricks HQ</a></p>

<?php        
    }
    
    function widget_critical_feature_status() {
        global $aiowps_feature_mgr;
        global $aio_wp_security;
        $feature_mgr = $aiowps_feature_mgr;

        _e('Below is the current status of the critical features that you should activate on your site to achieve a minimum level of recommended security', 'all-in-one-wp-security-and-firewall');
        $feature_items = $aiowps_feature_mgr->feature_items;
        $username_admin_feature = $aiowps_feature_mgr->get_feature_item_by_id("user-accounts-change-admin-user");
        echo '<div class="aiowps_feature_status_container">';
        echo '<div class="aiowps_feature_status_name">' . __('Admin Username', 'all-in-one-wp-security-and-firewall') . '</div>';
        echo '<a href="admin.php?page=' . AIOWPSEC_USER_ACCOUNTS_MENU_SLUG . '">';
        echo '<div class="aiowps_feature_status_bar">';
        if ($username_admin_feature->feature_status == $aiowps_feature_mgr->feature_active) {
            echo '<div class="aiowps_feature_status_label aiowps_feature_status_on">On</div>';
            echo '<div class="aiowps_feature_status_label">Off</div>';
        } else {
            echo '<div class="aiowps_feature_status_label">On</div>';
            echo '<div class="aiowps_feature_status_label aiowps_feature_status_off">Off</div>';
        }
        echo '</div></div></a>';
        echo '<div class="aio_clear_float"></div>';

        $login_lockdown_feature = $aiowps_feature_mgr->get_feature_item_by_id("user-login-login-lockdown");
        echo '<div class="aiowps_feature_status_container">';
        echo '<div class="aiowps_feature_status_name">' . __('Login Lockdown', 'all-in-one-wp-security-and-firewall') . '</div>';
        echo '<a href="admin.php?page=' . AIOWPSEC_USER_LOGIN_MENU_SLUG . '">';
        echo '<div class="aiowps_feature_status_bar">';
        if ($login_lockdown_feature->feature_status == $aiowps_feature_mgr->feature_active) {
            echo '<div class="aiowps_feature_status_label aiowps_feature_status_on">On</div>';
            echo '<div class="aiowps_feature_status_label">Off</div>';
        } else {
            echo '<div class="aiowps_feature_status_label">On</div>';
            echo '<div class="aiowps_feature_status_label aiowps_feature_status_off">Off</div>';
        }
        echo '</div></div></a>';
        echo '<div class="aio_clear_float"></div>';

        $filesystem_feature = $aiowps_feature_mgr->get_feature_item_by_id("filesystem-file-permissions");
        echo '<div class="aiowps_feature_status_container">';
        echo '<div class="aiowps_feature_status_name">' . __('File Permission', 'all-in-one-wp-security-and-firewall') . '</div>';
        echo '<a href="admin.php?page=' . AIOWPSEC_FILESYSTEM_MENU_SLUG . '">';
        echo '<div class="aiowps_feature_status_bar">';
        if ($filesystem_feature->feature_status == $aiowps_feature_mgr->feature_active) {
            echo '<div class="aiowps_feature_status_label aiowps_feature_status_on">On</div>';
            echo '<div class="aiowps_feature_status_label">Off</div>';
        } else {
            echo '<div class="aiowps_feature_status_label">On</div>';
            echo '<div class="aiowps_feature_status_label aiowps_feature_status_off">Off</div>';
        }
        echo '</div></div></a>';
        echo '<div class="aio_clear_float"></div>';

        $basic_firewall_feature = $aiowps_feature_mgr->get_feature_item_by_id("firewall-basic-rules");
        echo '<div class="aiowps_feature_status_container">';
        echo '<div class="aiowps_feature_status_name">' . __('Basic Firewall', 'all-in-one-wp-security-and-firewall') . '</div>';
        echo '<a href="admin.php?page=' . AIOWPSEC_FIREWALL_MENU_SLUG . '">';
        echo '<div class="aiowps_feature_status_bar">';
        if ($basic_firewall_feature->feature_status == $aiowps_feature_mgr->feature_active) {
            echo '<div class="aiowps_feature_status_label aiowps_feature_status_on">On</div>';
            echo '<div class="aiowps_feature_status_label">Off</div>';
        } else {
            echo '<div class="aiowps_feature_status_label">On</div>';
            echo '<div class="aiowps_feature_status_label aiowps_feature_status_off">Off</div>';
        }
        echo '</div></div></a>';
        echo '<div class="aio_clear_float"></div>';
    }
    
    function widget_last_5_logins() {
        global $wpdb;
        $login_activity_table = AIOWPSEC_TBL_USER_LOGIN_ACTIVITY;

        /* -- Ordering parameters -- */
        //Parameters that are going to be used to order the result
        isset($_GET["orderby"]) ? $orderby = strip_tags($_GET["orderby"]) : $orderby = '';
        isset($_GET["order"]) ? $order = strip_tags($_GET["order"]) : $order = '';

        $orderby = !empty($orderby) ? $orderby : 'login_date';
        $order = !empty($order) ? $order : 'DESC';

        $data = $wpdb->get_results($wpdb->prepare("SELECT * FROM $login_activity_table ORDER BY login_date DESC LIMIT %d", 5), ARRAY_A); //Get the last 5 records

        if ($data == NULL) {
            echo '<p>' . __('No data found!', 'all-in-one-wp-security-and-firewall') . '</p>';

        } else {
            $login_summary_table = '';
            echo '<p>' . __('Last 5 logins summary:', 'all-in-one-wp-security-and-firewall') . '</p>';
            $login_summary_table .= '<table class="widefat aiowps_dashboard_table">';
            $login_summary_table .= '<thead>';
            $login_summary_table .= '<tr>';
            $login_summary_table .= '<th>' . __('User', 'all-in-one-wp-security-and-firewall') . '</th>';
            $login_summary_table .= '<th>' . __('Date', 'all-in-one-wp-security-and-firewall') . '</th>';
            $login_summary_table .= '<th>' . __('IP', 'all-in-one-wp-security-and-firewall') . '</th>';
            $login_summary_table .= '</tr>';
            $login_summary_table .= '</thead>';
            foreach ($data as $entry) {
                $login_summary_table .= '<tr>';
                $login_summary_table .= '<td>' . $entry['user_login'] . '</td>';
                $login_summary_table .= '<td>' . $entry['login_date'] . '</td>';
                $login_summary_table .= '<td>' . $entry['login_ip'] . '</td>';
                $login_summary_table .= '</tr>';
            }
            $login_summary_table .= '</table>';
            echo $login_summary_table;
        }

        echo '<div class="aio_clear_float"></div>';
        
    }
    
    function widget_maintenance_mode_status() {
        global $aio_wp_security;
        if ($aio_wp_security->configs->get_value('aiowps_site_lockout') == '1') {
            echo '<p>' . __('Maintenance mode is currently enabled. Remember to turn it off when you are done', 'all-in-one-wp-security-and-firewall') . '</p>';
        } else {
            echo '<p>' . __('Maintenance mode is currently off.', 'all-in-one-wp-security-and-firewall') . '</p>';
        }

        echo '<div class="aiowps_feature_status_container">';
        echo '<div class="aiowps_feature_status_name">' . __('Maintenance Mode', 'all-in-one-wp-security-and-firewall') . '</div>';
        echo '<a href="admin.php?page=' . AIOWPSEC_MAINTENANCE_MENU_SLUG . '">';
        echo '<div class="aiowps_feature_status_bar">';
        if ($aio_wp_security->configs->get_value('aiowps_site_lockout') == '1') {//Maintenance mode is enabled
            echo '<div class="aiowps_feature_status_label aiowps_feature_status_off">On</div>';//If enabled show red by usign the "off" class
            echo '<div class="aiowps_feature_status_label">Off</div>';
        } else {
            echo '<div class="aiowps_feature_status_label">On</div>';
            echo '<div class="aiowps_feature_status_label aiowps_feature_status_on">Off</div>';
        }
        echo '</div></div></a>';
        echo '<div class="aio_clear_float"></div>';
        
    }
    
    function widget_brute_force() {
        global $aio_wp_security;
        if ($aio_wp_security->configs->get_value('aiowps_enable_brute_force_attack_prevention') == '1') {
            $brute_force_login_feature_link = '<a href="admin.php?page=' . AIOWPSEC_BRUTE_FORCE_MENU_SLUG . '&tab=tab2" target="_blank">' . __('Cookie-Based Brute Force', 'all-in-one-wp-security-and-firewall') . '</a>';
            $brute_force_feature_secret_word = $aio_wp_security->configs->get_value('aiowps_brute_force_secret_word');
            echo '<div class="aio_yellow_box">';

            echo '<p>' . sprintf(__('The %s feature is currently active.', 'all-in-one-wp-security-and-firewall'), $brute_force_login_feature_link) . '</p>';
            echo '<p>' . __('Your new WordPress login URL is now:', 'all-in-one-wp-security-and-firewall') . '</p>';
            echo '<p><strong>' . AIOWPSEC_WP_URL . '/?' . $brute_force_feature_secret_word . '=1</strong></p>';
            echo '</div>'; //yellow box div
            echo '<div class="aio_clear_float"></div>';
        }//End if statement for Cookie Based Brute Prevention box

        //Insert Rename Login Page feature box if this feature is active
        if ($aio_wp_security->configs->get_value('aiowps_enable_rename_login_page') == '1') {
            if (get_option('permalink_structure')) {
                $home_url = trailingslashit(home_url());
            } else {
                $home_url = trailingslashit(home_url()) . '?';
            }

            $rename_login_feature_link = '<a href="admin.php?page=' . AIOWPSEC_BRUTE_FORCE_MENU_SLUG . '&tab=tab1" target="_blank">' . __('Rename Login Page', 'all-in-one-wp-security-and-firewall') . '</a>';
            echo '<div class="aio_yellow_box">';

            echo '<p>' . sprintf(__('The %s feature is currently active.', 'all-in-one-wp-security-and-firewall'), $rename_login_feature_link) . '</p>';
            echo '<p>' . __('Your new WordPress login URL is now:', 'all-in-one-wp-security-and-firewall') . '</p>';
            echo '<p><strong>' . $home_url . $aio_wp_security->configs->get_value('aiowps_login_page_slug') . '</strong></p>';
            echo '</div>'; //yellow box div
            echo '<div class="aio_clear_float"></div>';
        }//End if statement for Rename Login box
        
    }
    
    function widget_logged_in_users() {
        $users_online_link = '<a href="admin.php?page=' . AIOWPSEC_USER_LOGIN_MENU_SLUG . '&tab=tab5">Logged In Users</a>';
        if (AIOWPSecurity_Utility::is_multisite_install()) {
            $logged_in_users = get_site_transient('users_online');
            $num_users = count($logged_in_users);
            if ($num_users > 1) {
                echo '<div class="aio_red_box"><p>' . __('Number of users currently logged in site-wide is:', 'all-in-one-wp-security-and-firewall') . ' <strong>' . $num_users . '</strong></p>';
                $info_msg = '<p>' . sprintf(__('Go to the %s menu to see more details', 'all-in-one-wp-security-and-firewall'), $users_online_link) . '</p>';
                echo $info_msg . '</div>';
            } else {
                echo '<div class="aio_green_box"><p>' . __('There are no other site-wide users currently logged in.', 'all-in-one-wp-security-and-firewall') . '</p></div>';
            }
        } else {
            $logged_in_users = get_transient('users_online');
            if ($logged_in_users === false || $logged_in_users == NULL) {
                $num_users = 0;
            } else {
                $num_users = count($logged_in_users);
            }
            if ($num_users > 1) {
                echo '<div class="aio_red_box"><p>' . __('Number of users currently logged into your site (including you) is:', 'all-in-one-wp-security-and-firewall') . ' <strong>' . $num_users . '</strong></p>';
                $info_msg = '<p>' . sprintf(__('Go to the %s menu to see more details', 'all-in-one-wp-security-and-firewall'), $users_online_link) . '</p>';
                echo $info_msg . '</div>';
            } else {
                echo '<div class="aio_green_box"><p>' . __('There are no other users currently logged in.', 'all-in-one-wp-security-and-firewall') . '</p></div>';
            }
        }        
    }
    
    function widget_locked_ip_addresses() {
        $locked_ips_link = '<a href="admin.php?page=' . AIOWPSEC_MAIN_MENU_SLUG . '&tab=tab3">Locked IP Addresses</a>';

        $locked_ips = AIOWPSecurity_Utility::get_locked_ips();
        if ($locked_ips === FALSE) {
            echo '<div class="aio_green_box"><p>' . __('There are no IP addresses currently locked out.', 'all-in-one-wp-security-and-firewall') . '</p></div>';
        } else {
            $num_ips = count($locked_ips);
            echo '<div class="aio_red_box"><p>' . __('Number of temporarily locked out IP addresses: ', 'all-in-one-wp-security-and-firewall') . ' <strong>' . $num_ips . '</strong></p>';
            $info_msg = '<p>' . sprintf(__('Go to the %s menu to see more details', 'all-in-one-wp-security-and-firewall'), $locked_ips_link) . '</p>';
            echo $info_msg . '</div>';
        }
    }

} //end class