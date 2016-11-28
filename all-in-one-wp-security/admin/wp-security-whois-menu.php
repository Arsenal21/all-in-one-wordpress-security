<?php

class AIOWPSecurity_WhoIs_Menu extends AIOWPSecurity_Admin_Menu
{
    var $menu_page_slug = AIOWPSEC_WHOIS_MENU_SLUG;
    
    /* Specify all the tabs of this menu in the following array */
    var $menu_tabs;

    var $menu_tabs_handler = array(
        'tab1' => 'render_tab1', 
        );
    
    function __construct() 
    {
        $this->render_menu_page();
    }
    
    function set_menu_tabs() 
    {
        $this->menu_tabs = array(
        'tab1' => __('WhoIS Lookup', 'all-in-one-wp-security-and-firewall'),
        );
    }

    function get_current_tab() 
    {
        $tab_keys = array_keys($this->menu_tabs);
        $tab = isset( $_GET['tab'] ) ? sanitize_text_field($_GET['tab']) : $tab_keys[0];
        return $tab;
    }

    /*
     * Renders our tabs of this menu as nav items
     */
    function render_menu_tabs() 
    {
        $current_tab = $this->get_current_tab();

        echo '<h2 class="nav-tab-wrapper">';
        foreach ( $this->menu_tabs as $tab_key => $tab_caption ) 
        {
            $active = $current_tab == $tab_key ? 'nav-tab-active' : '';
            echo '<a class="nav-tab ' . $active . '" href="?page=' . $this->menu_page_slug . '&tab=' . $tab_key . '">' . $tab_caption . '</a>';	
        }
        echo '</h2>';
    }
    
    /*
     * The menu rendering goes here
     */
    function render_menu_page() 
    {
        echo '<div class="wrap">';
        echo '<h2>'.__('WHOIS Lookup','all-in-one-wp-security-and-firewall').'</h2>';//Interface title
        $this->set_menu_tabs();
        $tab = $this->get_current_tab();
        $this->render_menu_tabs();
        ?>        
        <div id="poststuff"><div id="post-body">
        <?php 
        //$tab_keys = array_keys($this->menu_tabs);
        call_user_func(array(&$this, $this->menu_tabs_handler[$tab]));
        ?>
        </div></div>
        </div><!-- end of wrap -->
        <?php
    }
    
    function render_tab1()
    {
        global $aio_wp_security;

        ?>
        <h2><?php _e('WHOIS Lookup Information', 'all-in-one-wp-security-and-firewall')?></h2>
        <div class="aio_blue_box">
            <?php
            echo '<p>'.__('This feature allows you to look up more detailed information about an IP address or domain name by querying the WHOIS API.', 'all-in-one-wp-security-and-firewall').'
            </p>';
            ?>
        </div>

        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('Perform a WHOIS Lookup for an IP or Domain Name', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
            <form action="" method="POST">
                <?php wp_nonce_field('aiowpsec-whois-lookup-nonce'); ?>
                <table class="form-table">
                <tr valign="top">
                    <th scope="row"><?php _e('Enter IP Address or Domain Name', 'all-in-one-wp-security-and-firewall')?>:</th>
                    <td><input type="text" size="20" name="aiowps_whois_lookup_field" value="<?php //echo $aio_wp_security->configs->get_value('aiowps_whois_lookup_field'); ?>" />
                    <span class="description"><?php _e('Enter an IP address or domain name. Example: 111.11.12.13 OR some-domain-name.com', 'all-in-one-wp-security-and-firewall'); ?></span>
                    </td> 
                </tr>
                </table>
                <input type="submit" name="aiowps_whois_lookup" value="<?php _e('Perform IP or Domain Lookup', 'all-in-one-wp-security-and-firewall')?>" class="button-primary ip-domain-lookup" />
            </form>
        </div></div>
    <?php
        if (isset($_POST['aiowps_whois_lookup']))
        {
            $nonce=$_REQUEST['_wpnonce'];
            if (!wp_verify_nonce($nonce, 'aiowpsec-whois-lookup-nonce'))
            {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed on WHOIS lookup!",4);
                die("Nonce check failed on WHOIS lookup!");
            }
            
            require_once(AIO_WP_SECURITY_LIB_PATH.'/whois/whois.main.php');
            require_once(AIO_WP_SECURITY_LIB_PATH.'/whois/whois.utils.php');
            $input_val = trim($_POST['aiowps_whois_lookup_field']);
            $input_val = preg_replace('#^https?://#', '', $input_val);
            if (filter_var($input_val, FILTER_VALIDATE_IP) || filter_var(gethostbyname($input_val), FILTER_VALIDATE_IP))
            {
                //$info_msg_string = '<p class="aio_info_with_icon">'.sprintf( __('WHOIS lookup successfully completed. Please see the results below:', 'all-in-one-wp-security-and-firewall')).'</p>';
                //echo ($info_msg_string);
                $this->show_msg_updated(__('WHOIS lookup successfully completed. Please see the results below:', 'all-in-one-wp-security-and-firewall'));
                $whois = new Whois();
                $result = $whois->Lookup($input_val);
                if (!empty($result['rawdata']))
                {
                    $utils = new utils;
                    $winfo = $utils->showHTML($result);
                    echo $winfo;
                }
            }
            else
            {
                $this->show_msg_error(__('You have entered an incorrectly formatted IP address or domain name. Please try again.','all-in-one-wp-security-and-firewall'));
            }
        }
    }
} //end class