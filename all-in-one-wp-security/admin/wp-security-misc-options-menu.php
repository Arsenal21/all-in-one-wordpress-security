<?php

class AIOWPSecurity_Misc_Options_Menu extends AIOWPSecurity_Admin_Menu
{
    var $menu_page_slug = AIOWPSEC_MISC_MENU_SLUG;
    
    /* Specify all the tabs of this menu in the following array */
    var $menu_tabs;

    var $menu_tabs_handler = array(
        'tab1' => 'render_tab1',
        'tab2' => 'render_tab2',
        'tab3' => 'render_tab3',
        );

    function __construct() 
    {
        $this->render_menu_page();
    }

    function set_menu_tabs() 
    {
        $this->menu_tabs = array(
        'tab1' => __('Copy Protection', 'all-in-one-wp-security-and-firewall'),
        'tab2' => __('Frames', 'all-in-one-wp-security-and-firewall'),
        'tab3' => __('Users Enumeration', 'all-in-one-wp-security-and-firewall'),
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
        echo '<h2>'.__('Miscellaneous','all-in-one-wp-security-and-firewall').'</h2>';//Interface title
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
        $maint_msg = '';
        if(isset($_POST['aiowpsec_save_copy_protection']))
        {
            $nonce=$_REQUEST['_wpnonce'];
            if (!wp_verify_nonce($nonce, 'aiowpsec-copy-protection'))
            {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed on copy protection feature settings save!",4);
                die("Nonce check failed on copy protection feature settings save!");
            }
            
            //Save settings
            $aio_wp_security->configs->set_value('aiowps_copy_protection',isset($_POST["aiowps_copy_protection"])?'1':'');
            $aio_wp_security->configs->save_config();

            $this->show_msg_updated(__('Copy Protection feature settings saved!', 'all-in-one-wp-security-and-firewall'));

        }
        ?>
        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('Disable The Ability To Copy Text', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
        <form action="" method="POST">
        <?php wp_nonce_field('aiowpsec-copy-protection'); ?>
        <div class="aio_blue_box">
            <?php
            echo '<p>'.__('This feature allows you to disable the ability to select and copy text from your front end.', 'all-in-one-wp-security-and-firewall').'</p>';
            echo '<p>'.__('When admin user is logged in, the feature is automatically disabled for his session.', 'all-in-one-wp-security-and-firewall').'</p>';
            ?>
        </div>
        <table class="form-table">
            <tr valign="top">
                <th scope="row"><?php _e('Enable Copy Protection', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td>
                <input name="aiowps_copy_protection" type="checkbox"<?php if($aio_wp_security->configs->get_value('aiowps_copy_protection')=='1') echo ' checked="checked"'; ?> value="1"/>
                <span class="description"><?php _e('Check this if you want to disable the "Right Click", "Text Selection" and "Copy" option on the front end of your site.', 'all-in-one-wp-security-and-firewall'); ?></span>
                </td>
            </tr>

        </table>
    
        <div class="submit">
            <input type="submit" class="button-primary" name="aiowpsec_save_copy_protection" value="<?php _e('Save Copy Protection Settings'); ?>" />
        </div>
        </form>   
        </div></div>
        <?php
    }
    
    function render_tab2()
    {
        global $aio_wp_security;
        $maint_msg = '';
        if(isset($_POST['aiowpsec_save_frame_display_prevent']))
        {
            $nonce=$_REQUEST['_wpnonce'];
            if (!wp_verify_nonce($nonce, 'aiowpsec-prevent-display-frame'))
            {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed on prevent display inside frame feature settings save!",4);
                die("Nonce check failed on prevent display inside frame feature settings save!");
            }
            
            //Save settings
            $aio_wp_security->configs->set_value('aiowps_prevent_site_display_inside_frame',isset($_POST["aiowps_prevent_site_display_inside_frame"])?'1':'');
            $aio_wp_security->configs->save_config();

            $this->show_msg_updated(__('Frame Display Prevention feature settings saved!', 'all-in-one-wp-security-and-firewall'));

        }
        ?>
        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('Prevent Your Site From Being Displayed In a Frame', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
        <form action="" method="POST">
        <?php wp_nonce_field('aiowpsec-prevent-display-frame'); ?>
        <div class="aio_blue_box">
            <?php
            echo '<p>'.__('This feature allows you to prevent other sites from displaying any of your content via a frame or iframe.', 'all-in-one-wp-security-and-firewall').'</p>';
            echo '<p>'.__('When enabled, this feature will set the "X-Frame-Options" paramater to "sameorigin" in the HTTP header.', 'all-in-one-wp-security-and-firewall').'</p>';
            ?>
        </div>
        <table class="form-table">
            <tr valign="top">
                <th scope="row"><?php _e('Enable iFrame Protection', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td>
                <input name="aiowps_prevent_site_display_inside_frame" type="checkbox"<?php if($aio_wp_security->configs->get_value('aiowps_prevent_site_display_inside_frame')=='1') echo ' checked="checked"'; ?> value="1"/>
                <span class="description"><?php _e('Check this if you want to stop other sites from displaying your content in a frame or iframe.', 'all-in-one-wp-security-and-firewall'); ?></span>
                </td>
            </tr>

        </table>
    
        <div class="submit">
            <input type="submit" class="button-primary" name="aiowpsec_save_frame_display_prevent" value="<?php _e('Save Settings'); ?>" />
        </div>
        </form>   
        </div></div>
        <?php
    }
    
    function render_tab3()
    {
        global $aio_wp_security;
        $maint_msg = '';
        if(isset($_POST['aiowpsec_save_users_enumeration']))
        {
            $nonce=$_REQUEST['_wpnonce'];
            if (!wp_verify_nonce($nonce, 'aiowpsec-users-enumeration'))
            {
                $aio_wp_security->debug_logger->log_debug("Nonce check failed on prevent users enumeration feature settings save!",4);
                die("Nonce check failed on prevent users enumeration feature settings save!");
            }

            //Save settings
            $aio_wp_security->configs->set_value('aiowps_prevent_users_enumeration',isset($_POST["aiowps_prevent_users_enumeration"])?'1':'');
            $aio_wp_security->configs->save_config();

            $this->show_msg_updated(__('Users Enumeration Prevention feature settings saved!', 'all-in-one-wp-security-and-firewall'));

        }
        ?>
        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php _e('Prevent Users Enumeration', 'all-in-one-wp-security-and-firewall'); ?></label></h3>
        <div class="inside">
        <form action="" method="POST">
        <?php wp_nonce_field('aiowpsec-users-enumeration'); ?>
        <div class="aio_blue_box">
            <?php
            echo '<p>'.__('This feature allows you to prevent external users/bots from fetching the user info with urls like "/?author=1".', 'all-in-one-wp-security-and-firewall').'</p>';
            echo '<p>'.__('When enabled, this feature will print a "forbidden" error rather than the user information.', 'all-in-one-wp-security-and-firewall').'</p>';
            ?>
        </div>
        <table class="form-table">
            <tr valign="top">
                <th scope="row"><?php _e('Disable Users Enumeration', 'all-in-one-wp-security-and-firewall')?>:</th>
                <td>
                <input name="aiowps_prevent_users_enumeration" type="checkbox"<?php if($aio_wp_security->configs->get_value('aiowps_prevent_users_enumeration')=='1') echo ' checked="checked"'; ?> value="1"/>
                <span class="description"><?php _e('Check this if you want to stop users enumeration.', 'all-in-one-wp-security-and-firewall'); ?></span>
                </td>
            </tr>

        </table>

        <div class="submit">
            <input type="submit" class="button-primary" name="aiowpsec_save_users_enumeration" value="<?php _e('Save Settings'); ?>" />
        </div>
        </form>
        </div></div>
        <?php
    }

    
} //end class
