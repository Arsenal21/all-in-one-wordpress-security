<?php

/* Parent class for all admin menu classes */
abstract class AIOWPSecurity_Admin_Menu
{
    /* Specify all the tabs of menu in the following array */
    var $menu_tabs;

    /**
     * Renders menu page
     * @param string $title Page title
     */
    function __construct($title)
    {
        $this->render_menu_page($this->get_current_tab(), $title);
    }

    /**
     * Returns current tab from _GET parameter (checks it against defined tabs first).
     * If no current tab is given or value is invalid, returns first tab.
     *
     * @return string Current tab key
     */
    function get_current_tab()
    {
        $tab_keys = array_keys($this->menu_tabs);
        return isset($_GET['tab']) && isset($this->menu_tabs[$_GET['tab']]) ? $_GET['tab'] : $tab_keys[0];
    }

    /**
     * Render page
     * @param string $current_tab Current tab key
     * @param string $title Page title
     */
    function render_menu_page($current_tab, $title)
    {
        ?>
        <div class="wrap">
        <h2><?php echo esc_html($title); // echo page title ?></h2>
        <?php $this->render_menu_tabs($current_tab); // render page tab navigation ?>
        <div id="poststuff"><div id="post-body">
        <?php call_user_func(array($this, $this->menu_tabs_handler[$current_tab])); // render current tab content ?>
        </div></div>
        </div><!-- end of wrap -->
        <?php
    }

    /**
     * Renders our tabs of menu as nav items
     * @param string $current_tab Current tab key (to highlight tab nav item)
     */
    function render_menu_tabs($current_tab)
    {
        echo '<h2 class="nav-tab-wrapper">';
        foreach ( $this->menu_tabs as $tab_key => $tab_caption )
        {
            $active = $current_tab == $tab_key ? 'nav-tab-active' : '';
            echo '<a class="nav-tab ' . $active . '" href="?page=' . $this->menu_page_slug . '&tab=' . $tab_key . '">' . $tab_caption . '</a>';
        }
        echo '</h2>';
    }

    /**
     * Shows postbox for settings menu
     *
     * @param string $id css ID for postbox
     * @param string $title title of the postbox section
     * @param string $content the content of the postbox
     **/
    function postbox_toggle($id, $title, $content) 
    {
        //Always send string with translation markers in it
        ?>
        <div id="<?php echo $id; ?>" class="postbox">
            <div class="handlediv" title="Click to toggle"><br /></div>
            <h3 class="hndle"><span><?php echo $title; ?></span></h3>
            <div class="inside">
            <?php echo $content; ?>
            </div>
        </div>
        <?php
    }
    
    function postbox($title, $content) 
    {
        //Always send string with translation markers in it
        ?>
        <div class="postbox">
        <h3 class="hndle"><label for="title"><?php echo $title; ?></label></h3>
        <div class="inside">
            <?php echo $content; ?>
        </div>
        </div>
        <?php
    } 
    
    function show_msg_settings_updated()
    {
        echo '<div id="message" class="updated fade"><p><strong>';
        _e('Settings successfully updated.','all-in-one-wp-security-and-firewall');
        echo '</strong></p></div>';
    }
    
    static function show_msg_record_deleted_st()
    {
        echo '<div id="message" class="updated fade"><p><strong>';
        _e('The selected record(s) deleted successfully!','all-in-one-wp-security-and-firewall');
        echo '</strong></p></div>';
    }
    
    function show_msg_updated($msg)
    {
        echo '<div id="message" class="updated fade"><p><strong>';
        echo $msg;
        echo '</strong></p></div>';
    }
    
    static function show_msg_updated_st($msg)
    {
        echo '<div id="message" class="updated fade"><p><strong>';
        echo $msg;
        echo '</strong></p></div>';
    }
    
    function show_msg_error($error_msg)
    {
        echo '<div id="message" class="error"><p><strong>';
        echo $error_msg;
        echo '</strong></p></div>';
    }
    
    static function show_msg_error_st($error_msg)
    {
        echo '<div id="message" class="error"><p><strong>';
        echo $error_msg;
        echo '</strong></p></div>';
    }
    
    function start_buffer()
    {
        ob_start();
    }
    
    function end_buffer_and_collect()
    {
        $output = ob_get_contents();
        ob_end_clean();
        return $output;
    }
}