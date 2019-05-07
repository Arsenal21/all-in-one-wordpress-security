<?php

/* Parent class for all admin menu classes */

if(!defined('ABSPATH')){
    exit;//Exit if accessed directly
}

abstract class AIOWPSecurity_Admin_Menu
{
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
    
    static function display_bulk_result_message()
    {
        if(isset($_GET['bulk_count'])) {
            AIOWPSecurity_Admin_Menu::show_msg_updated_st(__('The bulk action was successful', 'all-in-one-wp-security-and-firewall'));
        }
        
        if(isset($_GET['bulk_error'])) {
            AIOWPSecurity_Admin_Menu::show_msg_error_st(__('The bulk action failed', 'all-in-one-wp-security-and-firewall'));            
        }
    }
}