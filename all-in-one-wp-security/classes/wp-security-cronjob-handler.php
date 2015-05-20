<?php

class AIOWPSecurity_Cronjob_Handler {
    function __construct()
    {
        add_action ('aiowps_hourly_cron_event', array(&$this, 'aiowps_hourly_cron_event_handler'));
        add_action ('aiowps_daily_cron_event', array(&$this, 'aiowps_daily_cron_event_handler'));
    }
    
    function aiowps_hourly_cron_event_handler()
    {
        //Do stuff that needs checking every hours
        global $aio_wp_security;
        //$aio_wp_security->debug_logger->log_debug_cron("Cronjob_Handler - Hourly cron handler got fired.");
        
        //do_action('aiowps_force_logout_check');
        //do_action('aiowps_check_password_stuff');   
        do_action('aiowps_perform_scheduled_backup_tasks');
        do_action('aiowps_perform_fcd_scan_tasks');
    }
    
    function aiowps_daily_cron_event_handler()
    {
        //Do stuff that needs checking daily
        global $aio_wp_security;
        $aio_wp_security->debug_logger->log_debug_cron("Cronjob_Handler - Daily cron handler got fired.");
        
        do_action('aiowps_perform_db_cleanup_tasks');
    }

}

