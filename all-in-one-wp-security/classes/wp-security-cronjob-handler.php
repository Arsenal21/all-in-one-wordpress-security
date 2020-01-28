<?php
if(!defined('ABSPATH')){
    exit;//Exit if accessed directly
}

class AIOWPSecurity_Cronjob_Handler {
    function __construct()
    {
        add_action ('aiowps_hourly_cron_event', array(&$this, 'aiowps_hourly_cron_event_handler'));
        add_action ('aiowps_daily_cron_event', array(&$this, 'aiowps_daily_cron_event_handler'));
    }
    
    function aiowps_hourly_cron_event_handler()
    {
        //Do stuff that needs checking hourly
        do_action('aiowps_perform_scheduled_backup_tasks');
        do_action('aiowps_perform_fcd_scan_tasks');
        do_action('aiowps_perform_db_cleanup_tasks');
    }
    
    function aiowps_daily_cron_event_handler()
    {
        //Do stuff that needs checking daily
    }

}

