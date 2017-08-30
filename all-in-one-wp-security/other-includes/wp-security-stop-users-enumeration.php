<?php

/*
 * Merged by Davide Giunchi, from plugin "Stop User Enumeration" url "http://locally.uk/wordpress-plugins/stop-user-enumeration/" by "Locally Digital Ltd"
 */

if (!is_admin() && isset($_SERVER['REQUEST_URI'])) {
    if (preg_match('/(wp-comments-post)/', $_SERVER['REQUEST_URI']) === 0 && !empty($_REQUEST['author'])) {
        wp_die('Accessing author info via link is forbidden');
    }
}

if(( preg_match('/users/', $_SERVER['REQUEST_URI']) !== 0 ) || ( isset($_REQUEST['rest_route']) && ( preg_match('/users/', $_REQUEST['rest_route']) !== 0 ))){
     if( ! is_user_logged_in() ) {
        wp_die('Accessing author info via REST API is forbidden');      
     }
}
