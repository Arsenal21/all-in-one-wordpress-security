<?php

/*
 * Merged by Davide Giunchi, from plugin "Stop User Enumeration"
 */

if (!is_admin() && isset($_SERVER['REQUEST_URI'])) {
    if (preg_match('/(wp-comments-post)/', $_SERVER['REQUEST_URI']) === 0 && !empty($_REQUEST['author'])) {
        wp_die('Accessing author info via link is forbidden');
    }
}


/*
 * Re-wrote code which checks for REST API requests
 * Below uses the "rest_api_init" action hook to check for REST requests.
 * The code will block unauthorized requests whilst allowing genuine requests. 
 * (Peter Petreski)
 */
add_action( 'rest_api_init', 'check_rest_api_requests', 10, 1);
function check_rest_api_requests($rest_server_object){
    $rest_user = wp_get_current_user();
    if(empty($rest_user->ID)){
        wp_die('You are not authorized to perform this action'); 
    }
}