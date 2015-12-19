<?php

/*
  Merged by Davide Giunchi, from plugin "Stop User Enumeration" url "http://locally.uk/wordpress-plugins/stop-user-enumeration/" by "Locally Digital Ltd"
 */

/*
  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License
  as published by the Free Software Foundation; either version 2
  of the License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

if (!is_admin()) {
    if (!is_admin()) {
        if (preg_match('/(wp-comments-post)/', $_SERVER['REQUEST_URI']) === 0) {
            if (!empty($_POST['author'])) {
                wp_die('Accessing author info via link is forbidden');
            }
        }

        if (preg_match('/author=([0-9]*)/', $_SERVER['QUERY_STRING']) === 1)
            wp_die('Accessing author info via link is forbidden');

        add_filter('redirect_canonical', 'll_detect_enumeration', 10, 2);
    }
}

add_filter('redirect_canonical', 'll_detect_enumeration', 10, 2);

function ll_detect_enumeration($redirect_url, $requested_url) {
    if (preg_match('/\?author(%00[0%]*)?=([0-9]*)(\/*)/', $requested_url) === 1 | isset($_POST['author'])) {
        wp_die('Accessing author info via link is forbidden');
    } else {
        return $redirect_url;
    }
}
