<?php
/* * * This class handles tasks that need to be executed at wp-loaded time ** */

class AIOWPSecurity_WP_Footer_Content {

    function __construct() {
        //Add content that need to be outputted in the footer area.

        global $aio_wp_security;

        //Handle the copy protection feature
        if ($aio_wp_security->configs->get_value('aiowps_copy_protection') == '1') {
            $this->output_copy_protection_code();
        }

        //TODO - add other footer output content here
    }

    function output_copy_protection_code() {
        ?>
        <meta http-equiv="imagetoolbar" content="no"><!-- disable image toolbar (if any) -->
        <script type="text/javascript">
            /*<![CDATA[*/
            document.oncontextmenu = function() {
                return false;
            };
            document.onselectstart = function() {
                if (event.srcElement.type != "text" && event.srcElement.type != "textarea" && event.srcElement.type != "password") {
                    return false;
                }
                else {
                    return true;
                }
            };
            if (window.sidebar) {
                document.onmousedown = function(e) {
                    var obj = e.target;
                    if (obj.tagName.toUpperCase() == 'SELECT'
                            || obj.tagName.toUpperCase() == "INPUT"
                            || obj.tagName.toUpperCase() == "TEXTAREA"
                            || obj.tagName.toUpperCase() == "PASSWORD") {
                        return true;
                    }
                    else {
                        return false;
                    }
                };
            }
            document.ondragstart = function() {
                return false;
            };
            /*]]>*/
        </script>
        <?php
    }

}

//End of class