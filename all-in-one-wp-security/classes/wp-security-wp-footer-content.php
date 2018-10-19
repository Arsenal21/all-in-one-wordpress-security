<?php
if(!defined('ABSPATH')){
    exit;//Exit if accessed directly
}

class AIOWPSecurity_WP_Footer_Content {

    function __construct() {
        //Add content that need to be outputted in the footer area.

        global $aio_wp_security;
        if($aio_wp_security->configs->get_value('aiowps_default_recaptcha')) {
            $this->print_google_recaptcha_api();
        }

        // Activate the copy protection feature for non-admin users
        $copy_protection_active = $aio_wp_security->configs->get_value('aiowps_copy_protection') == '1';
        if ( $copy_protection_active && !current_user_can(AIOWPSEC_MANAGEMENT_PERMISSION) ) {
            $this->output_copy_protection_code();
        }

        //TODO - add other footer output content here
    }
    
    /**
     * For Woocommerce my account page - display two separate Google reCaptcha forms "explicitly"
     * @global type $aio_wp_security
     */
    function print_google_recaptcha_api() {
        global $aio_wp_security;
        $site_key = esc_html( $aio_wp_security->configs->get_value('aiowps_recaptcha_site_key') );
            ?>
    <script type="text/javascript">
        var verifyCallback = function(response) {
            alert(response);
        };
        var onloadCallback = function() {
            grecaptcha.render('woo_recaptcha_1', {
              'sitekey' : '<?php echo $site_key; ?>',
            });
            grecaptcha.render('woo_recaptcha_2', {
              'sitekey' : '<?php echo $site_key; ?>',
            });
        };
    </script>
    <script src='https://www.google.com/recaptcha/api.js?onload=onloadCallback&render=explicit' async defer></script>
<?php
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