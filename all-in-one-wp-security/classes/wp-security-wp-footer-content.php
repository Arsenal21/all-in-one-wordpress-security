<?php
if(!defined('ABSPATH')){
    exit;//Exit if accessed directly
}

class AIOWPSecurity_WP_Footer_Content {

    function __construct() {
        //Add content that need to be outputted in the footer area.

        global $aio_wp_security;
        
        // If Google recaptcha is enabled do relevant tasks
        if($aio_wp_security->configs->get_value('aiowps_default_recaptcha')) {
            // For Woocommerce forms. 
            // Only proceed if woocommerce installed and active 
            if ( in_array( 'woocommerce/woocommerce.php', apply_filters( 'active_plugins', get_option( 'active_plugins' ) ) ) ) 
            {
                if($aio_wp_security->configs->get_value('aiowps_enable_woo_login_captcha') == '1' || 
                        $aio_wp_security->configs->get_value('aiowps_enable_woo_register_captcha') == '1' ||
                        $aio_wp_security->configs->get_value('aiowps_enable_woo_lostpassword_captcha') == '1')
                {
                    $this->print_recaptcha_api_woo();
                }
            }
            
            // For custom wp login form
            if($aio_wp_security->configs->get_value('aiowps_enable_custom_login_captcha') == '1')
            {
                $this->print_recaptcha_api_custom_login();
            }
            
        }

        // Activate the copy protection feature for non-admin users
        $copy_protection_active = $aio_wp_security->configs->get_value('aiowps_copy_protection') == '1';
        if ( $copy_protection_active && !current_user_can(AIOWPSEC_MANAGEMENT_PERMISSION) )
        {
            $this->output_copy_protection_code();
        }
        
        //TODO - add other footer output content here
    }
    
    /**
     * For Woocommerce my account page - display two separate Google reCaptcha forms "explicitly"
     * @global type $aio_wp_security
     */
    function print_recaptcha_api_woo() {
        global $aio_wp_security;
        $is_woo = false;
        $is_woo = is_account_page();
        if(!$is_woo) {
            return; // if current page is not woo account page don't do anything
        }
        $site_key = esc_html( $aio_wp_security->configs->get_value('aiowps_recaptcha_site_key') );
            ?>
    <script type="text/javascript">
            var verifyCallback = function(response) {
                alert(response);
            };
            var onloadCallback = function() {
                if ( jQuery('#woo_recaptcha_1').length ) {
                    grecaptcha.render('woo_recaptcha_1', {
                      'sitekey' : '<?php echo $site_key; ?>',
                    });
                }
                if ( jQuery('#woo_recaptcha_2').length ) {
                    grecaptcha.render('woo_recaptcha_2', {
                      'sitekey' : '<?php echo $site_key; ?>',
                    });
                }
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

    /**
     * For case when a custom wp_login_form() is displayed anywhere on a page.
     * Inserts a script element referencing google recaptcha api v2.
     * Only inserts the recaptcha script element if the wp login form exists. 
     */
    function print_recaptcha_api_custom_login()
    {
        ?>
        <script type="text/javascript">
            let cust_login = document.getElementById("loginform");
            if(cust_login !== null) {
                var recaptcha_script = document.createElement('script');
                recaptcha_script.setAttribute('src','https://www.google.com/recaptcha/api.js');
                document.head.appendChild(recaptcha_script);                
            }
        </script>
        <?php
    }
}
//End of class