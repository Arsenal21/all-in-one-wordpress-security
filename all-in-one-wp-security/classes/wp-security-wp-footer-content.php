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
            if ( in_array( 'woocommerce/woocommerce.php', apply_filters( 'active_plugins', get_option( 'active_plugins' ) ) ) && is_account_page() )
            {
                if($aio_wp_security->configs->get_value('aiowps_enable_woo_login_captcha') == '1' || 
                        $aio_wp_security->configs->get_value('aiowps_enable_woo_register_captcha') == '1' ||
                        $aio_wp_security->configs->get_value('aiowps_enable_woo_lostpassword_captcha') == '1')
                {
                    $this->print_recaptcha_api_trigger(array(
                        'woo_recaptcha_1',
                        'woo_recaptcha_2'
                    ));
                }
            }

            // ContactForm7 Conflict
            // Only proceed if contact form 7 installed and active
            elseif ( in_array( 'contact-form-7/wp-contact-form-7.php', apply_filters( 'active_plugins', get_option( 'active_plugins' ) ) ) )
            {
                $this->print_recaptcha_api_trigger(array(
                    'aiowps_recaptcha_field',
                ));
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
     * For Woocommerce my account page / Contactfrom7 - display multiple separate Google reCaptcha forms "explicitly" or single form for compatibility reasons
     * @global type $aio_wp_security
     */
    function print_recaptcha_api_trigger($recaptureNames = array()) {
        global $aio_wp_security;
        $site_key = esc_html( $aio_wp_security->configs->get_value('aiowps_recaptcha_site_key') );

        // Build JS logic
        $logicJs = '';
        foreach ($recaptureNames as $name) {
            $logicJs .= '
        		if ( jQuery("#' . $name . '").length ) {
                    grecaptcha.render("' . $name . '", {
                    	"sitekey" : "' . $site_key . '",
                    });
                }
        	';
        }

        ?>
        <script type="text/javascript">
            var verifyCallback = function(response) {
                alert(response);
            };
            var onloadCallback = function() {
                <?php echo $logicJs; ?>
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