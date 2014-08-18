<?php
global $aio_wp_security;
$aiowps_site_lockout_msg_raw = $aio_wp_security->configs->get_value('aiowps_site_lockout_msg');
if(empty($aiowps_site_lockout_msg_raw)){
    $aiowps_site_lockout_msg_raw = '<p>This site is currently not available. Please try again later.</p>';
}
$maintenance_msg = html_entity_decode($aiowps_site_lockout_msg_raw, ENT_COMPAT, "UTF-8");
$maintenance_msg = apply_filters('the_content', $maintenance_msg);
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head profile="http://gmpg.org/xfn/11">
	<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
	<title><?php bloginfo('name'); ?></title>

	<link rel="stylesheet" type="text/css" href="<?php echo AIO_WP_SECURITY_URL ; ?>/css/wp-security-site-lockout-page.css" />
	<?php wp_head(); ?>
</head>

<body>
<div class="aiowps-site-lockout-body">
    <div class="aiowps-site-lockout-body-content">
        <div class="aiowps-site-lockout-box">
                <div class="aiowps-site-lockout-msg">
                    <?php echo $maintenance_msg; ?>
                </div>
        </div> <!-- end .aiowps-site-lockout-box -->
    </div> <!-- end .aiowps-site-lockout-body-content -->
</div> <!-- end .aiowps-site-lockout-body -->
</body>
</html>