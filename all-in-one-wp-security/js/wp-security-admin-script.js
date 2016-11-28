jQuery(document).ready(function($){
    //Add Generic Admin Dashboard JS Code in this file

    //Media Uploader - start
    function aiowps_attach_media_uploader(key) {
        jQuery('#' + key + '_button').click(function() {
                text_element = jQuery('#' + key).attr('name');
                button_element = jQuery('#' + key + '_button').attr('name');
                tb_show('All In One Security - Please Select a File', 'media-upload.php?referer=aiowpsec&amp;TB_iframe=true&amp;post_id=0width=640&amp;height=485');
                return false;
        });		
        window.send_to_editor = function(html) {
                var self_element = text_element;
                fileurl = jQuery(html).attr('href');
                jQuery('#' + self_element).val(fileurl);
                tb_remove();
        };
    }

    var current_admin_page = getParameterByName('page'); //check query arg of loaded page to see if a gallery needs wm processing
    if(current_admin_page == 'aiowpsec_maintenance'){
        //don't load custom uploader stuff because we want to use standard wp uploader code
    }else{
        aiowps_attach_media_uploader('aiowps_htaccess_file');
        aiowps_attach_media_uploader('aiowps_wp_config_file');
        aiowps_attach_media_uploader('aiowps_import_settings_file');
        aiowps_attach_media_uploader('aiowps_db_file'); //TODO - for future use when we implement DB restore

    }
    //End of Media Uploader
    
    //Triggers the more info toggle link
    $(".aiowps_more_info_body").hide();//hide the more info on page load
    $(".aiowps_more_info_anchor").click(function(){
        $(this).next(".aiowps_more_info_body").animate({ "height": "toggle"});
        var toogle_char_ref = $(this).find(".aiowps_more_info_toggle_char");
        var toggle_char_value = toogle_char_ref.text();
        if(toggle_char_value === "+"){
            toogle_char_ref.text("-");
        }
        else{
             toogle_char_ref.text("+");
        }
    });
    //End of more info toggle

    //This function uses javascript to retrieve a query arg from the current page URL
    function getParameterByName(name) {
        var url = window.location.href;
        name = name.replace(/[\[\]]/g, "\\$&");
        var regex = new RegExp("[?&]" + name + "(=([^&#]*)|&|#|$)"),
            results = regex.exec(url);
        if (!results) return null;
        if (!results[2]) return '';
        return decodeURIComponent(results[2].replace(/\+/g, " "));
    }
});