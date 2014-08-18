(function($){
     $.fn.extend({  
         pwdstr: function(el) {	
             return this.each(function() {
                 $(this).keyup(function(){
                     $(el).html(getTime($(this).val()));
                });
					
                function getTime(str){

                var chars = 0;
                var rate = 2800000000;

                if((/[a-z]/).test(str)) chars +=  26;
                if((/[A-Z]/).test(str)) chars +=  26;
                if((/[0-9]/).test(str)) chars +=  10;
                if((/[^a-zA-Z0-9]/).test(str)) chars +=  32;

                var pos = Math.pow(chars,str.length);
                var s = pos/rate;
                var decimalYears = s/(3600*24*365);
                var years = Math.floor(decimalYears);

                var decimalMonths =(decimalYears-years)*12;
                var months = Math.floor(decimalMonths);

                var decimalDays = (decimalMonths-months)*30;
                var days = Math.floor(decimalDays);

                var decimalHours = (decimalDays-days)*24;
                var hours = Math.floor(decimalHours);

                var decimalMinutes = (decimalHours-hours)*60;
                var minutes = Math.floor(decimalMinutes);

                var decimalSeconds = (decimalMinutes-minutes)*60;
                var seconds = Math.floor(decimalSeconds);

                var time = [];

                if(years > 0){
                        if(years == 1)
                                time.push("1 year, ");
                        else
                                time.push(years + " years, ");
                }
                if(months > 0){
                        if(months == 1)
                                time.push("1 month, ");
                        else
                                time.push(months + " months, ");
                }
                if(days > 0){
                        if(days == 1)
                                time.push("1 day, ");
                        else
                                time.push(days + " days, ");
                }
                if(hours > 0){
                        if(hours == 1)
                                time.push("1 hour, ");
                        else
                                time.push(hours + " hours, ");
                }
                if(minutes > 0){
                        if(minutes == 1)
                                time.push("1 minute, ");
                        else
                                time.push(minutes + " minutes, ");
                }
                if(seconds > 0){
                        if(seconds == 1)
                                time.push("1 second, ");
                        else
                                time.push(seconds + " seconds, ");
                }

                if(time.length <= 0)
                        time = "less than one second, ";
                else if(time.length == 1)
                        time = time[0];
                else
                        time = time[0] + time[1];

                
                var field = $('#aiowps_password_test');
                if (s <= 1 || !field.val())
                {
                    //Time to crack < 1 sec
                    complexity = 0;
                }else if (s > 1 && s <= 43200)
                {
                    //1 sec < Time to crack < 12hrs
                    complexity = 1;
                }else if (s > 43200 && s <= 86400)
                {
                    //12 hrs < Time to crack < 1day
                    complexity = 2;
                }else if (s > 86400 && s <= 604800)
                {
                    //1 day < Time to crack < 1wk
                    complexity = 3;
                }else if (s > 604800 && s <= 2678400)
                {
                    //1wk < Time to crack < 1mth
                    complexity = 4;
                }else if (s > 2678400 && s <= 15552000)
                {
                    //1mth < Time to crack < 6mths
                    complexity = 5;
                }else if (s > 31536000 && s <= 31536000)
                {
                    //6mths < Time to crack < 1yrs
                    complexity = 6;
                }else if (s > 31536000 && s <= 315360000)
                {
                    //1yrs < Time to crack < 10yrs
                    complexity = 7;
                }else if (s > 315360000 && s <= 3153600000)
                {
                    //10yrs < Time to crack < 100yrs
                    complexity = 8;
                }else if (s > 3153600000 && s <= 31536000000)
                {
                    //100yrs < Time to crack < 1000yrs
                    complexity = 9;
                }else if (s > 31536000000)
                {
                    //1000yrs < Time to crack
                    complexity = 10;
                }
                calculated = (complexity/10)*268 - 134;
                prop = 'rotate('+(calculated)+'deg)';
                // Rotate the arrow
                $('.arrow').css({
                        '-moz-transform':prop,
                        '-webkit-transform':prop,
                        '-o-transform':prop,
                        '-ms-transform':prop,
                        'transform':prop
                });

                return time.substring(0,time.length-2);
                }
					
            });
        }
        
    });
    $(document).ready(function(){
        $('#aiowps_password_test').pwdstr('#aiowps_password_crack_time_calculation');
    });                
})(jQuery);

