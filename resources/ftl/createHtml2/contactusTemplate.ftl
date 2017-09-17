<!DOCTYPE html>
<html lang="en">
<head>

    <link rel="icon" href="fh_static_2/images/favicon.ico">

    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    
    <title>${TITLE}</title>
    <meta name="keywords" content="${KEYWORDS}" />
	<meta name="description" content="${DESCRIPTION}">

    <link rel="stylesheet" href="fh_static_2/css/style.css" media="screen" />
    <link rel="stylesheet" href="fh_static_2/css/boxed.css" media="screen" id="layout" />
    <link rel="stylesheet" href="fh_static_2/css/colors/color-yellow.css" media="screen" id="colors" />
    <link rel="stylesheet" href="fh_static_2/css/flexslider.css" media="screen" />
    <link rel="stylesheet" href="fh_static_2/css/fancybox.css" media="screen" />
    <link rel="stylesheet" href="fh_static_2/css/revslider.css" media="screen" />
    <link rel="stylesheet" href="fh_static_2/css/font-awesome.css" media="screen" />
    <link rel="stylesheet" href="fh_static_2/css/zocial.css" media="screen" />
    <link rel="stylesheet" href="fh_static_2/css/responsive.css" media="screen" />

    <!-- JavaScript -->
    <script src="fh_static_2/js/jquery-1.8.2.min.js"></script>
    <script src="fh_static_2/js/jquery.themepunch.plugins.min.js"></script>
    <script src="fh_static_2/js/jquery.themepunch.revolution.min.js"></script>
    <script src="fh_static_2/js/jquery.ui.widget.min.js"></script>                          
    <script src="fh_static_2/js/jquery.ui.accordion.min.js"></script>
    <script src="fh_static_2/js/jquery.ui.tabs.min.js"></script>
    <script src="fh_static_2/js/jquery.easing-1.3.min.js"></script>
    <script src="fh_static_2/js/jquery.fitvid.js"></script>
    <script src="fh_static_2/js/jquery.fancybox.pack.js"></script>
    <script src="fh_static_2/js/jquery.flexslider-min.js"></script>
    <script src="fh_static_2/js/jquery.isotope.min.js"></script>
    <script src="fh_static_2/js/jquery.imagesloaded.min.js"></script>
    <script src="fh_static_2/js/jquery.infinitescroll.min.js"></script>
    <script src="fh_static_2/js/jquery.jcarousel.min.js"></script>
    <script src="fh_static_2/js/jquery.jtweetsanywhere-1.3.1.min.js"></script>
    <script src="fh_static_2/js/jquery.touchSwipe.min.js"></script>
    <script src="fh_static_2/js/jquery.validate.min.js"></script>
    <script src="fh_static_2/js/jquery.zflickrfeed.min.js"></script>
    <script src="fh_static_2/js/respond.min.js"></script>
    <script src="fh_static_2/js/selectnav.min.js"></script>
    <script src="fh_static_2/js/custom.js"></script>

    <link rel="stylesheet" type="text/css" href="fh_static_2/css/styleselector.css">
    <script src="fh_static_2/js/styleselector.js"></script>

</head>
<body>

<!-- Body Wrapper -->
<div id="body-wrapper">


	<!-- header 包含导航菜单 -->
	<#include "headerTemplate.ftl"> 
	<!-- header 包含导航菜单 -->


    <!-- Page Title -->
    <h1 class="page-title fullwidth-padding">
        <div class="container">
            Contact US<br /> <span class="accent">联系我们</span>
        </div>
    </h1>

    <!-- Content  -->
    <div id="content" class="container">

        <!-- Intro -->
        <div class="intro">
           ${CONTACTUS}
        </div>
		
	    <!-- Contact Form -->
        <div class="contact-form">
            <form method="post" id="contact-form">
                <label>您的姓名</label>
                <input type="text" id="NAME" name="NAME" maxlength="10" />
                <label>电子邮箱</label>
                <input type="text" id="EMAIL" name="EMAIL" maxlength="30" />
                <label>您的地址</label>
                <input type="text" id="ADDRESS" name="ADDRESSESS" maxlength="50" />
                <label>留言给我们</label>
                <textarea cols="88" rows="6" id="LCONTENT" name="LCONTENT" maxlength="2000"></textarea>
                <input type="submit" value="提交" class="yellow-darkgray" onclick="save()">
            </form>
        </div>
    </div>
    <!-- Content / End -->

    <!-- Footer -->
    <#include "footerTemplate.ftl"> 
    <!-- Footer / End -->

</div>
<!-- Body Wrapper / End -->

<!-- Back to Top -->
<a href="#" id="back-to-top"><i class="icon-chevron-up"></i></a>

	<script type="text/javascript">
		$(window).load(function() {
			$("#contactus").addClass("current");
		});
		
		function save(){
			var NAME = $("#NAME").val();
			var EMAIL = $("#EMAIL").val();
			var ADDRESS = $("#ADDRESS").val();
			var LCONTENT = $("#LCONTENT").val();
			$.ajax({
				type: "POST",
				url: 'web/saveLeavemsg.do',
		    	data: {NAME:NAME,EMAIL:EMAIL,ADDRESS:ADDRESS,LCONTENT:LCONTENT,tm:new Date().getTime()},
				dataType:'json',
				cache: false,
				success: function(data){
					 if("00" == data.result){
					 	$("#NAME").val("");
						$("#EMAIL").val("");
						$("#ADDRESS").val("");
						$("#LCONTENT").val("");
						alert("提交成功");
					 }
				}
			});
		}
	</script>
</body></html>




