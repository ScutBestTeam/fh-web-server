<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${TITLE}</title>
<meta name="keywords" content="${KEYWORDS}" />
<meta name="description" content="${DESCRIPTION}">
<meta name="author" content="fhadmin">

<!-- core CSS -->
<link href="fh_static_3/css/bootstrap.min.css" rel="stylesheet">
<link href="fh_static_3/css/font-awesome.min.css" rel="stylesheet">
<link href="fh_static_3/css/prettyPhoto.css" rel="stylesheet">
<link href="fh_static_3/css/main.css" rel="stylesheet">
<link href="fh_static_3/css/responsive.css" rel="stylesheet">
<link href="fh_static_3/css/owl.carousel.css" rel="stylesheet">
<link href="fh_static_3/css/owl.theme.css" rel="stylesheet">

<!-- HTML5 shim and Respond.js for IE8 support of HTML5 elements and media queries -->
<!--[if lt IE 9]>
      <script src="https://oss.maxcdn.com/html5shiv/3.7.2/html5shiv.min.js"></script>
      <script src="https://oss.maxcdn.com/respond/1.4.2/respond.min.js"></script>
    <![endif]-->
</head>

<body>

<!-- header 包含导航菜单 -->
<#include "headerTemplate.ftl"> 
<!-- header 包含导航菜单 -->

<div id="inner-page">
  <div class="top-center">
    <h2>联系我们  Contact Us</h2>
  </div>
  <div class="container">
    <div class="row contact_top">
  		<p>
			${CONTACTUS}
		</p>
    </div>
    <div class="center">
      <h3>给我们留言</h3>
      <p class="lead">Send us a message</p>
    </div>
      <div class="row">
        <div  style="margin-left:20px;" class="col-sm-offset-1">
          <div class="form-group">
            <label>姓名 *</label>
            <input type="text" id="NAME" name="NAME" maxlength="10" class="form-control" required="required" style="width:79%;">
            <p class="help-block text-danger"></p>
          </div>
          <div class="form-group">
            <label>邮箱 *</label>
            <input type="text" id="EMAIL" name="EMAIL" maxlength="30"  class="form-control" required="required" style="width:79%;">
            <p class="help-block text-danger"></p>
          </div>
          <div class="form-group">
            <label>地址 *</label>
            <input type="tel" id="ADDRESS" name="ADDRESSESS" maxlength="50"  class="form-control" required="required" style="width:79%;">
            <p class="help-block text-danger"></p>
          </div>
          <div class="form-group">
            <label>内容 *</label>
            <input type="tel" id="LCONTENT" name="LCONTENT" maxlength="2000"  class="form-control" required="required" style="width:79%;">
            <p class="help-block text-danger"></p>
          </div>
          <div class="form-group">
            <label></label>
            <button type="submit" class="btn btn-primary btn-lg" onclick="save()">提交留言</button>
            <p class="help-block text-danger"></p>
          </div>
        </div>
      </div>
  </div>
</div>

<!-- footer 包含底部 -->
<#include "footerTemplate.ftl"> 
<!-- footer 包含底部  -->

<script type="text/javascript" src="fh_static_3/js/jquery.js"></script> 
<script type="text/javascript" src="fh_static_3/js/bootstrap.min.js"></script> 
<script type="text/javascript" src="fh_static_3/js/jquery.prettyPhoto.js"></script> 
<script type="text/javascript" src="fh_static_3/js/jquery.isotope.min.js"></script> 
<script type="text/javascript" src="fh_static_3/js/owl.carousel.js"></script> 
<script type="text/javascript" src="fh_static_3/js/main.js"></script>

<script type="text/javascript">
	$(window).load(function() {
		$("#contactus").addClass("active");
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
</body>
</html>
