<% 
	if(session != null)
	{	
		session.removeAttribute("access_token");
		session.removeAttribute("id_token");
		session.invalidate();
	}
%>
<html>
<head>
	 <meta charset="utf-8">
	 <meta http-equiv="X-UA-Compatible" content="IE=edge">
     <meta name="viewport" content="width=device-width, initial-scale=1">
	 <title>Demo App</title>
	 <link href="resources/css/bootstrap.min.css" rel="stylesheet" >
	 <link href="resources/css/font-awesome.min.css" rel="stylesheet">
	 <script src="resources/js/jquery-3.2.1.slim.min.js"></script>
	 <script src="resources/js/popper.min.js"></script>
	 <script src="resources/js/bootstrap.min.js"></script>
</head>
<body>
   	<div class="navbar fixed-top">
	    <div class="container">
	        <div class="navbar-header">
	            <a class="navbar-brand" rel="home" href="#" title="Personal">
	                <img style="max-width:100px; margin-top: -7px;" src="resources/img/logo.png">  
	            </a>
	        </div>
	        <div class="navbar-nav">
	        	<a class="nav-item" href="menu/index.jsp"><span class="fa fa-sign-in"></span> Login</a>
	        </div>	
   		 </div>
   	</div>	 
	<div class="container" style="margin-top:6%;">
			<div class="alert alert-success alert-dismissible" role="alert">
	  			<button type="button" class="close" data-dismiss="alert" aria-label="Close"><span aria-hidden="true">&times;</span></button>
	  			Session has ended
			</div>
	</div>
</body>
