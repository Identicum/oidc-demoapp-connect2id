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
		<div class="container h-100">
			<div class="row h-100 justify-content-center align-items-center">
				<div class="d-flex flex-column mb-3">
				  <div style="padding-bottom: 20px">Session has ended</div>
				  <div class="text-center"><a class="login" href="menu/index.jsp">Login</a></div>
				</div>
			</div>
		</div>
		<style>
			body {
				background-color: whitesmoke;
			}
			a.login {
		    color: #007bff;
		    text-decoration: none;
		    background-color: transparent;
		    border: 2px solid #007bff;
		    display: inline-block;
		    width: 100px;
		    height: 100px;
		    border-radius: 100%;
		    text-align: center;
		    line-height: 100px;
		    text-transform: uppercase;
		    text-decoration: none;
			}

			a.login:hover {
		    background-color: #007bff;
		    color: white;
		  }
		</style>
	</body>
</html>