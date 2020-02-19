<%@page import="net.minidev.json.JSONObject"%>
<%@page import="com.nimbusds.jwt.JWTClaimsSet"%>
<%@page import="com.nimbusds.jwt.JWT"%>
<%@page import="com.nimbusds.oauth2.sdk.token.BearerAccessToken"%>

<%
	JWT idToken = (JWT) session.getAttribute("id_token");
	String accessToken = (String) session.getAttribute("access_token");
	JSONObject userinfoJson = (JSONObject) session.getAttribute("userinfo");
	JSONObject tokenClaims = idToken.getJWTClaimsSet().toJSONObject();
	JSONObject headerClaims = idToken.getHeader().toJSONObject();
%>
<html>
<head>
	 <meta charset="utf-8">
	 <meta http-equiv="X-UA-Compatible" content="IE=edge">
     <meta name="viewport" content="width=device-width, initial-scale=1">
	 <title>OIDC Demo App</title>
	 <link href="../resources/css/bootstrap.min.css" rel="stylesheet" >
	 <link href="../resources/css/font-awesome.min.css" rel="stylesheet">
	 <script src="../resources/js/jquery-3.2.1.slim.min.js"></script>
	 <script src="../resources/js/popper.min.js"></script>
	 <script src="../resources/js/bootstrap.min.js"></script>
	 <script type="text/javascript">
	 	$(document).ready(function(){
		    $(".btn-group .btn input").change(function() {
		      $("." + $(this).attr('name')).toggleClass("d-none");
    	    });
		});
	 </script>
</head>
<body>
	<div class="navbar fixed-top">
	    <div class="container">
	        <div class="navbar-header">
	            <a class="navbar-brand" rel="home" href="#" title="Identicum">
	                <img style="max-width:150px; margin-top: -7px;" src="../resources/img/logo.png">  
	            </a>
	        </div>
	        <div class="navbar-nav">
	        	<a class="nav-item" href="#"><span class="fa fa-user"></span> <%= tokenClaims.getAsString("sub") %> </a>
				<!-- <a class="nav-item" href="../logout.jsp"><span class="fa fa-sign-out"></span> Logout</a> -->
				<a class="nav-item" href="../oidc/logout"><span class="fa fa-sign-out"></span> Logout</a>
	        </div>	
   		 </div>
   	</div>
	<div class="container" style="margin-top:5%;">
	 <ul class="nav nav-tabs" id="myTab" role="tablist">
	  <li class="nav-item">
	    <a class="nav-link active" id="idtokenformattable-tab" data-toggle="tab" href="#idtokenformattable" role="tab" aria-controls="idtokenformattable" aria-selected="true">ID Token (Claims)</a>
	  </li>
	  <li class="nav-item">
	    <a class="nav-link" id="idtokenformatjson-tab" data-toggle="tab" href="#idtokenformatjson" role="tab" aria-controls="idtokenformatjson" aria-selected="false">ID Token (Decoded)</a>
	  </li>
	  <li class="nav-item">
	    <a class="nav-link" id="idtoken-tab" data-toggle="tab" href="#idtoken" role="tab" aria-controls="idtoken" aria-selected="false">ID Token</a>
	  </li>
	   <li class="nav-item">
	    <a class="nav-link" id="accesstoken-tab" data-toggle="tab" href="#accesstoken" role="tab" aria-controls="accesstoken" aria-selected="true">Access Token</a>
	  </li>
	  <li class="nav-item">
	    <a class="nav-link" id="userinfo-tab" data-toggle="tab" href="#userinfo" role="tab" aria-controls="userinfo" aria-selected="true">User Info</a>
	  </li>
	</ul>
	<div class="tab-content" id="myTabContent">
	  <div class="tab-pane fade show active" id="idtokenformattable" role="tabpanel" aria-labelledby="idtoken-tab">
			<div class="btn-group btn-group-sm btn-group-toggle mt-2 ml-2 mb-3" data-toggle="buttons">
			  <label class="btn btn-outline-info active">
			    <input type="radio" name="idtoken-claim" autocomplete="off" checked>Payload
			  </label>
			  <label class="btn btn-outline-info">
			    <input type="radio" name="idtoken-claim" autocomplete="off"> Header
			  </label>
			</div>
	  		<table class="table table-hover">
				<thead>
					<tr style="color: #00b4c5;">
						<th>Name</th>
						<th>Value</th>
					</tr>
				</thead>
		        <tbody>
		       	<%
		       		for(java.util.Map.Entry<String, Object> entry : tokenClaims.entrySet())	{
		       	%>
				    <tr class="idtoken-claim">
				    	<td><%= entry.getKey() %></td>
				    	<td><%= entry.getValue() %></td>
				    </tr>
				 <%
				 	}
				 	for(java.util.Map.Entry<String, Object> entry : headerClaims.entrySet()) {
	   			%>
	   				 <tr class="idtoken-claim d-none">
				    	<td><%= entry.getKey() %></td>
				    	<td><%= entry.getValue() %></td>
				    </tr>
	   			<%
	   				}
				 %>
				</tbody>
			</table>
	  </div>
	  <div class="tab-pane" id="idtoken" role="tabpanel" aria-labelledby="idtoken">
		  <div class="btn-group btn-group-sm btn-group-toggle mt-2 ml-2 mb-3" data-toggle="buttons">
		  </div>
		  <div>
			  <code class="idtoken">
			  		<%=idToken.getParsedString()%>
			  </code>
		 </div>	  
	  </div>
	  <div class="tab-pane" id="idtokenformatjson" role="tabpanel" aria-labelledby="idtokenformatjson">
		  <div class="btn-group btn-group-sm btn-group-toggle mt-2 ml-2 mb-3" data-toggle="buttons">
		   	  <label class="btn btn-outline-info active">
			    <input type="radio" name="idtoken-json" autocomplete="off" checked>Payload
			  </label>
			  <label class="btn btn-outline-info">
			    <input type="radio" name="idtoken-json" autocomplete="off">Header
			  </label>
		  </div>
		  <div>
			  <code class="idtoken-json">
			  		<%=idToken.getJWTClaimsSet().toJSONObject().toJSONString()%>
			  </code>
			  <code class="idtoken-json d-none">
			  		<%=idToken.getHeader().toJSONObject().toJSONString()%>
			  </code>
		 </div>	  
	  </div>
	  <div class="tab-pane" id="accesstoken" role="tabpanel" aria-labelledby="accesstoken">
		  <div style="margin-top:20px;">
			  <code class="accesstoken">
			  		<%=accessToken%>
			  </code>
		 </div>	  
	  </div>
	  <div class="tab-pane" id="userinfo" role="tabpanel" aria-labelledby="userinfo">
	    <div style="margin-top:20px;">
		    <code>
		 		<%=userinfoJson.toJSONString()%>
		 	</code>	
	 	 </div>
	  </div>
	</div>
 </div>	
</body>
</html>