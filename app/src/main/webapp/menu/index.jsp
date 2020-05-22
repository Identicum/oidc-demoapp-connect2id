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

	String displayName = tokenClaims.getAsString("name");
	if( displayName == null ) {
		displayName = tokenClaims.getAsString("sub");
	}

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
<body style="padding-top: 70px">
	<div class="navbar navbar-expand-lg fixed-top navbar-dark bg-dark">
		<div class="container">
			<a class="navbar-brand" rel="home" href="#" title="Identicum">
				<img height="30" src="../resources/img/logo.png">  
			</a>
			<button class="navbar-toggler" type="button" data-toggle="collapse"
				data-target="#navbarText" aria-controls="navbarText"
				aria-expanded="false" aria-label="Toggle navigation">
				<span class="navbar-toggler-icon"></span>
			</button>
			<div class="collapse navbar-collapse" id="navbarText">
				<ul class="nav navbar-nav ml-auto">
					<li class="nav-item dropdown">
					  <a class="nav-link dropdown-toggle" href="#" id="navbarDropdown" role="button" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
							<i class="fas fa-user-circle fa-fw"></i> <%= displayName %>
					  </a>
					  <div class="dropdown-menu" aria-labelledby="dropdownMenuButton">
							<a class="dropdown-item" href="../oidc/logout"><span class="fa fa-sign-out"></span> Logout</a>
					  </div>
					</li>
				</ul>
			</div>
		</div>
	</div>
	<div class="container">
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
	<div class="tab-content" id="myTabContent" style="padding-top:20px">
		<div class="tab-pane fade show active" id="idtokenformattable" role="tabpanel" aria-labelledby="idtoken-tab">
			<h5>Header Claims</h5>
			<div class="table-responsive-sm">
				<table class="table table-striped">
					<thead>
						<tr>
							<th style="width: 30%; min-width: 250px">Name</th>
							<th>Value</th>
						</tr>
					</thead>
					<tbody>
						<%
						for(java.util.Map.Entry<String, Object> entry : headerClaims.entrySet()) {
							%>
							<tr class="idtoken-claim">
								<td><%= entry.getKey() %></td>
								<td><%= entry.getValue() %></td>
							</tr>
							<%
						}
					 	%>
					</tbody>
				</table>
			</div>
			<h5>Payload Claims</h5>
			<div class="table-responsive-sm">
				<table class="table table-striped">
					<thead>
						<tr>
							<th style="width: 30%; min-width: 250px">Name</th>
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
					 	%>
					</tbody>
				</table>
			</div>
		</div>
		<div class="tab-pane" id="idtoken" role="tabpanel" aria-labelledby="idtoken">
			<code class="idtoken"><%=idToken.getParsedString()%></code>
		</div>
		<div class="tab-pane" id="idtokenformatjson" role="tabpanel" aria-labelledby="idtokenformatjson">
			<h5>Header</h5>
			<code class="idtoken-json">
				<%=idToken.getHeader().toJSONObject().toJSONString()%>
			</code>
			<br/><br/>
			<h5>Payload</h5>
			<code class="idtoken-json">
				<%=idToken.getJWTClaimsSet().toJSONObject().toJSONString()%>
			</code>
		</div>
		<div class="tab-pane" id="accesstoken" role="tabpanel" aria-labelledby="accesstoken">
			<code class="accesstoken"><%=accessToken%></code>
		</div>
		<div class="tab-pane" id="userinfo" role="tabpanel" aria-labelledby="userinfo">
			<code><%=userinfoJson.toJSONString()%></code>	
		</div>
	</div>
 </div>	
</body>
</html>