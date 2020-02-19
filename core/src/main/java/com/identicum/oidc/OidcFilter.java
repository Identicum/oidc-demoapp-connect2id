package com.identicum.oidc;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;

import net.minidev.json.JSONObject;

public class OidcFilter implements Filter
{
	private final static Logger logger = LoggerFactory.getLogger(OidcFilter.class);
	
	public final static String STATE = "state";
	public final static String ACCESS_TOKEN = "access_token";
	public final static String ID_TOKEN = "id_token";
	public final static String USER_CLAIMS= "user_claims";
	public final static String USERINFO = "userinfo";
	private final static String GOTO = "com.identicum.oauth.goto";
	
	private OidcClient client = null;

	public void destroy()
	{
		logger.info("Destroy");
	}

	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException
	{
		HttpServletRequest request = (HttpServletRequest) servletRequest;
		HttpServletResponse response = (HttpServletResponse) servletResponse;

		// Valido si tengo una sesión existente
		HttpSession mySession = request.getSession(true);
		if (mySession.getAttribute(ID_TOKEN) == null 
				&& mySession.getAttribute(ACCESS_TOKEN) == null)
		{
			logger.info("Session not found");			
			
			if (this.isCallback(request))
			{
				logger.info("Code received. Processing callback");
				AuthenticationSuccessResponse authResponse = this.client.getAuthenticationResponse(request);
				
				logger.info("Validating response state parameter");
				if( !authResponse.getState().equals(mySession.getAttribute(STATE))) {
					throw new RuntimeException("Invalid state parameter");
				}
						
				logger.info("Code received. Requesting access_token and id_token");
				OIDCTokenResponse accessTokenResponse = this.client.requestTokensWithAuthorizationCode(authResponse.getAuthorizationCode());
				
				BearerAccessToken accessToken = accessTokenResponse.getTokens().getBearerAccessToken();		
				mySession.setAttribute(ACCESS_TOKEN, accessToken.getValue());
		
				if(this.client.getScope().contains("openid") && accessTokenResponse.getOIDCTokens() != null)
				{
					JWT idToken = accessTokenResponse.getOIDCTokens().getIDToken();
					logger.info("Validating id_token");
					JSONObject userClaims = this.client.validateIdToken(idToken);
					
					logger.info("Getting user's claims from id_token");
					mySession.setAttribute("id_token", idToken);
					mySession.setAttribute(USER_CLAIMS, userClaims);
				}
				
				//else
				//{	
				logger.info("Requesting User info");
				mySession.setAttribute(USERINFO, this.client.requestUserInfo(accessToken));								
				//}

				// Share oidc client configuration for OIDC Logout Filter
				mySession.setAttribute("oidc_client", this.client);
				
				String pageURL = request.getContextPath(); // Default page				
				// Verifico si tengo en sesión la página original que el usuario intentó acceder
				if(mySession.getAttribute(GOTO) != null) {
					pageURL = (String) mySession.getAttribute(GOTO);
					mySession.removeAttribute(GOTO);
				}
					
				logger.info("Session created. Redirecting user to: {} ",pageURL);
				response.sendRedirect(pageURL);
				return;
			}
			else
			{
				logger.info("Start OIDC negotiation");
				State state = new State();
				Nonce nonce = new Nonce();
				String redirectTo = this.client.getAuthenticationRequestURI(state, nonce).toString();
				mySession.setAttribute(STATE, state);
				String pageURL = request.getRequestURI().toString() + (request.getQueryString() != null ? "?" + request.getQueryString() : "");
				logger.debug("Keeping original page request in session: {} ", pageURL);
				mySession.setAttribute(GOTO, pageURL);
				logger.info("Redirecting user to the OIDC Server:" + redirectTo);
				response.sendRedirect(redirectTo);
				return;
			}
		}
		else
		{
			logger.info("Session found. Continue chain");
			filterChain.doFilter(servletRequest, servletResponse);
			return;
		}
	}
	
	public void init(FilterConfig filterConfig) throws ServletException
	{
		logger.info("Initializating OIDC Filter...");
		this.client = new OidcClient(); 
		try
		{
			this.client.setRedirectURI( new URI(this.getRequiredProperty(filterConfig, "redirectUri")));
			this.client.setAuthorizationRequestURIParameter( this.getProperty(filterConfig, "authorizationRequestUriParameter","") );
			this.client.setClientId( new ClientID(this.getRequiredProperty(filterConfig, "clientId")));
			this.client.setClientSecret(new Secret( this.getRequiredProperty(filterConfig, "clientSecret")));
			this.client.setScopes( this.getProperty(filterConfig, "scopes", "profile,openid") );
			this.client.setPostLogoutURI(new URI(this.getProperty(filterConfig, "appPostLogoutRedirectURI", "")));

			String endpointConfiguration = this.getRequiredProperty(filterConfig, "metadataEndpoint");
			this.client.discoverMetadata(endpointConfiguration);
		}
		catch (URISyntaxException ue)
		{
			logger.error("Error creating filter", ue);
		}
	}
	
	private boolean isCallback(HttpServletRequest request)
	{
		String page = request.getRequestURI().substring(request.getContextPath().length());
		String code = request.getParameter("code");
		return (this.client.getRedirectURI().getPath().endsWith(page) && code != null);
	}
	
	private String getRequiredProperty(FilterConfig filterConfig, String propertyName)
	{
		String value = filterConfig.getInitParameter(propertyName);
		if(value == null || value.trim().isEmpty()) 
			throw new RuntimeException("Parameter " + propertyName + " is required");
		return value;
	}
	
	private String getProperty(FilterConfig filterConfig, String propertyName, String defaultValue)
	{
		String value = filterConfig.getInitParameter(propertyName);
		return (value == null) ? defaultValue : value;
	}
	
}
