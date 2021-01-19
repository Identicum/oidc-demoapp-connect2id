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
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;

import net.minidev.json.JSONObject;

public class OidcFilter implements Filter
{
	private final static Logger logger = LoggerFactory.getLogger(OidcFilter.class);
	
	public final static String STATE = "state";
	public final static String PCKE_CODE_VERIFIER = "pkce_code_verifier";
	public final static String ACCESS_TOKEN = "access_token";
	public final static String ID_TOKEN = "id_token";
	public final static String USER_CLAIMS= "user_claims";
	public final static String USERINFO = "userinfo";
	public final static String TOKENINFO = "tokeninfo";
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

		// Check if i have an existing session
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
				OIDCTokenResponse accessTokenResponse;
				if(client.isPublic()) {
					accessTokenResponse = this.client.requestTokensWithAuthorizationCode(authResponse.getAuthorizationCode(), (CodeVerifier) mySession.getAttribute(PCKE_CODE_VERIFIER));
				}
				else
				{
					accessTokenResponse = this.client.requestTokensWithAuthorizationCode(authResponse.getAuthorizationCode());
				}
				logger.info("Tokens returned: {}",  accessTokenResponse.getTokens());
				BearerAccessToken accessToken = accessTokenResponse.getTokens().getBearerAccessToken();		
				mySession.setAttribute(ACCESS_TOKEN, accessToken.getValue());
		
				if(this.client.getScope().contains("openid") && accessTokenResponse.getOIDCTokens() != null)
				{
					JWT idToken = accessTokenResponse.getOIDCTokens().getIDToken();
					logger.info("Validating id_token {} ", idToken.getParsedString());
					JSONObject userClaims = this.client.validateIdToken(idToken);
					
					logger.info("Getting user's claims from id_token");
					mySession.setAttribute("id_token", idToken);
					mySession.setAttribute(USER_CLAIMS, userClaims);
				}
				
				//else
				//{	
				logger.info("Requesting User info");
				//TODO: Check if access token has JWT format
				mySession.setAttribute(USERINFO, this.client.requestUserInfo(accessToken));
				mySession.setAttribute(TOKENINFO, this.client.requestTokenInfo(accessToken));
				//}

				// Share oidc client configuration for OIDC Logout Filter
				mySession.setAttribute("oidc_client", this.client);
				
				String pageURL = request.getContextPath(); // Default page				
				// Check if a i have a goto page in session
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
				URI redirectTo;
				if(this.client.isPublic()) {
					CodeVerifier codeVerifier = new CodeVerifier();
					redirectTo = this.client.getAuthenticationRequestURI(state, nonce, codeVerifier);
					mySession.setAttribute(PCKE_CODE_VERIFIER, codeVerifier);
				}
				else {
					redirectTo = this.client.getAuthenticationRequestURI(state, nonce);
				}

				mySession.setAttribute(STATE, state);
				String pageURL = request.getRequestURI().toString() + (request.getQueryString() != null ? "?" + request.getQueryString() : "");
				mySession.setAttribute(GOTO, pageURL);
				logger.info("Redirecting user to: " + redirectTo);
				response.sendRedirect(redirectTo.toString());
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
			this.client.setClientSecret(new Secret( this.getProperty(filterConfig, "clientSecret","")));
			this.client.setScopes( this.getProperty(filterConfig, "scopes", "profile,openid") );
			this.client.setPostLogoutURI(new URI(this.getProperty(filterConfig, "appPostLogoutRedirectURI", "")));
			this.client.setSkipSSLCertValidation(Boolean.parseBoolean(this.getProperty(filterConfig, "skipSSLCertValidation", "false")));
			this.client.setRequestParameter(Boolean.parseBoolean(this.getProperty(filterConfig, "enableRequestParameter", "false")));
			this.client.setRequestObjectSigningAlg(this.getProperty(filterConfig, "requestObjectSigningAlg", "none"));
			this.client.setMetadataEndpoint(this.getRequiredProperty(filterConfig, "metadataEndpoint"));
			logger.debug("OIDC Client configuration: {}", this.client.toString());
			this.client.discoverMetadata();
		}
		catch (URISyntaxException ue)

		{
			logger.error("Error creating filter", ue);
			throw new RuntimeException("Invalid URI sintax, unable to initialize OIDC configuration:" +  ue.getMessage(), ue);
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
