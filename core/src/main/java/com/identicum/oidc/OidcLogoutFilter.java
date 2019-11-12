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
import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jwt.JWT;

/***
 * Filtro que realiza la funcionalidad de logout.
 * Primero remueve los atributos de la sesión y la invalida.
 * Para finalizar realiza un redircect al endpoint OIDC de endsession
 * 
 * @author mbesozzi
 *
 */
public class OidcLogoutFilter implements Filter{
	
	private final static String PROP_APP_POST_LOGOUT_URI = "appPostLogoutURI";
	
	private OidcClient client = null;
	
	private final static Logger logger = LoggerFactory.getLogger(OidcLogoutFilter.class);	
	
	@Override
	public void destroy() {
		logger.info("Destroy");
	}

	@Override
	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
		
		HttpServletRequest request = (HttpServletRequest) servletRequest;	
		HttpSession mySession = request.getSession();
		
		if(mySession != null) {	
			JWT idToken = (JWT) mySession.getAttribute("id_token");
			// response.setHeader("Authorization", "Basic " + mySession.getAttribute("access_token"));
			mySession.invalidate();
			logger.info("Redirecting to IDP end session endpoint");
			this.client.requestOIDCEndSession(idToken);
		}
		else
		{
			logger.warn("Session not found");
		}
		return;
	}

	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
		try {
			client = new OidcClient();
			client.setPostLogoutURI(new URI(this.getProperty(filterConfig, PROP_APP_POST_LOGOUT_URI, "")));
		}
		catch (URISyntaxException ue)
		{
			logger.error("Error creating filter", ue);
		}	
	}
	
	private String getProperty(FilterConfig filterConfig, String propertyName, String defaultValue)
	{
		String value = filterConfig.getInitParameter(propertyName);
		return (value == null) ? defaultValue : value;
	}

}
