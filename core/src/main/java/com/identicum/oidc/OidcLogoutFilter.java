package com.identicum.oidc;

import java.io.IOException;

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
	
	private final static Logger logger = LoggerFactory.getLogger(OidcLogoutFilter.class);	
	
	@Override
	public void destroy() {
		logger.info("Destroy");
	}

	@Override
	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
		
		HttpServletRequest request = (HttpServletRequest) servletRequest;	
		HttpSession mySession = request.getSession();
		
		OidcClient oidcClient = (OidcClient) mySession.getAttribute("oidc_client");
				
		if(mySession != null ) {	
			JWT idToken = (JWT) mySession.getAttribute("id_token");
			//response.setHeader("Authorization", "Basic " + mySession.getAttribute("access_token"));
			mySession.invalidate();
			logger.info("Request OIDC EndSession, Post Logout Redirect URI: " + oidcClient.getPostLogoutURI().toString());
			oidcClient.requestOIDCEndSession(idToken);
		}
		else
		{
			logger.warn("Session not found");
		}
		return;
	}

	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
		// TODO Auto-generated method stub
	}
}
