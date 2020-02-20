package com.identicum.oidc;

import java.io.IOException;
import java.net.URI;

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
import com.nimbusds.oauth2.sdk.http.HTTPResponse;

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
		HttpServletResponse response = (HttpServletResponse) servletResponse;

		HttpSession mySession = request.getSession();
		
		OidcClient oidcClient = (OidcClient) mySession.getAttribute("oidc_client");
				
		JWT idToken = (JWT) mySession.getAttribute("id_token");
		mySession.invalidate();
		URI logoutUri = oidcClient.requestOIDCEndSession(idToken).toURI();
		logger.info("Request OIDC EndSession " + logoutUri.toString());
		response.sendRedirect(logoutUri.toString());
		return;
	}

	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
		// TODO Auto-generated method stub
	}
}
