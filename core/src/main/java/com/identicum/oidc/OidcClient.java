package com.identicum.oidc;


import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.LogoutRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.UserInfoErrorResponse;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;

import net.minidev.json.JSONObject;

public class OidcClient
{
	private final static Logger logger = LoggerFactory.getLogger(OidcClient.class);

	private URI redirectURI;
	private String authorizationRequestURIParameter;
	private ClientID clientId;
	private Secret clientSecret;
	private Scope scope;
	private URI postLogoutURI;


	private OIDCProviderMetadata providerMetadata;

	public URI getRedirectURI()
	{
		return redirectURI;
	}

	public void setRedirectURI(URI redirectURI)
	{
		this.redirectURI = redirectURI;
	}

	public ClientID getClientId()
	{
		return clientId;
	}

	public void setClientId(ClientID clientId)
	{
		this.clientId = clientId;
	}

	public Secret getClientSecret()
	{
		return clientSecret;
	}

	public void setClientSecret(Secret clientSecret)
	{
		this.clientSecret = clientSecret;
	}

	public Scope getScope()
	{
		return scope;
	}

	public void setScope(Scope scope)
	{
		this.scope = scope;
	}

	public void setScopes(String scopes)
	{
		this.scope = Scope.parse(scopes);
	}

	public String getAuthorizationRequestURIParameter() {
		return authorizationRequestURIParameter;
	}

	public void setAuthorizationRequestURIParameter(String authorizationRequestURIParameter) {
		this.authorizationRequestURIParameter = authorizationRequestURIParameter;
	}

	public void discoverMetadata(String endpoint)
	{
		try
		{
			URL providerConfigurationURL = new URL(endpoint);
			InputStream stream = providerConfigurationURL.openStream();
			String providerInfo = null;
			@SuppressWarnings("resource")
			java.util.Scanner s = new java.util.Scanner(stream);
			providerInfo = s.useDelimiter("\\A").hasNext() ? s.next() : "";
			this.providerMetadata = OIDCProviderMetadata.parse(providerInfo);
		}
		catch(Exception e)
		{
			throw new RuntimeException("Error getting privder metadata from server: " + endpoint, e);
		}
	}

	private Issuer getExpectedIssuer()
	{
		return this.providerMetadata.getIssuer();
	}

	private JWKSet getJWKSet()
	{
		JWKSet jwkset = null;
		try {
			jwkset = JWKSet.load(this.providerMetadata.getJWKSetURI().toURL());
		} catch (Exception e1) {
			e1.printStackTrace();
		}
		return jwkset;
	}

	public JSONObject validateIdToken(JWT idToken) {
		return validateIdToken(idToken, getExpectedIssuer(), (JWSAlgorithm) idToken.getHeader().getAlgorithm());
	}

	public Boolean algorithmIsSupported(Algorithm alg)
	{
		List<JWSAlgorithm> supportedAlgs = this.providerMetadata.getIDTokenJWSAlgs();
		return supportedAlgs.contains(alg);
	}

	public JSONObject validateIdToken(JWT idToken, Issuer iss, JWSAlgorithm jwsAlg)
	{
		if (! algorithmIsSupported(idToken.getHeader().getAlgorithm()) ) {
			throw new RuntimeException("Invalid token algorithm, the algorithm " + idToken.getHeader().getAlgorithm() + "is not supported" );
		}

		IDTokenValidator validator = new IDTokenValidator(iss, this.getClientId(), jwsAlg, this.getJWKSet());
		JSONObject jsonObject = null;
		try {
			IDTokenClaimsSet claims = validator.validate(idToken, null);
			logger.debug("The Id token is valid, the token subject is: " + claims.getSubject());
			jsonObject = claims.toJSONObject();
		}
		catch (BadJOSEException e) {
			e.printStackTrace();
			 // Invalid signature or claims (iss, aud, exp).
			throw new RuntimeException("Invalid signature or claims (iss, aud, exp): " + e.getMessage());

		} catch (JOSEException e) {
		    // Internal processing exception
			e.printStackTrace();
			throw new RuntimeException("Invalid signature: " + e.getMessage());
		}

		return jsonObject;
	}

	public AuthenticationSuccessResponse getAuthenticationResponse(HttpServletRequest request)
	{
		logger.info("Parsing authentication response");
		AuthenticationResponse authResp = null;
		try	{
			authResp = AuthenticationResponseParser.parse(new URI(request.getRequestURL() + "?" + request.getQueryString()));
		}
		catch (Exception e)
		{
			logger.error("Error parsing request" + e.getMessage(), e);
			throw new RuntimeException("Error on OIDC Negotiation: " + e.getMessage());
		}

		if (authResp instanceof AuthenticationErrorResponse)
		{
			ErrorObject error = ((AuthenticationErrorResponse) authResp).getErrorObject();
			logger.error("Error from server " + error.getDescription());
			throw new RuntimeException("Error on OIDC Negotiation: " + error.getDescription() );
		}
		return (AuthenticationSuccessResponse) authResp;

	}

	public void requestOIDCEndSession(JWT idToken) throws IOException
	{
		LogoutRequest request = new LogoutRequest(providerMetadata.getEndSessionEndpointURI(), idToken, this.postLogoutURI, new State());
		request.toHTTPRequest().send();
	}

	public OIDCTokenResponse requestTokensWithAuthorizationCode(AuthorizationCode authCode)
	{
		java.net.URI tokenEndpointURI = providerMetadata.getTokenEndpointURI();
		ClientSecretBasic clientSecretBasic = new ClientSecretBasic(this.clientId, this.clientSecret);
		TokenRequest tokenReq = new TokenRequest(tokenEndpointURI, clientSecretBasic, new AuthorizationCodeGrant(authCode, this.redirectURI));
		logger.info("Requesting token with authorization code: " + authCode + " to endpoint: " + tokenEndpointURI.toString() + " using credentials: " + clientSecretBasic);

		HTTPResponse tokenHTTPResp = null;
		TokenResponse tokenResponse = null;
		try
		{
			tokenHTTPResp = tokenReq.toHTTPRequest().send();
			tokenResponse = OIDCTokenResponseParser.parse(tokenHTTPResp);
			if (tokenResponse instanceof TokenErrorResponse)
			{
				ErrorObject error = ((TokenErrorResponse) tokenResponse).getErrorObject();
				logger.error("Token response is error: " + error.getDescription());
				throw new RuntimeException("Error on OIDC Negotiation");
			}
		}
		catch (Exception e)
		{
			logger.error("Error getting token with authorization code: " + e.getMessage(), e);
			throw new RuntimeException("Error on OIDC Negotiation");
		}

		return (OIDCTokenResponse) tokenResponse;
	}

	public URI getPostLogoutURI() {
		return postLogoutURI;
	}

	public void setPostLogoutURI(URI postLogoutURI) {
		this.postLogoutURI = postLogoutURI;
	}

	public URI getAuthenticationRequestURI(State state, Nonce nonce)
	{
		logger.info("Building OIDC request URI");
		AuthenticationRequest authenticationRequest = new AuthenticationRequest( providerMetadata.getAuthorizationEndpointURI(),
				new ResponseType(ResponseType.Value.CODE),
				this.scope,
				this.clientId,
				this.redirectURI,
				state,
				nonce);
		URI uri = authenticationRequest.toURI();

		if(!this.getAuthorizationRequestURIParameter().isEmpty()) {
			try {
				logger.debug("Triying to add custom parameters to Authentication Request URI: " + this.getAuthorizationRequestURIParameter());
				String newQuery = uri.getQuery() + "&" + this.getAuthorizationRequestURIParameter();
				return new URI(uri.getScheme(), uri.getAuthority(), uri.getPath(), newQuery, uri.getFragment());
			}
			catch (URISyntaxException e) {
				logger.error("Unable to append custom parameters to Authentication Request URI " + e.getMessage());
			}
		}

		return uri;
	}


	public JSONObject requestUserInfo(BearerAccessToken accessToken)
	{
		UserInfoRequest userInfoReq = new UserInfoRequest(providerMetadata.getUserInfoEndpointURI(), accessToken);
		HTTPResponse userInfoHTTPResp = null;
		UserInfoResponse userInfoResponse = null;
		try
		{
			userInfoHTTPResp = userInfoReq.toHTTPRequest().send();
			userInfoResponse = UserInfoResponse.parse(userInfoHTTPResp);
		}
		catch (Exception e)
		{
			logger.error("Error getting User Info: " + e.getMessage(), e);
			throw new RuntimeException("Error getting userinfo", e);
		}

		if (userInfoResponse instanceof UserInfoErrorResponse)
		{
			ErrorObject error = ((UserInfoErrorResponse) userInfoResponse).getErrorObject();
			logger.error("Error getting User Info: " + error.getDescription());
			throw new RuntimeException("Error getting userinfo: " + error.getCode() + " - " + error.getDescription());
		}

		UserInfoSuccessResponse successResponse = (UserInfoSuccessResponse) userInfoResponse;
		return successResponse.getUserInfo().toJSONObject();
	}

}
