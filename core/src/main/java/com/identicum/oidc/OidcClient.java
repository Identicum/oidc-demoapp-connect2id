package com.identicum.oidc;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLConnection;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.servlet.http.HttpServletRequest;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.AuthorizationRequest.Builder;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.minidev.json.JSONObject;

public class OidcClient {
	private final static Logger logger = LoggerFactory.getLogger(OidcClient.class);

	private URI redirectURI;
	private String authorizationRequestURIParameter;
	private ClientID clientId;
	private Secret clientSecret;
	private Scope scope;
	private URI postLogoutURI;
	private Boolean requestParameterEnabled;
	private String requestObjectSigningAlg;
	private String metadataEndpoint;

	private Boolean skipSSLCertValidation;

	private OIDCProviderMetadata providerMetadata;

	public URI getRedirectURI() {
		return redirectURI;
	}

	public void setRedirectURI(URI redirectURI) {
		this.redirectURI = redirectURI;
	}

	public void setMetadataEndpoint(String metadataEndpoint){
		this.metadataEndpoint = metadataEndpoint;
	}

	public String getMetadataEndpoint(){
		return metadataEndpoint;
	}

	public void setRequestParameter(Boolean enabled)
	{
		this.requestParameterEnabled = enabled;
	}

	public String getRequestObjectSigningAlg()
	{
		return this.requestObjectSigningAlg;
	}

	public void setRequestObjectSigningAlg(String requestObjectSigningAlg)
	{
		this.requestObjectSigningAlg = requestObjectSigningAlg;
	}
	
	public void setSkipSSLCertValidation(Boolean skipSSLCertValidation)
	{
		this.skipSSLCertValidation = skipSSLCertValidation;
	}

	public Boolean isSkipSSLCertValidationEnabled()
	{
		return skipSSLCertValidation;
	}

	public Boolean isParameterRequestEnabled()
	{
		return requestParameterEnabled;
	}

	public ClientID getClientId() {
		return clientId;
	}

	public void setClientId(ClientID clientId) {
		this.clientId = clientId;
	}

	public Secret getClientSecret() {
		return clientSecret;
	}

	public void setClientSecret(Secret clientSecret) {
		this.clientSecret = clientSecret;
	}

	public Scope getScope() {
		return scope;
	}

	public void setScope(Scope scope) {
		this.scope = scope;
	}

	public void setScopes(String scopes) {
		this.scope = Scope.parse(scopes);
	}

	public String getAuthorizationRequestURIParameter() {
		return authorizationRequestURIParameter;
	}

	public Boolean isPublic(){
		return (StringUtils.isBlank(this.getClientSecret().getValue()));
	}

	public void setAuthorizationRequestURIParameter(String authorizationRequestURIParameter) {
		this.authorizationRequestURIParameter = authorizationRequestURIParameter;
	}

	public void discoverMetadata() {
		try {
			this.providerMetadata = OIDCProviderMetadata.parse(this.getContent(this.getMetadataEndpoint()));
		} catch (ParseException e) {
			throw new RuntimeException("Unable to parse provider metadata: " + this.getMetadataEndpoint(), e);
		}
	}

	private SSLSocketFactory getSSLContextTrustAllCerts() {
		try 
		{
			TrustManager[] trustAllCerts = new X509TrustManager[] { new X509TrustManager() {
				public java.security.cert.X509Certificate[] getAcceptedIssuers() {
					return null;
				}
				public void checkClientTrusted(X509Certificate[] certs, String authType) {
				}
				public void checkServerTrusted(X509Certificate[] certs, String authType) {
				}
			} };
			// Install the all-trusting trust manager
			SSLContext sc = SSLContext.getInstance("SSL");
			sc.init(null, trustAllCerts, new java.security.SecureRandom());
			return sc.getSocketFactory();
		} catch (Exception e) {
			throw new RuntimeException("Unable create SSL Context for trusting all certificates", e);
		}
	}

	private String getContent(String endpoint) {
		try {
			URLConnection httpUrlConn = new URL(endpoint).openConnection();
			InputStream stream;	
			logger.debug("Getting data from: {}", endpoint);
			if (httpUrlConn instanceof HttpsURLConnection && this.skipSSLCertValidation) {
				logger.debug("Disabled SSL certificate validation ...");
				((HttpsURLConnection) httpUrlConn).setSSLSocketFactory(getSSLContextTrustAllCerts());
				((HttpsURLConnection) httpUrlConn).setHostnameVerifier(new HostnameVerifier() {
					public boolean verify(String hostname, SSLSession session) {
						return true;
					}
				});
			}
			stream = httpUrlConn.getInputStream();
			@SuppressWarnings("resource")
			java.util.Scanner s = new java.util.Scanner(stream);
			String content = s.useDelimiter("\\A").hasNext() ? s.next() : "";
			stream.close();
			return content;
		} catch (Exception e) {
			throw new RuntimeException("Unable to get data from url: " + endpoint, e);
		}
	}

	private Issuer getExpectedIssuer() {
		return this.providerMetadata.getIssuer();
	}

	private JWKSet getJWKSet() {
		try {
			return JWKSet.parse(this.getContent(this.providerMetadata.getJWKSetURI().toString()));
		} catch (java.text.ParseException e) {
			throw new RuntimeException("Unable to parse jwt from provider metadata", e);
		}
	}

	public JSONObject validateIdToken(JWT idToken) {
		return validateIdToken(idToken, getExpectedIssuer(), (JWSAlgorithm) idToken.getHeader().getAlgorithm());
	}

	public Boolean algSigningObjectRequestIsSupported(Algorithm alg)
	{
		return this.providerMetadata.getRequestObjectJWSAlgs().contains(alg);
	}
	
	public Boolean algorithmIsSupported(Algorithm alg) {
		List<JWSAlgorithm> supportedAlgs = this.providerMetadata.getIDTokenJWSAlgs();
		return supportedAlgs.contains(alg);
	}

	public JSONObject validateIdToken(JWT idToken, Issuer iss, JWSAlgorithm jwsAlg) {
		logger.debug("Validating if algorithm header is supported");
		if (!algorithmIsSupported(idToken.getHeader().getAlgorithm())) {
			throw new RuntimeException("Invalid token algorithm, the algorithm " + idToken.getHeader().getAlgorithm()
					+ "is not supported");
		}

		logger.debug("Validating iss {}, alg: {} ", iss, jwsAlg);
		IDTokenValidator validator = new IDTokenValidator(iss, this.getClientId(), jwsAlg, this.getJWKSet());
		JSONObject jsonObject = null;
		try {
			IDTokenClaimsSet claims = validator.validate(idToken, null);
			logger.debug("The Id token is valid, the token subject is: " + claims.getSubject());
			jsonObject = claims.toJSONObject();
		} catch (BadJOSEException e) {
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

	public AuthenticationSuccessResponse getAuthenticationResponse(HttpServletRequest request) {
		logger.info("Parsing authentication response");
		AuthenticationResponse authResp = null;
		try {
			authResp = AuthenticationResponseParser.parse(new URI(request.getRequestURL() + "?" + request.getQueryString()));
		} catch (Exception e) {
			logger.error("Error parsing request" + e.getMessage(), e);
			throw new RuntimeException("Error on OIDC Negotiation: " + e.getMessage());
		}

		if (authResp instanceof AuthenticationErrorResponse) {
			ErrorObject error = ((AuthenticationErrorResponse) authResp).getErrorObject();
			logger.error("Error from server " + error.getDescription());
			throw new RuntimeException("Error on OIDC Negotiation: " + error.getDescription());
		}
		return (AuthenticationSuccessResponse) authResp;

	}

	public LogoutRequest requestOIDCEndSession(JWT idToken) throws IOException {
		LogoutRequest request = new LogoutRequest(providerMetadata.getEndSessionEndpointURI(), idToken, this.postLogoutURI, new State());
		return request;
	}

	public OIDCTokenResponse requestTokensWithAuthorizationCode(AuthorizationCode authCode, CodeVerifier codeVerifier) {
		
		TokenRequest tokenRequest = new TokenRequest(providerMetadata.getTokenEndpointURI(),this.clientId, new AuthorizationCodeGrant(authCode, this.redirectURI, codeVerifier));
		
		logger.info("Requesting token with authz code: {} to endpoint: {} using code verifier: {}", authCode, providerMetadata.getAuthorizationEndpointURI(), codeVerifier.getValue());
		return requestToken(tokenRequest);
	}

	private OIDCTokenResponse requestToken(TokenRequest tokenReq)
	{
		try 
		{
			HTTPRequest request = disableSSLCertValidation(tokenReq.toHTTPRequest());
			HTTPResponse tokenHTTPResp = request.send();
			TokenResponse tokenResponse = OIDCTokenResponseParser.parse(tokenHTTPResp);
			if (tokenResponse instanceof TokenErrorResponse) {
				ErrorObject error = ((TokenErrorResponse) tokenResponse).getErrorObject();
				logger.error("Token response is error: " + error.getDescription());
				throw new RuntimeException("Error on OIDC Negotiation");
			}
			return (OIDCTokenResponse) tokenResponse;
		} catch (Exception e) 
		{
			logger.error("Error getting token with authorization code: " + e.getMessage(), e);
			throw new RuntimeException("Error on OIDC Negotiation", e);
		}
	}
	
	public OIDCTokenResponse requestTokensWithAuthorizationCode(AuthorizationCode authCode) {
	
		ClientSecretBasic clientSecretBasic = new ClientSecretBasic(this.clientId, this.clientSecret);
		TokenRequest tokenReq = new TokenRequest(providerMetadata.getTokenEndpointURI(), clientSecretBasic, new AuthorizationCodeGrant(authCode, this.redirectURI));

		logger.info("Requesting token with authz code: {} to endpoint: {} using client credentials.", authCode, providerMetadata.getAuthorizationEndpointURI());

		return requestToken(tokenReq);
		
	}

	public URI getPostLogoutURI() {
		return postLogoutURI;
	}

	public void setPostLogoutURI(URI postLogoutURI) {
		this.postLogoutURI = postLogoutURI;
	}

	public URI getAuthenticationRequestURI(State state, Nonce nonce)
	{
		Builder authzRequestBuilder = this.getBaseAuthzRequest(state, nonce);

		if (this.requestParameterEnabled) 
		{
			try {
				
				//@see: https://openid.net/specs/openid-connect-core-1_0.html#JWTRequests
				if(this.requestObjectSigningAlg.equalsIgnoreCase(JWSAlgorithm.NONE.getName()) || this.requestObjectSigningAlg.isEmpty() )
				{
					logger.debug("Generating plain JWT for request object with claims: {}", authzRequestBuilder.build().toJWTClaimsSet());
					PlainJWT plainJWT = new PlainJWT(authzRequestBuilder.build().toJWTClaimsSet());
					logger.debug("Plain JWT generated: " + plainJWT.serialize());
					authzRequestBuilder.requestObject(plainJWT);
				}
				else
				{
					logger.debug("Generating JWS {} for request object with claims: {}", this.requestObjectSigningAlg ,authzRequestBuilder.build().toJWTClaimsSet());
					JWSAlgorithm alg = new JWSAlgorithm(this.requestObjectSigningAlg);
					if(!algSigningObjectRequestIsSupported(alg)) throw new RuntimeException("Signing alg " + alg.getName() + " for request object is not supported" );
					JWSSigner signer = new MACSigner(this.getClientSecret().getValue().getBytes());
					SignedJWT signedJWT = new SignedJWT(new JWSHeader(alg), authzRequestBuilder.build().toJWTClaimsSet());
					signedJWT.sign(signer);
					logger.debug("JWS generated: " + signedJWT.serialize());
					authzRequestBuilder.requestObject(signedJWT);
				}

			} catch (Exception e) {
				e.printStackTrace();
				throw new RuntimeException("Unable to generate JWT for request object", e);
			}
		}
		return addCommonParametersAuthzRequest(authzRequestBuilder);
		
	} 

	public URI getAuthenticationRequestURI(State state, Nonce nonce, CodeVerifier pkceVerifier)
	{
		Builder authzRequestBuilder = this.getBaseAuthzRequest(state, nonce);
		logger.debug("Public client detected, adding PCKE SHA-256 code verifier to authz request");
		authzRequestBuilder.codeChallenge(pkceVerifier, CodeChallengeMethod.S256);
		if (this.requestParameterEnabled) {
			logger.warn("Not implemented request object for public client");
		}
		return addCommonParametersAuthzRequest(authzRequestBuilder);
	}

	private Builder getBaseAuthzRequest(State state, Nonce nonce)
	{
		logger.info("Building Authz request, client id: {}, scope: {}", this.clientId, this.scope);
		return new AuthorizationRequest.Builder(new ResponseType(ResponseType.Value.CODE), this.clientId).scope(scope).state(state);
	}

	private URI addCommonParametersAuthzRequest(Builder authzRequestBuilder) 
	{
		authzRequestBuilder.redirectionURI(this.redirectURI)
						   .endpointURI(providerMetadata.getAuthorizationEndpointURI());
		URI uri = authzRequestBuilder.build().toURI();

		if (!this.getAuthorizationRequestURIParameter().isEmpty()) {
			try {
				logger.debug("Triying to add custom parameters to Authentication Request URI: "
						+ this.getAuthorizationRequestURIParameter());
				String newQuery = uri.getQuery() + "&" + this.getAuthorizationRequestURIParameter();
				return new URI(uri.getScheme(), uri.getAuthority(), uri.getPath(), newQuery, uri.getFragment());
			} catch (URISyntaxException e) {
				logger.error("Unable to append custom parameters to Authentication Request URI " + e.getMessage());
			}
		}
		return uri;
	}

	private HTTPRequest disableSSLCertValidation(HTTPRequest request)
	{
		request.setSSLSocketFactory(getSSLContextTrustAllCerts());
		request.setHostnameVerifier(new HostnameVerifier() {
			public boolean verify(String hostname, SSLSession session) {
				return true;
			}
		});
		return request;

	}

	public JSONObject requestUserInfo(BearerAccessToken accessToken)
	{
		UserInfoRequest userInfoReq = new UserInfoRequest(providerMetadata.getUserInfoEndpointURI(), accessToken);
		HTTPResponse userInfoHTTPResp = null;
		UserInfoResponse userInfoResponse = null;
		try
		{	
			HTTPRequest request  = (this.skipSSLCertValidation) ? disableSSLCertValidation(userInfoReq.toHTTPRequest()) : userInfoReq.toHTTPRequest();	
			userInfoHTTPResp = request.send();
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

	public JSONObject requestTokenInfo(BearerAccessToken accessToken)
	{
		TokenIntrospectionRequest tokenInfoReq = new TokenIntrospectionRequest(providerMetadata.getIntrospectionEndpointURI(), accessToken);
		HTTPResponse tokenInfoHTTPResp = null;
		TokenIntrospectionResponse tokenInfoResponse = null;
		try
		{
			HTTPRequest request  = (this.skipSSLCertValidation) ? disableSSLCertValidation(tokenInfoReq.toHTTPRequest()) : tokenInfoReq.toHTTPRequest();
			tokenInfoHTTPResp = request.send();
			tokenInfoResponse = TokenIntrospectionResponse.parse(tokenInfoHTTPResp);
		}
		catch (Exception e)
		{
			logger.error("Error getting Token Info: " + e.getMessage(), e);
			throw new RuntimeException("Error getting tokeninfo", e);
		}

		if (tokenInfoResponse instanceof TokenIntrospectionErrorResponse)
		{
			ErrorObject error = ((TokenIntrospectionErrorResponse) tokenInfoResponse).getErrorObject();
			logger.error("Error getting Token Info: " + error.getDescription());
			throw new RuntimeException("Error getting tokeninfo: " + error.getCode() + " - " + error.getDescription());
		}

		TokenIntrospectionSuccessResponse successResponse = (TokenIntrospectionSuccessResponse) tokenInfoResponse;
		return successResponse.toJSONObject();
	}

	@Override
	public String toString()
	{
		StringBuilder defs = new StringBuilder();
		defs.append("clientId: ").append(this.clientId);
		defs.append(", scope: ").append(this.scope);
		defs.append(", redirectUri: " + this.redirectURI);
		defs.append(", publicClient: ").append(this.isPublic());
		defs.append(", requestParameterEnabled: ").append(this.isParameterRequestEnabled());
		defs.append(", requestObjectSigningAlg: ").append(this.requestObjectSigningAlg);
		defs.append(", skipSslCertificateValidation: ").append(this.isSkipSSLCertValidationEnabled());
		defs.append(", authzRequestUriParams: ").append(this.getAuthorizationRequestURIParameter());
		defs.append(", metadataEndpoint: ").append(this.getMetadataEndpoint());
		return defs.toString();
	}
}
