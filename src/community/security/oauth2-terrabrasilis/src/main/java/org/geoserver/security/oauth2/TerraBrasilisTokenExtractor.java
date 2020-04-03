package org.geoserver.security.oauth2;

import java.util.Arrays;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.authentication.BearerTokenExtractor;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

public class TerraBrasilisTokenExtractor extends BearerTokenExtractor {
	
	private final static Log logger = LogFactory.getLog(TerraBrasilisTokenExtractor.class);
	private final static String TERRABRASILIS_COOKIE_KEY="oauth.obt.inpe.br";
	
	@Override
	public Authentication extract(HttpServletRequest request) {
		String tokenValue = extractToken(request);
		if (tokenValue != null) {
			PreAuthenticatedAuthenticationToken authentication = new PreAuthenticatedAuthenticationToken(tokenValue, "");
			return authentication;
		}
		return null;
	}
	
	@Override
	protected String extractToken(HttpServletRequest request) {
		
		// first check the header...
		String token = extractHeaderToken(request);

		// bearer type allows a request parameter as well
		if (token == null) {
			logger.debug("Token not found in headers. Trying request cookies.");
			token = this.extractTokenFromCookies(request);
			if (token == null) {
				logger.debug("Token not found in request cookies.  Trying request params.");
				token = request.getParameter(OAuth2AccessToken.ACCESS_TOKEN);
				if (token == null) {
					logger.debug("Token not found in request parameters.  Not an OAuth2 request.");
				}
			}			
			else {
				request.setAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_TYPE, OAuth2AccessToken.BEARER_TYPE);
			}
		} 
			

		return token;
	}
	
	private String extractTokenFromCookies(HttpServletRequest request)
	{
		String token=null;
		if(request.getCookies()!=null)
		{
			for (Cookie cookie : request.getCookies()) {
				if(TERRABRASILIS_COOKIE_KEY.equalsIgnoreCase(cookie.getName()))
				{
					token=cookie.getValue();
					break;
				}
			 }
		}
	return token;
	}
}
