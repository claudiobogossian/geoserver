/* (c) 2016 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.oauth2;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.logging.Level;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.geoserver.security.SecurityUtils;
import org.geoserver.security.config.SecurityNamedServiceConfig;
import org.geoserver.security.impl.GeoServerRole;
import org.geoserver.security.impl.GeoServerUser;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.authentication.BearerTokenExtractor;
import org.springframework.security.oauth2.provider.token.RemoteTokenServices;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

/** @author Alessio Fabiani, GeoSolutions S.A.S. */
public class TerraBrasilisOAuthAuthenticationFilter extends GeoServerOAuthAuthenticationFilter {

    public TerraBrasilisOAuthAuthenticationFilter(
            SecurityNamedServiceConfig config,
            RemoteTokenServices tokenServices,
            GeoServerOAuth2SecurityConfiguration oauth2SecurityConfiguration,
            OAuth2RestOperations oauth2RestTemplate) {
        super(config, tokenServices, oauth2SecurityConfiguration, oauth2RestTemplate);
    }

    @Override
    protected void doAuthenticate(HttpServletRequest request, HttpServletResponse response) {

        String principal = null;
        try {
            principal = getPreAuthenticatedPrincipal(request, response);
        } catch (IOException e1) {
            LOGGER.log(Level.FINE, e1.getMessage(), e1);
            principal = null;
        } catch (ServletException e1) {
            LOGGER.log(Level.FINE, e1.getMessage(), e1);
            principal = null;
        }

        LOGGER.log(
                Level.FINE,
                "preAuthenticatedPrincipal = " + principal + ", trying to authenticate");

        PreAuthenticatedAuthenticationToken result = null;

        if (principal == null || principal.trim().length() == 0) {
            result =
                    new PreAuthenticatedAuthenticationToken(
                            principal, null, Collections.singleton(GeoServerRole.ANONYMOUS_ROLE));
        } else {
            if (GeoServerUser.ROOT_USERNAME.equals(principal)) {
                result =
                        new PreAuthenticatedAuthenticationToken(
                                principal,
                                null,
                                Arrays.asList(
                                        GeoServerRole.ADMIN_ROLE,
                                        GeoServerRole.GROUP_ADMIN_ROLE,
                                        GeoServerRole.AUTHENTICATED_ROLE));
            } else {
                Collection<GeoServerRole> roles = null;

                roles = new ArrayList<GeoServerRole>();

                roles.add(GeoServerRole.AUTHENTICATED_ROLE);

                result = new PreAuthenticatedAuthenticationToken(principal, null, roles);
            }
        }

        result.setDetails(getAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(result);
    }
    @Override
    protected String getBearerToken(ServletRequest request) {
        if (request instanceof HttpServletRequest) {
            Authentication auth = new TerraBrasilisTokenExtractor().extract((HttpServletRequest) request);
            if (auth != null) return SecurityUtils.getUsername(auth.getPrincipal());
        }

        return null;
    }
    
    private String getAccessTokenFromRequest(ServletRequest req) {
        String accessToken = getParameterValue("access_token", req);
        if (accessToken == null) {
            accessToken = getBearerToken(req);
        }
        return accessToken;
    }
    
    /** Try to authenticate if there is no authenticated principal */
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        // Search for an access_token on the request (simulating SSO)
        String accessToken = getAccessTokenFromRequest(request);

        OAuth2AccessToken token = restTemplate.getOAuth2ClientContext().getAccessToken();

        
        /**
         *  Por enquanto realizar todas as requisções a validação da sessão. Se tiver problema de desempenho
         *  verificar de realizar a validação abaixo se o usuário já tiver sessão com o mesmo token.
         */
        
        if (accessToken != null && token != null && !token.getValue().equals(accessToken)) {
            restTemplate.getOAuth2ClientContext().setAccessToken(null);
        }

        HttpServletRequest httpRequest = (HttpServletRequest) request;

        /*
         * This cookie works only locally, when accessing the GeoServer GUI and on the same domain. For remote access you need to logout from the
         * GeoServer GUI.
         */
        final String customSessionCookie = getCustomSessionCookieValue(httpRequest);

        Authentication authentication = null;
        
        if(accessToken==null)
        {
        	authentication = SecurityContextHolder.getContext().getAuthentication();
        }
        
        
        final Collection<? extends GrantedAuthority> authorities =
                (authentication != null ? authentication.getAuthorities() : null);

        if (accessToken == null
                && customSessionCookie == null
                && (authentication != null
                        && (authentication instanceof PreAuthenticatedAuthenticationToken)
                        && !(authorities.size() == 1
                                && authorities.contains(GeoServerRole.ANONYMOUS_ROLE)))) {
            final AccessTokenRequest accessTokenRequest =
                    restTemplate.getOAuth2ClientContext().getAccessTokenRequest();
            if (accessTokenRequest != null && accessTokenRequest.getStateKey() != null) {
                restTemplate
                        .getOAuth2ClientContext()
                        .removePreservedState(accessTokenRequest.getStateKey());
            }

            try {
                accessTokenRequest.remove("access_token");
            } finally {
                SecurityContextHolder.clearContext();
                httpRequest.getSession(false).invalidate();
                try {
                    httpRequest.logout();
                    authentication = null;
                } catch (ServletException e) {
                    LOGGER.fine(e.getLocalizedMessage());
                }
                LOGGER.fine("Cleaned out Session Access Token Request!");
            }
        }

        if ((authentication == null && accessToken != null)
                || authentication == null
                || (authentication != null
                        && authorities.size() == 1
                        && authorities.contains(GeoServerRole.ANONYMOUS_ROLE))) {

            doAuthenticate((HttpServletRequest) request, (HttpServletResponse) response);

            Authentication postAuthentication = authentication;
            if (postAuthentication != null) {
                if (cacheAuthentication(postAuthentication, (HttpServletRequest) request)) {
                    getSecurityManager()
                            .getAuthenticationCache()
                            .put(
                                    getName(),
                                    getCacheKey((HttpServletRequest) request),
                                    postAuthentication);
                }
            }
        }

        chain.doFilter(request, response);
    }
}
