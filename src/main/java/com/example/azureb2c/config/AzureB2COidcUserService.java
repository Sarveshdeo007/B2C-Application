package com.example.azureb2c.config;

import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class AzureB2COidcUserService extends OidcUserService {
    private static final Logger logger = LoggerFactory.getLogger(AzureB2COidcUserService.class);

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        try {
            logger.debug("Access Token: {}", userRequest.getAccessToken().getTokenValue());
            logger.debug("ID Token Claims: {}", userRequest.getIdToken().getClaims());

            return super.loadUser(userRequest);
        } catch (OAuth2AuthenticationException ex) {
            logger.error("OAuth2 Authentication Exception: {}", ex.getError().getErrorCode(), ex);

            OAuth2Error oauth2Error = new OAuth2Error(
                    ex.getError().getErrorCode(),
                    "Failed to load user details from Azure B2C",
                    null);
            throw new OAuth2AuthenticationException(oauth2Error, ex);
        } catch (Exception ex) {
            logger.error("Unexpected error: {}", ex.getMessage(), ex);

            OAuth2Error oauth2Error = new OAuth2Error(
                    "unexpected_error",
                    "An unexpected error occurred",
                    null);
            throw new OAuth2AuthenticationException(oauth2Error, ex);
        }
    }
}
