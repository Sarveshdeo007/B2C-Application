package com.example.azureb2c.config;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import java.io.IOException;

@Component
public class B2CAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    private static final Logger logger = LoggerFactory.getLogger(B2CAuthenticationSuccessHandler.class);

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {
        logger.debug("Authentication success callback started");

        if (authentication.getPrincipal() instanceof OidcUser) {
            OidcUser oidcUser = (OidcUser) authentication.getPrincipal();
            logger.debug("User authenticated successfully: {}", oidcUser.getName());

            request.getSession().setAttribute("user_name", oidcUser.getName());
            request.getSession().setAttribute("id_token", oidcUser.getIdToken().getTokenValue());

            response.sendRedirect("/");
        } else {
            logger.error("Unexpected authentication type: {}", authentication.getClass());
            response.sendRedirect("/error");
        }
    }
}
