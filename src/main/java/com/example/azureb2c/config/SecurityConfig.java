package com.example.azureb2c.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.web.client.RestTemplate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.HashMap;
import java.util.Map;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotReadableException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpInputMessage;
import com.fasterxml.jackson.core.type.TypeReference;
import java.io.IOException;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.beans.factory.annotation.Value;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import com.example.azureb2c.config.B2CAuthenticationSuccessHandler;
import jakarta.servlet.http.Cookie;
import org.springframework.security.core.context.SecurityContextHolder;
import java.util.Base64;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);
    private static final String END_SESSION_ENDPOINT = "https://volvogroupextid.ciamlogin.com/volvogroupextid.onmicrosoft.com/oauth2/v2.0/logout?p=b2c_1a_g_volvoglobal_signup_signin";

    private final ClientRegistrationRepository clientRegistrationRepository;
    private final B2CAuthenticationSuccessHandler successHandler;
    private final ObjectMapper mapper = new ObjectMapper();

    @Value("${app.base-url:https://grook-production.up.railway.app}")
    private String baseUrl;

    public SecurityConfig(ClientRegistrationRepository clientRegistrationRepository,
            B2CAuthenticationSuccessHandler successHandler) {
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.successHandler = successHandler;
        logger.debug("Initializing SecurityConfig");
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        logger.debug("Configuring SecurityFilterChain");

        String authorizationRequestBaseUri = "/oauth2/authorization";
        final OAuth2AuthorizationRequestResolver resolver = new DefaultOAuth2AuthorizationRequestResolver(
                clientRegistrationRepository, authorizationRequestBaseUri);

        OAuth2AuthorizationRequestResolver customResolver = customizeAuthorizationRequestResolver(resolver);

        // Configure custom logout success handler
        LogoutSuccessHandler logoutSuccessHandler = (request, response, authentication) -> {
            try {
                logger.debug("Handling logout success, redirecting to welcome page");
                request.getSession().invalidate();
                request.getSession(true);
                Cookie[] cookies = request.getCookies();
                if (cookies != null) {
                    for (Cookie cookie : cookies) {
                        cookie.setValue("");
                        cookie.setPath("/");
                        cookie.setMaxAge(0);
                        response.addCookie(cookie);
                    }
                }
                String postLogoutRedirectUri = baseUrl + "/";
                String encodedRedirectUri = URLEncoder.encode(postLogoutRedirectUri, StandardCharsets.UTF_8);
                String logoutUrl = END_SESSION_ENDPOINT + "&post_logout_redirect_uri=" + encodedRedirectUri;
                logger.debug("Redirecting to B2C logout URL: {}", logoutUrl);
                response.sendRedirect(logoutUrl);
            } catch (IOException e) {
                logger.error("Error during logout: ", e);
            }
        };

        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/", "/login", "/error", "/images/**", "/login/oauth2/code/*", "/profile/**",
                                "/handle-fragment")
                        .permitAll()
                        .anyRequest().authenticated())
                .oauth2Login(oauth2 -> oauth2
                        .authorizationEndpoint(authorization -> authorization
                                .authorizationRequestResolver(customResolver)
                                .baseUri(authorizationRequestBaseUri))
                        .tokenEndpoint(token -> token
                                .accessTokenResponseClient(accessTokenResponseClient()))
                        .successHandler(successHandler))
                .logout(logout -> logout
                        .logoutSuccessHandler(logoutSuccessHandler)
                        .invalidateHttpSession(true)
                        .clearAuthentication(true)
                        .deleteCookies("JSESSIONID", "OAuth2AuthorizationRequestResolver.AUTHORIZATION_REQUEST",
                                "XSRF-TOKEN", "OAUTH2_AUTHORIZATION_REQUEST", "OAUTH2_CLIENT_REGISTRATION_ID")
                        .addLogoutHandler((request, response, auth) -> {
                            request.getSession().removeAttribute("SPRING_SECURITY_SAVED_REQUEST");
                            request.getSession().removeAttribute("SPRING_SECURITY_CONTEXT");
                            request.getSession().removeAttribute("OAUTH2_AUTHORIZATION_REQUEST");
                            request.getSession().removeAttribute("OAUTH2_CLIENT_REGISTRATION_ID");
                        }))
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session
                        .invalidSessionUrl("/")
                        .maximumSessions(1)
                        .expiredUrl("/"))
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint((request, response, authException) -> {
                            logger.debug("Handling authentication exception for URI: {}", request.getRequestURI());
                            logger.debug("Request method: {}", request.getMethod());
                            logger.debug("Parameters: {}", request.getParameterMap());

                            // Check if this is a callback from B2C
                            if (request.getRequestURI().contains("/login/oauth2/code/azure")) {
                                // Get form parameters
                                String error = request.getParameter("error");
                                String errorDescription = request.getParameter("error_description");
                                String idToken = request.getParameter("id_token");

                                logger.debug("Processing B2C callback");
                                logger.debug("Error: {}", error);
                                logger.debug("Error Description: {}", errorDescription);
                                logger.debug("Has ID Token: {}", idToken != null);

                                // Check for delete account flow
                                if (request.getMethod().equals("POST")) {
                                    if (errorDescription != null
                                            && errorDescription.toLowerCase().contains("deleteaccount")) {
                                        logger.debug("Detected delete account callback from error description");
                                        performLogout(request, response);
                                        return;
                                    }

                                    // Also check ID token for missing claims if present
                                    if (idToken != null) {
                                        try {
                                            String[] parts = idToken.split("\\.");
                                            if (parts.length == 3) {
                                                String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
                                                Map<String, Object> claims = mapper.readValue(payload, Map.class);
                                                logger.debug("Token claims: {}", claims);

                                                String acr = (String) claims.get("acr");
                                                if (acr != null && acr.toLowerCase().contains("deleteaccount")) {
                                                    logger.debug("Detected delete account callback from acr claim");
                                                    performLogout(request, response);
                                                    return;
                                                }
                                            }
                                        } catch (Exception e) {
                                            logger.error("Error processing ID token: {}", e.getMessage());
                                        }
                                    }
                                }

                                // Handle profile edit callback
                                if (error != null) {
                                    String referer = request.getHeader("Referer");
                                    if (referer != null && referer.contains("#id_token=")) {
                                        String token = referer
                                                .substring(referer.indexOf("#id_token=") + "#id_token=".length());
                                        logger.debug("Found id_token in profile edit callback: {}", token);
                                        response.sendRedirect("/profile?id_token=" + token);
                                        return;
                                    }
                                }
                            }

                            // For all other cases, proceed with normal error handling
                            response.sendRedirect("/login?error");
                        }));

        return http.build();
    }

    private void performLogout(HttpServletRequest request, HttpServletResponse response) throws IOException {
        logger.debug("Performing logout for delete account");
        // Clear session
        request.getSession().invalidate();
        // Clear security context
        SecurityContextHolder.clearContext();
        // Clear cookies
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                cookie.setValue("");
                cookie.setPath("/");
                cookie.setMaxAge(0);
                response.addCookie(cookie);
            }
        }
        // Redirect to B2C logout endpoint
        String postLogoutRedirectUri = baseUrl + "/login?deleted=true";
        String encodedRedirectUri = URLEncoder.encode(postLogoutRedirectUri, StandardCharsets.UTF_8);
        String logoutUrl = END_SESSION_ENDPOINT + "&post_logout_redirect_uri=" + encodedRedirectUri;
        logger.debug("Redirecting to B2C logout URL: {}", logoutUrl);
        response.sendRedirect(logoutUrl);
    }

    private OAuth2AuthorizationRequestResolver customizeAuthorizationRequestResolver(
            OAuth2AuthorizationRequestResolver resolver) {
        return new OAuth2AuthorizationRequestResolver() {
            @Override
            public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
                OAuth2AuthorizationRequest req = resolver.resolve(request);
                logger.debug("Resolving authorization request for URL: {}", request.getRequestURL().toString());
                return customizeRequest(req, request);
            }

            @Override
            public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
                OAuth2AuthorizationRequest req = resolver.resolve(request, clientRegistrationId);
                logger.debug("Resolving authorization request for client: {}", clientRegistrationId);
                return customizeRequest(req, request);
            }

            private OAuth2AuthorizationRequest customizeRequest(OAuth2AuthorizationRequest req,
                    HttpServletRequest request) {
                if (req == null) {
                    logger.debug("Authorization request is null");
                    return null;
                }

                Map<String, Object> additionalParams = new HashMap<>(req.getAdditionalParameters());

                // Check if this is a profile edit request
                String requestURI = request.getRequestURI();
                if (requestURI != null && requestURI.contains("/profile/edit")) {
                    logger.debug("Profile edit request detected");
                    additionalParams.put("response_mode", "form_post");
                }

                logger.debug("Authorization request parameters: {}", additionalParams);
                logger.debug("Authorization request redirect URI: {}", req.getRedirectUri());

                return OAuth2AuthorizationRequest.from(req)
                        .additionalParameters(params -> params.putAll(additionalParams))
                        .build();
            }
        };
    }

    @Bean
    public OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient() {
        DefaultAuthorizationCodeTokenResponseClient client = new DefaultAuthorizationCodeTokenResponseClient();

        RestTemplate restTemplate = new RestTemplate(Arrays.asList(
                new FormHttpMessageConverter(),
                new OAuth2AccessTokenResponseHttpMessageConverter() {
                    @Override
                    protected OAuth2AccessTokenResponse readInternal(Class<? extends OAuth2AccessTokenResponse> clazz,
                            HttpInputMessage inputMessage) throws HttpMessageNotReadableException {
                        try {
                            Map<String, Object> tokenResponseParameters = mapper.readValue(inputMessage.getBody(),
                                    new TypeReference<Map<String, Object>>() {
                                    });

                            String accessToken = (String) tokenResponseParameters.get("access_token");
                            String idToken = (String) tokenResponseParameters.get("id_token");

                            if (accessToken == null && idToken != null) {
                                accessToken = idToken;
                                logger.debug("Using ID token as access token");
                            }

                            long expiresIn = 3600L;
                            if (tokenResponseParameters.containsKey("expires_in")) {
                                expiresIn = Long.parseLong(String.valueOf(tokenResponseParameters.get("expires_in")));
                            }

                            Set<String> scopes = new HashSet<>(Arrays.asList("openid"));

                            return OAuth2AccessTokenResponse.withToken(accessToken)
                                    .tokenType(OAuth2AccessToken.TokenType.BEARER)
                                    .expiresIn(expiresIn)
                                    .scopes(scopes)
                                    .additionalParameters(tokenResponseParameters)
                                    .build();
                        } catch (IOException ex) {
                            logger.error("Error reading token response: ", ex);
                            throw new HttpMessageNotReadableException(
                                    "Error reading OAuth 2.0 Access Token Response: " + ex.getMessage(),
                                    ex, inputMessage);
                        }
                    }
                }));

        client.setRestOperations(restTemplate);
        return client;
    }
}