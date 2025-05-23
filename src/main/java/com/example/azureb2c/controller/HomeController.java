package com.example.azureb2c.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.util.Base64;
import java.util.Map;
import java.util.HashMap;

@Controller
public class HomeController {
    private static final Logger logger = LoggerFactory.getLogger(HomeController.class);
    private final ObjectMapper mapper = new ObjectMapper();

    @GetMapping("/home")
    public String home(@RequestParam(required = false) String id_token,
            @AuthenticationPrincipal OidcUser principal,
            Model model,
            HttpServletRequest request,
            HttpSession session) {
        logger.debug("Accessing home page with principal: {}", principal);

        if (id_token != null) {
            try {
                String[] parts = id_token.split("\\.");
                if (parts.length == 3) {
                    String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
                    Map<String, Object> newClaims = mapper.readValue(payload, Map.class);
                    logger.debug("Successfully decoded token claims: {}", newClaims);

                    // Check if this is from delete account flow by checking missing claims
                    if (!newClaims.containsKey("name") || !newClaims.containsKey("given_name")) {
                        logger.debug("Detected delete account flow (missing name claims), performing cleanup");
                        // Clear session
                        session.invalidate();
                        // Clear security context
                        SecurityContextHolder.clearContext();
                        // Redirect to logout
                        return "redirect:/logout";
                    }

                    // Get existing claims if principal exists
                    Map<String, Object> existingClaims = principal != null ? principal.getClaims() : new HashMap<>();

                    // Create merged claims starting with existing claims
                    Map<String, Object> mergedClaims = new HashMap<>(existingClaims);

                    // Check which flow we're coming from based on acr claim
                    String acr = (String) newClaims.get("acr");
                    boolean isPasswordReset = acr != null && acr.toLowerCase().contains("passwordreset");

                    if (isPasswordReset) {
                        // For password reset, preserve existing name-related claims
                        preserveNameClaims(mergedClaims, existingClaims);
                        // Update only auth-related claims
                        updateAuthClaims(mergedClaims, newClaims);
                        model.addAttribute("message", "Password reset successful!");
                    } else {
                        // For profile update, use new name claims
                        updateNameClaims(mergedClaims, newClaims);
                        // Update auth claims
                        updateAuthClaims(mergedClaims, newClaims);
                        model.addAttribute("message", "Profile updated successfully!");
                    }

                    // Preserve critical claims
                    preserveCriticalClaims(mergedClaims, existingClaims);

                    // Update model and session
                    updateModelWithClaims(model, mergedClaims);
                    updateSessionAndAuthentication(mergedClaims, session, request, principal);

                    return "home";
                }
            } catch (Exception e) {
                logger.error("Error processing token: {}", e.getMessage(), e);
                // Continue with existing principal if token processing fails
                if (principal != null) {
                    updateModelWithClaims(model, principal.getClaims());
                }
                return "home";
            }
        }

        if (principal != null) {
            updateModelWithClaims(model, principal.getClaims());
            return "home";
        }

        return "redirect:/login";
    }

    private void preserveNameClaims(Map<String, Object> mergedClaims, Map<String, Object> existingClaims) {
        String[] nameClaims = { "name", "given_name", "family_name" };
        for (String claim : nameClaims) {
            if (existingClaims.containsKey(claim)) {
                mergedClaims.put(claim, existingClaims.get(claim));
            }
        }
    }

    private void updateNameClaims(Map<String, Object> mergedClaims, Map<String, Object> newClaims) {
        String[] nameClaims = { "name", "given_name", "family_name" };
        for (String claim : nameClaims) {
            if (newClaims.containsKey(claim)) {
                mergedClaims.put(claim, newClaims.get(claim));
            }
        }
    }

    private void updateAuthClaims(Map<String, Object> mergedClaims, Map<String, Object> newClaims) {
        String[] authClaims = { "auth_time", "nonce", "exp", "iat", "nbf", "acr" };
        for (String claim : authClaims) {
            if (newClaims.containsKey(claim)) {
                mergedClaims.put(claim, newClaims.get(claim));
            }
        }
    }

    private void preserveCriticalClaims(Map<String, Object> mergedClaims, Map<String, Object> existingClaims) {
        // Preserve email claims
        String[] emailClaims = { "email", "emails", "signInNames.emailAddress" };
        for (String claim : emailClaims) {
            if (existingClaims.containsKey(claim)) {
                mergedClaims.put(claim, existingClaims.get(claim));
            }
        }

        // Preserve other critical claims
        String[] criticalClaims = { "sub", "iss", "aud", "tid", "ver", "country", "preferredLanguage" };
        for (String claim : criticalClaims) {
            if (existingClaims.containsKey(claim)) {
                mergedClaims.put(claim, existingClaims.get(claim));
            }
        }
    }

    private void updateModelWithClaims(Model model, Map<String, Object> claims) {
        model.addAttribute("name", claims.get("name"));
        model.addAttribute("givenName", claims.get("given_name"));
        model.addAttribute("familyName", claims.get("family_name"));
        model.addAttribute("email", extractEmail(claims));
    }

    private String extractEmail(Map<String, Object> claims) {
        Object emailObj = claims.get("emails");
        if (emailObj instanceof java.util.List) {
            java.util.List<?> emails = (java.util.List<?>) emailObj;
            if (!emails.isEmpty()) {
                return emails.get(0).toString();
            }
        }

        String email = (String) claims.get("email");
        if (email != null)
            return email;

        email = (String) claims.get("signInNames.emailAddress");
        if (email != null)
            return email;

        if (emailObj != null) {
            return emailObj.toString();
        }

        return null;
    }

    private void updateSessionAndAuthentication(Map<String, Object> claims, HttpSession session,
            HttpServletRequest request, OidcUser principal) {
        try {
            // Update session attributes
            session.setAttribute("user_claims", claims);
            session.setAttribute("name", claims.get("name"));

            // Only update email if it exists in claims
            String email = extractEmail(claims);
            if (email != null) {
                session.setAttribute("email", email);
            }

            // Update Spring Security context with new claims
            if (SecurityContextHolder.getContext()
                    .getAuthentication() instanceof OAuth2AuthenticationToken currentAuth) {
                try {
                    // Create new token with all required claims
                    OidcIdToken newToken = new OidcIdToken(
                            claims.get("jti") != null ? claims.get("jti").toString()
                                    : java.util.UUID.randomUUID().toString(),
                            claims.get("iat") instanceof Number
                                    ? java.time.Instant.ofEpochSecond(((Number) claims.get("iat")).longValue())
                                    : java.time.Instant.now(),
                            claims.get("exp") instanceof Number
                                    ? java.time.Instant.ofEpochSecond(((Number) claims.get("exp")).longValue())
                                    : java.time.Instant.now().plusSeconds(3600),
                            claims);

                    // Create user info with all claims
                    OidcUserInfo userInfo = new OidcUserInfo(claims);

                    // Create new user with all information
                    DefaultOidcUser newUser = new DefaultOidcUser(
                            principal.getAuthorities(),
                            newToken,
                            userInfo);

                    // Create new authentication token
                    OAuth2AuthenticationToken newAuth = new OAuth2AuthenticationToken(
                            newUser,
                            principal.getAuthorities(),
                            currentAuth.getAuthorizedClientRegistrationId());

                    // Update security context
                    SecurityContextHolder.getContext().setAuthentication(newAuth);
                    logger.debug("Successfully updated authentication with claims: {}", claims);
                } catch (Exception e) {
                    logger.error("Error creating new token: {}", e.getMessage(), e);
                    throw e;
                }
            }
        } catch (Exception e) {
            logger.error("Error updating session/authentication: {}", e.getMessage(), e);
            throw e;
        }
    }
}
