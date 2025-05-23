package com.example.azureb2c.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.ui.Model;
import org.springframework.security.core.annotation.AuthenticationPrincipal;

@Controller
public class ProfileController {
        private static final Logger logger = LoggerFactory.getLogger(ProfileController.class);
        private final ObjectMapper mapper = new ObjectMapper();

        @Value("${spring.security.oauth2.client.registration.azure.client-id:dummy-client-id}")
        private String clientId;

        @GetMapping("/profile/edit")
        public void editProfile(HttpServletResponse response, Authentication authentication) throws IOException {
                logger.debug("Starting profile edit flow for user: {}",
                                authentication != null ? authentication.getName() : "anonymous");

                String redirectUri = "https://grook-production.up.railway.app/login/oauth2/code/azure";
                String nonce = generateNonce();

                String url = String.format(
                                "https://volvogroupiddev.b2clogin.com/volvogroupiddev.onmicrosoft.com/oauth2/v2.0/authorize"
                                                +
                                                "?p=B2C_1A_SARVESHVOLVOGLOBAL_PROFILEEDIT" +
                                                "&client_id=%s" +
                                                "&nonce=%s" +
                                                "&redirect_uri=%s" +
                                                "&scope=openid" +
                                                "&response_type=id_token",
                                clientId, nonce, redirectUri);

                logger.debug("Generated profile edit URL: {}", url);
                logger.debug("Using nonce: {}", nonce);
                response.sendRedirect(url);
        }

        @GetMapping("/profile/reset-password")
        public void resetPassword(HttpServletResponse response, Authentication authentication) throws IOException {
                logger.debug("Starting password reset flow for user: {}",
                                authentication != null ? authentication.getName() : "anonymous");

                String redirectUri = "https://grook-production.up.railway.app/login/oauth2/code/azure";
                String nonce = generateNonce();

                String url = String.format(
                                "https://volvogroupiddev.b2clogin.com/volvogroupiddev.onmicrosoft.com/oauth2/v2.0/authorize"
                                                +
                                                "?p=B2C_1A_SARVESHVOLVOGLOBAL_PASSWORDRESET" +
                                                "&client_id=%s" +
                                                "&nonce=%s" +
                                                "&redirect_uri=%s" +
                                                "&scope=openid" +
                                                "&response_type=id_token",
                                clientId, nonce, redirectUri);

                logger.debug("Generated password reset URL: {}", url);
                logger.debug("Using nonce: {}", nonce);
                response.sendRedirect(url);
        }

        @GetMapping("/profile/delete")
        public void deleteAccount(HttpServletResponse response, Authentication authentication,
                        HttpServletRequest request) throws IOException {
                logger.debug("Starting account deletion flow for user: {}",
                                authentication != null ? authentication.getName() : "anonymous");

                // Set a session attribute to track delete account flow
                request.getSession().setAttribute("delete_account_flow", true);

                String redirectUri = "https://grook-production.up.railway.app/login/oauth2/code/azure";
                String nonce = generateNonce();

                String url = String.format(
                                "https://volvogroupiddev.b2clogin.com/volvogroupiddev.onmicrosoft.com/oauth2/v2.0/authorize"
                                                +
                                                "?p=B2C_1A_VOLVOGLOBAL_DELETEACCOUNT" +
                                                "&client_id=%s" +
                                                "&nonce=%s" +
                                                "&redirect_uri=%s" +
                                                "&scope=openid" +
                                                "&response_type=id_token" +
                                                "&response_mode=form_post",
                                clientId, nonce, redirectUri);

                logger.debug("Generated delete account URL: {}", url);
                response.sendRedirect(url);
        }

        private String generateNonce() {
                SecureRandom secureRandom = new SecureRandom();
                byte[] bytes = new byte[32];
                secureRandom.nextBytes(bytes);
                String nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
                logger.debug("Generated new nonce: {}", nonce);
                return nonce;
        }

        @GetMapping("/profile")
        public String profile(@RequestParam(required = false) String id_token,
                        @AuthenticationPrincipal OidcUser principal,
                        Model model) {
                if (id_token != null) {
                        logger.debug("Received id_token in query parameter: {}", id_token);
                        try {
                                String[] parts = id_token.split("\\.");
                                if (parts.length == 3) {
                                        String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
                                        Map<String, Object> claims = mapper.readValue(payload, Map.class);
                                        logger.debug("Successfully decoded token. Claims: {}", claims);

                                        String name = (String) claims.get("name");
                                        String givenName = (String) claims.get("given_name");
                                        String familyName = (String) claims.get("family_name");

                                        model.addAttribute("name", name);
                                        model.addAttribute("givenName", givenName);
                                        model.addAttribute("familyName", familyName);
                                        model.addAttribute("message", "Profile updated successfully!");
                                        return "profile";
                                }
                        } catch (Exception e) {
                                logger.error("Error processing token: {}", e.getMessage(), e);
                                return "redirect:/error";
                        }
                }

                if (principal != null) {
                        model.addAttribute("name", principal.getClaim("name"));
                        model.addAttribute("givenName", principal.getClaim("given_name"));
                        model.addAttribute("familyName", principal.getClaim("family_name"));
                        return "profile";
                }

                return "redirect:/login";
        }
}