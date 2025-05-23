package com.example.azureb2c.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Base64;
import java.util.Map;
import java.io.IOException;

@Controller
public class AuthController {
    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);
    private final ObjectMapper mapper = new ObjectMapper();

    @GetMapping("/")
    public String home(@AuthenticationPrincipal OidcUser principal, HttpServletRequest request, Model model) {
        logger.debug("Accessing home page");

        if (principal == null) {
            logger.debug("User is not authenticated. Redirecting to login page.");
            return "login";
        }

        try {
            String idToken = (String) request.getSession().getAttribute("id_token");
            logger.debug("User claims: {}", principal.getClaims());

            // Get name and email from claims
            String name = principal.getAttribute("name");
            String email = principal.getAttribute("signInNames.emailAddress");

            model.addAttribute("name", name);
            model.addAttribute("email", email != null ? email : "Unknown");
            model.addAttribute("idToken", idToken);

            logger.debug("Returning home page with user details");
            return "home";
        } catch (Exception e) {
            logger.error("Error while loading home page: {}", e.getMessage(), e);
            model.addAttribute("error", "Failed to load user details. Please try again.");
            return "error";
        }
    }

    @GetMapping("/login")
    public String login(HttpServletRequest request,
            @RequestParam(required = false) String error,
            @RequestParam(required = false) String deleted,
            Model model) throws IOException {
        logger.debug("Handling login request at: {}", request.getRequestURL().toString());
        logger.debug("Query string: {}", request.getQueryString());
        logger.debug("Referer: {}", request.getHeader("Referer"));

        // Check if this is coming from delete account flow
        String referer = request.getHeader("Referer");
        if (referer != null && referer.contains("VOLVOGLOBAL_DELETEACCOUNT")) {
            logger.debug("Detected delete account flow from referer, redirecting to logout");
            return "redirect:/logout";
        }

        // Check if this is a profile edit callback with id_token in fragment
        if (referer != null && referer.contains("#id_token=")) {
            String idToken = referer.substring(referer.indexOf("#id_token=") + "#id_token=".length());
            logger.debug("Found id_token in URL fragment: {}", idToken);

            // Decode the token to check if it's from delete account flow
            try {
                String[] parts = idToken.split("\\.");
                if (parts.length == 3) {
                    String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
                    Map<String, Object> claims = mapper.readValue(payload, Map.class);
                    logger.debug("Token claims: {}", claims);

                    String acr = (String) claims.get("acr");
                    if (acr != null && acr.toLowerCase().contains("deleteaccount")) {
                        logger.debug("Detected delete account flow from token claims");
                        return "redirect:/logout";
                    }
                }
            } catch (Exception e) {
                logger.error("Error processing token: {}", e.getMessage());
            }

            return "redirect:/profile?id_token=" + idToken;
        }

        if (deleted != null && deleted.equals("true")) {
            model.addAttribute("success", "Your account has been successfully deleted.");
        } else if (error != null) {
            // Check if we have a session attribute indicating delete account flow
            Object deleteFlow = request.getSession().getAttribute("delete_account_flow");
            if (deleteFlow != null && (Boolean) deleteFlow) {
                logger.debug("Detected delete account flow from session, redirecting to logout");
                request.getSession().removeAttribute("delete_account_flow");
                return "redirect:/logout";
            }
            model.addAttribute("error", "Authentication failed. Please try again.");
        }
        return "login";
    }

    @GetMapping("/error")
    public String error(HttpServletRequest request, Model model) {
        String errorMessage = request.getParameter("message");
        logger.debug("Error occurred: {}", errorMessage);
        model.addAttribute("error", errorMessage != null ? errorMessage : "An unexpected error occurred.");
        return "error";
    }
}
