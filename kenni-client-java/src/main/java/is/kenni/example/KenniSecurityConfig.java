package is.kenni.example;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

/**
 * Web-side security: Spring's OAuth2 Login wires up the Authorization Code +
 * PKCE flow against Kenni based on {@code application.yml}. The protected-API
 * filter chain is in {@link ApiResourceServerConfig}; this one handles
 * everything else.
 */
@Configuration
public class KenniSecurityConfig {

    @Bean
    @Order(2)
    public SecurityFilterChain webSecurityFilterChain(HttpSecurity http,
            ClientRegistrationRepository clientRegistrations) throws Exception {
        return http
                .authorizeHttpRequests(auth -> auth
                        // Public pages + the unauthenticated client-credentials demo endpoint.
                        .requestMatchers("/", "/error", "/login/**", "/oauth2/**",
                                "/api/client-credentials")
                        .permitAll()
                        // Everything else (incl. /api/me) requires an authenticated user.
                        .anyRequest().authenticated())
                .oauth2Login(oauth2 -> oauth2.authorizationEndpoint(authz ->
                        authz.authorizationRequestResolver(
                                pkceAwareAuthorizationRequestResolver(clientRegistrations))))
                // CSRF: keep enabled, but expose the token in a cookie so JS fetches
                // can read it. Forms get the token auto-injected by Thymeleaf.
                .csrf(csrf -> csrf
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                        // /api/client-credentials is called via fetch()‚ exempt it for the demo.
                        .ignoringRequestMatchers("/api/client-credentials"))
                .build();
    }

    /**
     * Spring Security 6 auto-enables PKCE only for *public* clients
     * ({@code client-authentication-method: none}). For confidential clients
     * (which is what we are — Kenni issues a client_secret), PKCE has to be
     * wired in explicitly. Kenni requires PKCE, so without this the token
     * exchange silently fails and Spring redirects to {@code /login?error}
     * with the unhelpful "Invalid credentials" message.
     */
    private static OAuth2AuthorizationRequestResolver pkceAwareAuthorizationRequestResolver(
            ClientRegistrationRepository repo) {
        var resolver = new DefaultOAuth2AuthorizationRequestResolver(repo, "/oauth2/authorization");
        resolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());
        return resolver;
    }
}
