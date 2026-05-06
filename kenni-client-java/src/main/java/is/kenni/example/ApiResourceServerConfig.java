package is.kenni.example;

import java.util.List;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Resource-server configuration for {@code /api/protected-resource}.
 *
 * <p>Conditional on {@code app.kenni.api-scope}: when no API scope is
 * configured, this bean is skipped entirely and the protected-resource
 * controller returns 503 (because the web filter chain authenticates with the
 * OIDC user, not the bearer scope).
 */
@Configuration
@ConditionalOnProperty(name = "app.kenni.api-scope")
public class ApiResourceServerConfig {

    @Bean
    @Order(1)
    public SecurityFilterChain apiSecurityFilterChain(HttpSecurity http,
            KenniProperties kenni,
            JwtDecoder kenniApiJwtDecoder) throws Exception {
        return http
                .securityMatcher("/api/protected-resource")
                // CSRF doesn't apply to bearer-protected APIs.
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        // Spring's default JwtAuthenticationConverter maps the `scope` claim
                        // to authorities prefixed with "SCOPE_". Requiring that authority is
                        // enough to enforce the configured KENNI_API_SCOPE.
                        .anyRequest().hasAuthority("SCOPE_" + kenni.apiScope()))
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.decoder(kenniApiJwtDecoder)))
                .build();
    }

    /**
     * JWT decoder that validates Kenni access tokens. Spring's default
     * {@code JwtValidators.createDefaultWithIssuer} covers issuer + timestamp;
     * we add an audience validator on top so a token minted for a *different*
     * Kenni API in the same tenant doesn't sail through.
     */
    @Bean
    public JwtDecoder kenniApiJwtDecoder(KenniProperties kenni) {
        // Kenni's access tokens follow RFC 9068 (JWT Profile for OAuth 2.0
        // Access Tokens) and carry `"typ": "at+jwt"` in the JOSE header.
        // Spring Security's default JWT processor only accepts `"typ": "JWT"`
        // (or absent), so we have to broaden the type verifier — otherwise
        // every bearer call fails with `JOSE header typ (type) at+jwt not allowed`.
        var decoder = NimbusJwtDecoder.withIssuerLocation(kenni.issuer())
                .jwtProcessorCustomizer(processor -> processor.setJWSTypeVerifier(
                        new DefaultJOSEObjectTypeVerifier<>(
                                JOSEObjectType.JWT,
                                new JOSEObjectType("at+jwt"))))
                .build();

        var expectedAudience = kenni.resolvedApiAudience();
        OAuth2TokenValidator<Jwt> audienceValidator = new JwtClaimValidator<List<String>>(
                JwtClaimNames.AUD,
                aud -> aud != null && aud.contains(expectedAudience));

        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer(kenni.issuer()),
                audienceValidator));
        return decoder;
    }
}
