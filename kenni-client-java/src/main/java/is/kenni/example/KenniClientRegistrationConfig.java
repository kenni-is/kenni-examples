package is.kenni.example;

import java.util.LinkedHashSet;
import java.util.Set;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ClientRegistrations;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

/**
 * Builds the Kenni {@link ClientRegistration} programmatically so we can
 * conditionally append {@code KENNI_API_SCOPE} to the requested scopes.
 *
 * <p>Spring's {@code application.yml} can't express a conditional list entry —
 * if {@code KENNI_API_SCOPE} is unset and we hardcoded the list in YAML, Kenni
 * would issue access tokens without that scope and {@code /api/protected-resource}
 * would 401 every request even after a successful sign-in. Doing this in code
 * also lets us drop the {@code spring.security.oauth2.client.*} block entirely.
 *
 * <p>Defining a {@link ClientRegistrationRepository} bean here suppresses
 * Spring Boot's auto-configured one (it's {@code @ConditionalOnMissingBean}).
 */
@Configuration
public class KenniClientRegistrationConfig {

    static final String REGISTRATION_ID = "kenni";

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository(KenniProperties kenni) {
        String issuer = required(kenni.issuer(), "app.kenni.issuer", "KENNI_ISSUER");
        String clientId = required(kenni.clientId(), "app.kenni.client-id", "KENNI_CLIENT_ID");
        String clientSecret = required(kenni.clientSecret(), "app.kenni.client-secret", "KENNI_CLIENT_SECRET");

        Set<String> scopes = new LinkedHashSet<>();
        scopes.add("openid");
        scopes.add("profile");
        scopes.add("national_id");
        scopes.add("offline_access");
        if (kenni.apiEnabled()) {
            scopes.add(kenni.apiScope());
        }

        // fromIssuerLocation does the OIDC discovery fetch and pre-populates
        // endpoints + JWKS URI on the registration.
        ClientRegistration kenniRegistration = ClientRegistrations
                .fromIssuerLocation(issuer)
                .registrationId(REGISTRATION_ID)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .scope(scopes)
                .build();

        return new InMemoryClientRegistrationRepository(kenniRegistration);
    }

    private static String required(String value, String propertyName, String envVarName) {
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(String.format(
                    "Required Kenni configuration is missing: %s (env var: %s).%n" +
                    "Either set the env var, or copy `application-local.yml.example` " +
                    "to `application-local.yml` and fill in your Kenni values. See README.md.",
                    propertyName, envVarName));
        }
        return value;
    }
}
