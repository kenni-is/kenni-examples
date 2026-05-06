package is.kenni.example;

import org.springframework.boot.context.properties.ConfigurationProperties;

/** Typed view over the {@code app.kenni.*} env-var-driven config. */
@ConfigurationProperties(prefix = "app.kenni")
public record KenniProperties(
        String issuer,
        String clientId,
        String clientSecret,
        String apiScope,
        String apiAudience,
        String m2mClientId,
        String m2mClientSecret,
        String m2mScope) {

    public boolean apiEnabled() {
        return apiScope != null && !apiScope.isBlank();
    }

    public boolean m2mEnabled() {
        return notBlank(m2mClientId) && notBlank(m2mClientSecret) && notBlank(m2mScope);
    }

    /** Audience claim expected on incoming Kenni access tokens. Defaults to {@code <client-id>-api}. */
    public String resolvedApiAudience() {
        return notBlank(apiAudience) ? apiAudience : clientId + "-api";
    }

    private static boolean notBlank(String s) {
        return s != null && !s.isBlank();
    }
}
