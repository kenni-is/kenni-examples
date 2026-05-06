package is.kenni.example;

import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Bearer-protected resource. The {@link ApiResourceServerConfig} filter chain
 * has already verified signature, issuer, audience, expiry, and the configured
 * {@code KENNI_API_SCOPE} authority before this method runs.
 */
@RestController
public class ProtectedResourceController {

    private final KenniProperties kenni;

    public ProtectedResourceController(KenniProperties kenni) {
        this.kenni = kenni;
    }

    @GetMapping("/api/protected-resource")
    public ResponseEntity<?> get(@AuthenticationPrincipal Jwt jwt) {
        if (!kenni.apiEnabled()) {
            return ResponseEntity.status(503).body(Map.of(
                    "error", "KENNI_API_SCOPE is not configured on this app."));
        }

        String scopeClaim = jwt.getClaimAsString("scope");
        List<String> scopes = scopeClaim == null ? List.of() : Arrays.stream(scopeClaim.split(" "))
                .filter(s -> !s.isBlank()).toList();

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("message", "Halló!");
        body.put("served_by", "Java / Spring Boot example");
        body.put("sub", jwt.getSubject());
        body.put("national_id", jwt.getClaimAsString("national_id"));
        body.put("scopes", scopes);
        Instant exp = jwt.getExpiresAt();
        body.put("expires_at", exp != null ? exp.toString() : null);
        return ResponseEntity.ok(body);
    }
}
