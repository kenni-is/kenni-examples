package is.kenni.example;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;
import org.springframework.web.util.UriComponentsBuilder;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import jakarta.servlet.http.HttpServletRequest;

/**
 * /api/me — server-side proxy that pulls the user's stored Kenni access token
 *           from the OAuth2 authorized-client store and uses it to call our
 *           own /api/protected-resource. Done server-side so the access token
 *           never reaches the browser.
 *
 * /api/client-credentials — token-endpoint exchange with HTTP Basic auth
 *                           (RFC 6749 §2.3.1). Returns the decoded JWT claims
 *                           so the demo proves the grant worked.
 */
@RestController
@RequestMapping("/api")
public class ApiController {

    private final KenniProperties kenni;
    private final ClientRegistrationRepository clients;
    private final RestClient http = RestClient.create();

    public ApiController(KenniProperties kenni, ClientRegistrationRepository clients) {
        this.kenni = kenni;
        this.clients = clients;
    }

    @GetMapping("/me")
    public ResponseEntity<?> me(
            @RegisteredOAuth2AuthorizedClient("kenni") OAuth2AuthorizedClient client,
            HttpServletRequest request) {
        if (!kenni.apiEnabled()) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .body(Map.of("error", "KENNI_API_SCOPE is not configured on this app."));
        }
        if (client == null || client.getAccessToken() == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Not signed in."));
        }
        String accessToken = client.getAccessToken().getTokenValue();

        URI target = UriComponentsBuilder
                .fromUriString(request.getScheme() + "://" + request.getHeader("host") + "/api/protected-resource")
                .build().toUri();

        var response = http.get()
                .uri(target)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                .retrieve()
                .onStatus(s -> true, (req, resp) -> { /* don't throw on 4xx/5xx */ })
                .toEntity(byte[].class);

        byte[] body = response.getBody();

        // Spring Security's resource-server returns 401/403 with an empty body
        // and the actual reason in the WWW-Authenticate header. A JS client
        // that does `r.json()` on an empty body throws "Unexpected end of JSON
        // input" — synthesise a JSON error so failure modes stay surfacable.
        if (body == null || body.length == 0) {
            String wwwAuth = response.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE);
            return ResponseEntity.status(response.getStatusCode())
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(Map.of(
                            "error", "Upstream returned empty body.",
                            "upstream_status", response.getStatusCode().value(),
                            "www_authenticate", wwwAuth != null ? wwwAuth : ""));
        }

        // Pass the upstream body through verbatim (byte[] avoids Spring re-
        // serialising the JSON string and double-quoting it).
        MediaType contentType = response.getHeaders().getContentType();
        return ResponseEntity.status(response.getStatusCode())
                .contentType(contentType != null ? contentType : MediaType.APPLICATION_JSON)
                .body(body);
    }

    @PostMapping("/client-credentials")
    public ResponseEntity<?> clientCredentials() {
        if (!kenni.m2mEnabled()) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .body(Map.of("error",
                            "Set KENNI_M2M_CLIENT_ID, KENNI_M2M_CLIENT_SECRET, and KENNI_M2M_SCOPE."));
        }

        ClientRegistration registration = clients.findByRegistrationId("kenni");
        String tokenEndpoint = registration.getProviderDetails().getTokenUri();

        // RFC 6749 §2.3.1: form-urlencode each credential before joining and
        // base64-encoding for HTTP Basic. Important when a secret contains `:` or `%`.
        String basic = Base64.getEncoder().encodeToString(
                (uriEncode(kenni.m2mClientId()) + ":" + uriEncode(kenni.m2mClientSecret()))
                        .getBytes(StandardCharsets.UTF_8));

        String body = "grant_type=client_credentials&scope=" + uriEncode(kenni.m2mScope());

        var response = http.post()
                .uri(URI.create(tokenEndpoint))
                .header(HttpHeaders.AUTHORIZATION, "Basic " + basic)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .accept(MediaType.APPLICATION_JSON)
                .body(body)
                .retrieve()
                .onStatus(s -> true, (req, resp) -> { /* don't throw */ })
                .toEntity(Map.class);

        if (!response.getStatusCode().is2xxSuccessful()) {
            return ResponseEntity.status(response.getStatusCode()).body(Map.of(
                    "error", "Token endpoint rejected the request.",
                    "detail", response.getBody()));
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> tokenSet = response.getBody();
        Object accessToken = tokenSet != null ? tokenSet.get("access_token") : null;

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("token_type", tokenSet != null ? tokenSet.get("token_type") : null);
        out.put("expires_in", tokenSet != null ? tokenSet.get("expires_in") : null);
        out.put("scope", tokenSet != null ? tokenSet.get("scope") : null);
        out.put("claims", decodeJwtClaims(accessToken instanceof String s ? s : null));
        return ResponseEntity.ok(out);
    }

    /** Decode without verification — the demo just wants to show what's inside. */
    private static Map<String, Object> decodeJwtClaims(String token) {
        if (token == null) return null;
        try {
            JWT jwt = JWTParser.parse(token);
            return jwt.getJWTClaimsSet().getClaims();
        } catch (Exception e) {
            return null; // opaque token
        }
    }

    private static String uriEncode(String s) {
        return java.net.URLEncoder.encode(s, StandardCharsets.UTF_8);
    }
}
