package is.kenni.example;

import java.io.IOException;
import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.util.UriComponentsBuilder;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Sign-out endpoints. Two flavours:
 *
 * <ul>
 *   <li>{@code /auth/logout} — local sign-out: invalidate the session and
 *       redirect home. Kenni's session cookie is untouched, so the next sign-in
 *       is silent.
 *   <li>{@code /auth/rp-logout} — RP-initiated logout: invalidate the local
 *       session, then redirect through Kenni's {@code end_session_endpoint}
 *       with {@code id_token_hint}, {@code post_logout_redirect_uri}, and
 *       {@code client_id}. Order matters — if the Kenni redirect fails, the
 *       local session is still cleared.
 * </ul>
 */
@Controller
@RequestMapping("/auth")
public class AuthController {

    private final ClientRegistrationRepository clients;
    private final KenniProperties kenni;

    public AuthController(ClientRegistrationRepository clients, KenniProperties kenni) {
        this.clients = clients;
        this.kenni = kenni;
    }

    @PostMapping("/logout")
    public void logout(HttpServletRequest request, HttpServletResponse response) throws IOException {
        request.getSession(false);
        invalidateSession(request);
        response.sendRedirect("/");
    }

    @PostMapping("/rp-logout")
    public void rpLogout(@AuthenticationPrincipal OidcUser principal,
            HttpServletRequest request, HttpServletResponse response) throws IOException {
        ClientRegistration registration = clients.findByRegistrationId("kenni");
        Object endSession = registration.getProviderDetails().getConfigurationMetadata().get("end_session_endpoint");
        if (endSession == null) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "issuer does not advertise end_session_endpoint");
            return;
        }

        String idTokenHint = principal != null ? principal.getIdToken().getTokenValue() : null;
        invalidateSession(request);

        Map<String, String> params = new LinkedHashMap<>();
        params.put("client_id", kenni.clientId());
        params.put("post_logout_redirect_uri", baseUrl(request) + "/");
        if (idTokenHint != null) params.put("id_token_hint", idTokenHint);

        URI logoutUrl = UriComponentsBuilder.fromUriString(endSession.toString())
                .queryParams(toMultiValue(params))
                .build()
                .toUri();

        response.sendRedirect(logoutUrl.toString());
    }

    private static void invalidateSession(HttpServletRequest request) {
        var session = request.getSession(false);
        if (session != null) session.invalidate();
    }

    private static String baseUrl(HttpServletRequest request) {
        return request.getScheme() + "://" + request.getHeader("host");
    }

    private static org.springframework.util.MultiValueMap<String, String> toMultiValue(Map<String, String> in) {
        var out = new org.springframework.util.LinkedMultiValueMap<String, String>();
        in.forEach(out::add);
        return out;
    }
}
