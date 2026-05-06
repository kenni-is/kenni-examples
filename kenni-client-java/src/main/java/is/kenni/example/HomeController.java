package is.kenni.example;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {

    private final KenniProperties kenni;

    public HomeController(KenniProperties kenni) {
        this.kenni = kenni;
    }

    @GetMapping("/")
    public String index(Model model, @AuthenticationPrincipal OidcUser principal) {
        boolean signedIn = principal != null;
        String name = "";
        String nationalId = null;
        if (signedIn) {
            String n = principal.getFullName();
            if (n == null || n.isBlank()) {
                String given = principal.getGivenName();
                String family = principal.getFamilyName();
                n = ((given != null ? given : "") + " " + (family != null ? family : "")).trim();
            }
            if (n.isBlank()) {
                n = principal.getSubject();
            }
            name = n;
            Object nid = principal.getClaim("national_id");
            if (nid != null) nationalId = nid.toString();
        }

        model.addAttribute("signedIn", signedIn);
        model.addAttribute("name", name);
        model.addAttribute("nationalId", nationalId);
        model.addAttribute("apiEnabled", kenni.apiEnabled());
        model.addAttribute("m2mEnabled", kenni.m2mEnabled());
        return "index";
    }
}
