package is.kenni.example.controllers;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/authed")
public class AuthedController {

  @GetMapping("/user")
  public String index(Model model, @AuthenticationPrincipal OidcUser oidcUser,
      @RegisteredOAuth2AuthorizedClient("kenni-client") OAuth2AuthorizedClient authorizedClient) {
    model.addAttribute("idToken", oidcUser.getIdToken().getTokenValue());
    model.addAttribute("accessToken", authorizedClient.getAccessToken().getTokenValue());

    return "user";
  }

}
