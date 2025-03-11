package com.kibuti.oauth2server.controller;

import java.security.Principal;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.kibuti.oauth2server.entity.RegisteredClientEntity;
import com.kibuti.oauth2server.payload.ClientRegistrationRequest;
import com.kibuti.oauth2server.service.ClientRegistrationService;

@Controller
@RequestMapping("/developer")
@RequiredArgsConstructor
public class DeveloperPortalController {

    private final ClientRegistrationService clientService;

    @GetMapping("/dashboard")
    public String developerDashboard(Principal principal, Model model) {
        List<RegisteredClientEntity> clients = clientService.getClientsByUser(principal.getName());
        model.addAttribute("clients", clients);
        return "developer/dashboard";
    }

    @GetMapping("/applications/register")
    public String registerClientForm(Model model) {
        model.addAttribute("clientRequest", new ClientRegistrationRequest());
        return "register-client";
    }

    @PostMapping("/applications/register")
    public String registerClient(
            @Valid @ModelAttribute("clientRequest") ClientRegistrationRequest request,
            BindingResult result,
            Principal principal,
            RedirectAttributes redirectAttributes) {

        if (result.hasErrors()) {
            return "register-client";
        }

        // Get the plain text secret before it's encrypted
        String plainSecret = UUID.randomUUID().toString(); // Or however you generate secrets

        // Pass the plain secret to the service
        RegisteredClientEntity client = clientService.registerNewClient(request, principal.getName(), plainSecret);

        redirectAttributes.addFlashAttribute("success", "Application registered successfully!");
        redirectAttributes.addFlashAttribute("clientId", client.getClientId());
        redirectAttributes.addFlashAttribute("clientSecret", plainSecret); // Use the plain text version

        return "redirect:/developer/applications/" + client.getClientId();
    }

    @GetMapping("/applications/{clientId}")
    public String clientDetails(
            @PathVariable String clientId,
            Principal principal,
            Model model,
            @ModelAttribute("clientSecret") String clientSecret) {  // Get the flash attribute if it exists

        Optional<RegisteredClientEntity> client = clientService.getClientsByUser(principal.getName())
                .stream()
                .filter(c -> c.getClientId().equals(clientId))
                .findFirst();

        if (client.isEmpty()) {
            return "redirect:/developer/dashboard";
        }

        model.addAttribute("client", client.get());

        // Only put clientSecret in the model if it's not empty (i.e., right after registration)
        if (clientSecret != null && !clientSecret.isEmpty()) {
            model.addAttribute("clientSecret", clientSecret);
        }

        model.addAttribute("issuerUrl", "http://localhost:9000");

        return "client-details";
    }



    @PostMapping("/applications/{clientId}/regenerate-secret")
    public String regenerateClientSecret(
            @PathVariable String clientId,
            Principal principal,
            RedirectAttributes redirectAttributes) {

        String newPlainSecret = UUID.randomUUID().toString();
        boolean updated = clientService.regenerateClientSecret(clientId, principal.getName(), newPlainSecret);

        if (updated) {
            redirectAttributes.addFlashAttribute("success", "Client secret regenerated successfully");
            redirectAttributes.addFlashAttribute("clientSecret", newPlainSecret);
        } else {
            redirectAttributes.addFlashAttribute("error", "Failed to regenerate client secret");
        }

        return "redirect:/developer/applications/" + clientId;
    }

}