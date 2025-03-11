package com.kibuti.oauth2server.controller;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import com.kibuti.oauth2server.entity.RegisteredClientEntity;
import com.kibuti.oauth2server.entity.User;
import com.kibuti.oauth2server.repository.RegisteredClientEntityRepository;
import com.kibuti.oauth2server.repository.UserRepository;
import com.kibuti.oauth2server.service.ClientRegistrationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;



import lombok.RequiredArgsConstructor;

@Controller
@RequestMapping("/admin")
@RequiredArgsConstructor
public class AdminController {

    private final ClientRegistrationService clientService;
    private final RegisteredClientEntityRepository clientRepository;
    private final UserRepository userRepository;

    @GetMapping("/dashboard")
    public String adminDashboard(Model model) {
        long totalClients = clientRepository.count();
        long pendingClients = clientRepository.countByApprovedFalse();
        long totalUsers = userRepository.count();

        model.addAttribute("totalClients", totalClients);
        model.addAttribute("pendingClients", pendingClients);
        model.addAttribute("totalUsers", totalUsers);

        // Get latest clients pending approval
        List<RegisteredClientEntity> pendingApprovalClients = clientRepository.findTop10ByApprovedFalseOrderByClientIdIssuedAtDesc();
        model.addAttribute("pendingApprovalClients", pendingApprovalClients);

        return "admin/dashboard";
    }

    @GetMapping("/applications")
    public String listApplications(Model model) {
        List<RegisteredClientEntity> clients = clientRepository.findAll();
        model.addAttribute("clients", clients);
        return "admin/applications";
    }

    @GetMapping("/applications/{clientId}")
    public String clientDetails(@PathVariable String clientId, Model model) {
        Optional<RegisteredClientEntity> client = clientRepository.findByClientId(clientId);

        if (client.isEmpty()) {
            return "redirect:/admin/applications";
        }

        model.addAttribute("client", client.get());
        return "admin/client-details";
    }

    @PostMapping("/applications/{clientId}/approve")
    public String approveClient(@PathVariable String clientId, RedirectAttributes redirectAttributes) {
        Optional<RegisteredClientEntity> optionalClient = clientRepository.findByClientId(clientId);

        if (optionalClient.isPresent()) {
            RegisteredClientEntity client = optionalClient.get();
            client.setApproved(true);
            clientRepository.save(client);

            redirectAttributes.addFlashAttribute("success", "Application '" + client.getClientName() + "' has been approved.");
        } else {
            redirectAttributes.addFlashAttribute("error", "Application not found.");
        }

        return "redirect:/admin/applications";
    }

    @PostMapping("/applications/{clientId}/reject")
    public String rejectClient(@PathVariable String clientId, RedirectAttributes redirectAttributes) {
        Optional<RegisteredClientEntity> optionalClient = clientRepository.findByClientId(clientId);

        if (optionalClient.isPresent()) {
            clientRepository.delete(optionalClient.get());
            redirectAttributes.addFlashAttribute("success", "Application has been rejected and removed.");
        } else {
            redirectAttributes.addFlashAttribute("error", "Application not found.");
        }

        return "redirect:/admin/applications";
    }

    @GetMapping("/users")
    public String listUsers(Model model) {
        List<User> users = userRepository.findAll();
        model.addAttribute("users", users);
        return "admin/users";
    }

    @GetMapping("/users/{userId}")
    public String userDetails(@PathVariable UUID userId, Model model) {
        Optional<User> user = userRepository.findById(userId);

        if (user.isEmpty()) {
            return "redirect:/admin/users";
        }

        List<RegisteredClientEntity> userClients = clientRepository.findByOwnerId(userId);

        model.addAttribute("user", user.get());
        model.addAttribute("userClients", userClients);

        return "admin/user-details";
    }

    @PostMapping("/users/{userId}/toggle-status")
    public String toggleUserStatus(@PathVariable UUID userId, RedirectAttributes redirectAttributes) {
        Optional<User> optionalUser = userRepository.findById(userId);

        if (optionalUser.isPresent()) {
            User user = optionalUser.get();
            user.setEnabled(!user.isEnabled());
            userRepository.save(user);

            String status = user.isEnabled() ? "enabled" : "disabled";
            redirectAttributes.addFlashAttribute("success", "User '" + user.getUsername() + "' has been " + status + ".");
        } else {
            redirectAttributes.addFlashAttribute("error", "User not found.");
        }

        return "redirect:/admin/users";
    }

    @PostMapping("/users/{userId}/make-admin")
    public String makeUserAdmin(@PathVariable UUID userId, RedirectAttributes redirectAttributes) {
        Optional<User> optionalUser = userRepository.findById(userId);

        if (optionalUser.isPresent()) {
            User user = optionalUser.get();
            user.getRoles().add("ADMIN");
            userRepository.save(user);

            redirectAttributes.addFlashAttribute("success", "User '" + user.getUsername() + "' has been granted admin rights.");
        } else {
            redirectAttributes.addFlashAttribute("error", "User not found.");
        }

        return "redirect:/admin/users/" + userId;
    }

    @PostMapping("/users/{userId}/remove-admin")
    public String removeUserAdmin(@PathVariable UUID userId, RedirectAttributes redirectAttributes) {
        Optional<User> optionalUser = userRepository.findById(userId);

        if (optionalUser.isPresent()) {
            User user = optionalUser.get();
            user.getRoles().remove("ADMIN");
            userRepository.save(user);

            redirectAttributes.addFlashAttribute("success", "Admin rights have been revoked from user '" + user.getUsername() + "'.");
        } else {
            redirectAttributes.addFlashAttribute("error", "User not found.");
        }

        return "redirect:/admin/users/" + userId;
    }
}