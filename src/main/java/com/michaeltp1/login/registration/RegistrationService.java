package com.michaeltp1.login.registration;

import com.michaeltp1.login.appuser.AppUser;
import com.michaeltp1.login.appuser.AppUserRole;
import com.michaeltp1.login.appuser.AppUserService;
import com.michaeltp1.login.email.EmailSender;
import com.michaeltp1.login.registration.token.ConfirmationToken;
import com.michaeltp1.login.registration.token.ConfirmationTokenService;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@AllArgsConstructor
public class RegistrationService {

    private final AppUserService appUserService;
    private final EmailValidator emailValidator;
    private final ConfirmationTokenService confirmationTokenService;
    private final EmailSender emailSender;

    public String register(RegistrationRequest request) {
        boolean isValidEmail= emailValidator.test(request.getEmail());
        if(!isValidEmail) {
            throw  new IllegalStateException("Invalid email");
        }
        String token= appUserService.signUpUser(new AppUser(
                request.getFirstName(),
                request.getLastName(),
                request.getEmail(),
                request.getPassword(),
                AppUserRole.USER

        ));
        String link="http://localhost:8080/api/v1/registration/confirm?token="+token;
        emailSender.sendEmail(request.getEmail(), String.format("%s %s %s", request.getFirstName(), request.getLastName(), link));
        return token;
    }

    @Transactional
    public String confirmToken(String token) {
        ConfirmationToken confirmationToken = confirmationTokenService
                .getToken(token)
                .orElseThrow(() ->
                        new IllegalStateException("token not found"));

        if (confirmationToken.getConfirmedAt() != null) {
            throw new IllegalStateException("email already confirmed");
        }

        LocalDateTime expiredAt = confirmationToken.getExpiresAt();

        if (expiredAt.isBefore(LocalDateTime.now())) {
            throw new IllegalStateException("token expired");
        }

        confirmationTokenService.setConfirmedAt(token);
        appUserService.enableAppUser(
                confirmationToken.getAppUser().getEmail());
        return "confirmed";
    }
}
