package com.michaeltp1.login.email;

import lombok.AllArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;

@Service
@AllArgsConstructor
public class EmailService implements EmailSender{

    private final static Logger LOGGER= LoggerFactory.getLogger(EmailService.class);

    private final JavaMailSender mailSender;


    @Override
    @Async
    public void sendEmail(String to, String email) {
        try{
            MimeMessage message=mailSender.createMimeMessage();
            MimeMessageHelper helper=new MimeMessageHelper(message,"utf-8");
            helper.setText(email,true);
            helper.setSubject("Confirm your email");
            helper.setTo(to);
            helper.setFrom("michaeljtp1@gmail.com");
            mailSender.send(message);

        }catch (MessagingException e){
            LOGGER.error("Error sending email", e);
            throw  new IllegalStateException("Error sending email", e);
        }
    }
}
