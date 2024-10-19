package com.example.demo.controller;

import com.example.demo.model.TokenResponseDTO;
import com.example.demo.service.RequestDispatcherService;
import com.example.demo.utils.JsonUtil;
import com.nimbusds.jose.shaded.gson.Gson;
import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.util.ContentCachingResponseWrapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

@RestController
public class CustomizeTokenController {

    private static final String CLIENT_ID = "oidc-client";
    private static final String CLIENT_SECRET = "secret";

    final RequestDispatcherService requestDispatcherService;

    public CustomizeTokenController(RequestDispatcherService requestDispatcher) {
        this.requestDispatcherService = requestDispatcher;
    }

    @PostMapping("/custom-token")
    public ResponseEntity<?> handleCustomToken(@RequestParam String clientId, @RequestParam String clientSecret
            ,  HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        CustomRequestWrapper requestWrapper = new CustomRequestWrapper(request);

        RequestDispatcher dispatcher = requestDispatcherService.getRequestDispatcher("/oauth2/token");

        // Set the grant_type parameter
        requestWrapper.setParameter("grant_type", "client_credentials");
        requestWrapper.removeParameter("clientId");
        requestWrapper.removeParameter("clientSecret");

        // Add scope parameter (adjust as needed)
//        requestWrapper.setParameter("scope", "openid");

        // Set the Authorization header with Basic auth
        String credentials = clientId + ":" + clientSecret;
        String encodedCredentials = Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
        requestWrapper.addHeader("Authorization", "Basic " + encodedCredentials);

        // Ensure correct Content-Type
        requestWrapper.addHeader("Content-Type", "application/x-www-form-urlencoded");

        ContentCachingResponseWrapper responseWrapper = new ContentCachingResponseWrapper(response);
//        RequestDispatcher dispatcher = request.getRequestDispatcher("/oauth2/token");


            dispatcher.forward(requestWrapper, responseWrapper);
            String responseBody = new String(responseWrapper.getContentAsByteArray(), StandardCharsets.UTF_8);
            int status = responseWrapper.getStatus();

        System.out.println(response);
        System.out.println(responseWrapper);
            HttpHeaders headers = new HttpHeaders();

            if (status ==200) {
                TokenResponseDTO tokenResponseDTO = JsonUtil.convertJsonToPojo(responseBody, TokenResponseDTO.class);
                return ResponseEntity.ok(tokenResponseDTO);
            } else {
                TokenResponseDTO tokenResponseDTO = new TokenResponseDTO();
                return new ResponseEntity<>(tokenResponseDTO, HttpStatus.UNAUTHORIZED);
            }

    }
}