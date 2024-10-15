package com.example.demo.controller;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.util.ContentCachingResponseWrapper;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

@RestController
public class CustomizeTokenController {

    private static final String CLIENT_ID = "oidc-client";
    private static final String CLIENT_SECRET = "secret";

    @PostMapping("/custom-token")
    public ResponseEntity<String> handleCustomToken(@RequestParam String clientId, @RequestParam String clientSecret
            ,  HttpServletRequest request, HttpServletResponse response)  {
        CustomRequestWrapper requestWrapper = new CustomRequestWrapper(request);

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
        RequestDispatcher dispatcher = request.getRequestDispatcher("/oauth2/token");

        try {
            dispatcher.forward(requestWrapper, responseWrapper);
            String responseBody = new String(responseWrapper.getContentAsByteArray(), StandardCharsets.UTF_8);
            int status = responseWrapper.getStatus();
            HttpHeaders headers = new HttpHeaders();
//            for (String headerName : responseWrapper.getHeaderNames()) {
//                headers.addAll(headerName, responseWrapper.getHeaders(headerName));
//            }
//            return ResponseEntity
//                    .status(status)
//                    .headers(headers)
//                    .body(responseBody);
        } catch (Exception e) {
            return ResponseEntity
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error occurred while processing the request: " + e.getMessage());
        } finally {
//            responseWrapper.copyBodyToResponse();
        }

        return  null;
    }
}