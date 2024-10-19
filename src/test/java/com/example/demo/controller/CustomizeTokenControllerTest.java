package com.example.demo.controller;



import com.example.demo.model.TokenResponseDTO;
import com.example.demo.service.RequestDispatcherService;
import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class CustomizeTokenControllerTest {

    private CustomizeTokenController controller;

    @Mock
    private RequestDispatcherService mockRequestDispatcherService;

    @Mock
    private RequestDispatcher mockDispatcher;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        controller = new CustomizeTokenController(mockRequestDispatcherService);
        when(mockRequestDispatcherService.getRequestDispatcher("/oauth2/token")).thenReturn(mockDispatcher);
    }

    @Test
    void handleCustomToken_SuccessfulRequest() throws Exception {
        // Arrange
        String clientId = "oidc-client";
        String clientSecret = "secret";
        String successResponse = "{\"access_token\":\"test-token\",\"token_type\":\"Bearer\",\"expires_in\":3600}";

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("clientId", clientId);
        request.setParameter("clientSecret", clientSecret);

        MockHttpServletResponse response = new MockHttpServletResponse();

        doAnswer(invocation -> {
            HttpServletResponse resp = invocation.getArgument(1);
            resp.setStatus(HttpStatus.OK.value());
            resp.getWriter().write(successResponse);
            return null;
        }).when(mockDispatcher).forward(any(HttpServletRequest.class), any(HttpServletResponse.class));

        // Act
        ResponseEntity<?> result = controller.handleCustomToken(clientId, clientSecret, request, response);

        // Assert
        assertEquals(HttpStatus.OK, result.getStatusCode());
        assertTrue(result.getBody() instanceof TokenResponseDTO);
//        TokenResponseDTO tokenResponse = (TokenResponseDTO) result.getBody();
//        assertEquals("test-token", tokenResponse.getAccessToken());
//        assertEquals("Bearer", tokenResponse.getTokenType());
//        assertEquals(3600, tokenResponse.getExpiresIn());
//
//        // Verify that the request was properly modified
//        verify(mockDispatcher).forward(argThat(req ->
//                "client_credentials".equals(req.getParameter("grant_type")) &&
//                        req.getParameter("clientId") == null &&
//                        req.getParameter("clientSecret") == null &&
//                        req.getHeader("Authorization") != null &&
//                        req.getHeader("Content-Type").equals("application/x-www-form-urlencoded")
//        ), any(HttpServletResponse.class));
//    }

        // ... (UnauthorizedRequest test remains the same)

    }
}
