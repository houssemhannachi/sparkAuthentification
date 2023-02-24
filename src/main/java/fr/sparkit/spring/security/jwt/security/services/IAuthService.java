package fr.sparkit.spring.security.jwt.security.services;

import fr.sparkit.spring.security.jwt.payload.request.*;
import org.springframework.http.*;

public interface IAuthService {
    ResponseEntity<?> jwtSignin(LoginRequest loginRequest);

    ResponseEntity<?> register(SignupRequest signupRequest);

    ResponseEntity<?> refreshToken(TokenRefreshRequest tokenRefreshRequest);

    ResponseEntity<?> logout(String authorziation);
}
