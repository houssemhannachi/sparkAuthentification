package fr.sparkit.spring.security.jwt.security.services;

import fr.sparkit.spring.security.jwt.exception.*;
import fr.sparkit.spring.security.jwt.models.User;
import fr.sparkit.spring.security.jwt.models.*;
import fr.sparkit.spring.security.jwt.payload.request.*;
import fr.sparkit.spring.security.jwt.payload.response.*;
import fr.sparkit.spring.security.jwt.repository.*;
import fr.sparkit.spring.security.jwt.security.jwt.*;
import org.springframework.beans.factory.annotation.*;
import org.springframework.http.*;
import org.springframework.security.authentication.*;
import org.springframework.security.core.*;
import org.springframework.security.core.context.*;
import org.springframework.security.core.userdetails.*;
import org.springframework.security.crypto.password.*;
import org.springframework.stereotype.*;

import java.util.*;

@Service
public class AuthService implements IAuthService {
    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    RefreshTokenService refreshTokenService;

    @Autowired
    UserRepository userRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    RoleRepository roleRepository;

    @Override
    public ResponseEntity<?> jwtSignin(LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        String jwt = jwtUtils.generateTokenFromUser(userDetails);

        String refreshToken = refreshTokenService.createRefreshToken(userDetails.getId());

        return ResponseEntity.ok(new JwtResponse(jwt, refreshToken));
    }

    @Override
    public ResponseEntity<?> register(SignupRequest signupRequest) {
        if (userRepository.existsByUsername(signupRequest.getUsername())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Username is already taken!"));
        }

        if (userRepository.existsByEmail(signupRequest.getEmail())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is already in use!"));
        }

        // Create new user's account
        fr.sparkit.spring.security.jwt.models.User user = new fr.sparkit.spring.security.jwt.models.User(signupRequest.getUsername(), signupRequest.getEmail(), encoder.encode(signupRequest.getPassword()));

        Set<String> strRoles = signupRequest.getRole();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER).orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN).orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(adminRole);

                        break;
                    case "mod":
                        Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR).orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(modRole);

                        break;
                    default:
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER).orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(userRole);
                }
            });
        }
        user.setRoles(roles);
        userRepository.save(user);
        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }

    @Override
    public ResponseEntity<?> refreshToken(TokenRefreshRequest tokenRefreshRequest) {
        String requestRefreshToken = tokenRefreshRequest.getRefreshToken();

        if (jwtUtils.validateJwtToken(requestRefreshToken)) {
            Long id = jwtUtils.getIdFromJwtRefreshToken(requestRefreshToken);
            Optional<User> user = userRepository.findById(id);
            if (user.isPresent()) {
                String token = jwtUtils.generateTokenFromUser(UserDetailsImpl.build(user.get()));
                refreshTokenService.deleteByToken(requestRefreshToken);
                String refreshToken = refreshTokenService.createRefreshToken(id);
                return ResponseEntity.ok(new TokenRefreshResponse(token, refreshToken));
            } else {
                throw new UsernameNotFoundException("USer not Found");
            }
        }
        throw new TokenRefreshException(requestRefreshToken, "Refresh token is not in database!");


    }

    @Override
    public ResponseEntity<?> logout(String authorization) {
        try {
            String jwt = jwtUtils.parseJwtFromAuthorization(authorization);
            refreshTokenService.deleteByToken(jwt);
            return ResponseEntity.ok(new MessageResponse("Log out successful!"));
        } catch (Exception e) {
            return ResponseEntity.ok("here");
        }

    }
}
