package fr.sparkit.spring.security.jwt.security.services;

import fr.sparkit.spring.security.jwt.exception.*;
import fr.sparkit.spring.security.jwt.models.*;
import fr.sparkit.spring.security.jwt.repository.*;
import fr.sparkit.spring.security.jwt.security.jwt.*;
import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.*;
import org.springframework.stereotype.*;
import org.springframework.transaction.annotation.*;

import java.util.*;

@Service
public class RefreshTokenService {
    @Value("${sparkit.app.jwtRefreshExpirationMs}")
    private Long refreshTokenDurationMs;
    @Value("${sparkit.app.jwtSecret}")
    private String jwtSecret;
    @Autowired
    private RefreshTokenRepository refreshTokenRepository;
    @Autowired
    JwtUtils jwtUtils;
    @Autowired
    private UserRepository userRepository;

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    public String createRefreshToken(Long id) {
        RefreshToken refreshToken = new RefreshToken();
        Map claims = new HashMap();
        claims.put("id", id);
        String refreshTokenString = Jwts.builder().setClaims(claims).setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + refreshTokenDurationMs)).signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
        refreshToken.setUser(userRepository.findById(id).get());
        refreshToken.setToken(refreshTokenString);
        refreshTokenRepository.save(refreshToken);
        return refreshTokenString;
    }


    @Transactional
    public int deleteByUserId(Long userId) {
        return refreshTokenRepository.deleteByUser(userRepository.findById(userId).get());
    }

    @Transactional
    public void deleteByToken(String refreshToken) {
        refreshTokenRepository.deleteRefreshTokenByToken(refreshToken);
    }

    public String verifyExpirationRefresh(RefreshToken refreshToken) {
        if (jwtUtils.verifyExpiration(refreshToken.getToken())) {
            refreshTokenRepository.delete(refreshToken);
            throw new TokenRefreshException(refreshToken.getToken(), "Refresh token was expired. Please make a new signin request");
        }

        return refreshToken.getToken();
    }
}
