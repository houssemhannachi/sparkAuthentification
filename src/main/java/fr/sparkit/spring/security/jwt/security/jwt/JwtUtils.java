package fr.sparkit.spring.security.jwt.security.jwt;

import fr.sparkit.spring.security.jwt.exception.*;
import fr.sparkit.spring.security.jwt.security.services.*;
import io.jsonwebtoken.*;
import org.slf4j.*;
import org.springframework.beans.factory.annotation.*;
import org.springframework.stereotype.*;
import org.springframework.util.*;

import javax.servlet.http.*;
import java.time.*;
import java.util.*;
import java.util.stream.*;

@Component
public class JwtUtils {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${sparkit.app.jwtSecret}")
    private String jwtSecret;

    @Value("${sparkit.app.jwtExpirationMs}")
    private int jwtExpirationMs;


    public String generateTokenFromUser(UserDetailsImpl user) {
        Map<String, Object> claims = new HashMap<String, Object>();
        List<String> roles = user.getAuthorities().stream()
                .map(r -> r.getAuthority())
                .collect(Collectors.toList());
        claims.put("email", user.getEmail());

        claims.put("roles", roles);
        return Jwts.builder().setClaims(claims)
                .setHeaderParam("typ", "JWT")
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs)).signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
    }


    public String generateTokenFromUsername(String username) {
        return Jwts.builder().setSubject(username).setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs)).signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
    }

    public String getEmailFromJwtToken(String token) {
        return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().get("email", String.class);
    }

    public Long getIdFromJwtRefreshToken(String token) {
        return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().get("id", Long.class);
    }


    public Date getExpirationFromJwtToken(String token) {
        return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getExpiration();
    }


    public boolean validateJwtToken(String authToken) {
        if (this.validateSignature(authToken)) {
            return true;
        }
        return false;


    }

    public Boolean verifyExpiration(String token) {
        if (this.getExpirationFromJwtToken(token).compareTo(Date.from(Instant.now())) < 0) {
            throw new TokenRefreshException(token, "Refresh token was expired. Please make a new signin request");
        }
        return true;
    }


    private boolean validateSignature(String token) {
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token);

            return true;
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        }
        return false;
    }

    public String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader("Authorization");

        if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
            return headerAuth.substring(7, headerAuth.length());
        }


        return null;
    }

    public String parseJwtFromAuthorization(String Authorization) {

        if (StringUtils.hasText(Authorization) && Authorization.startsWith("Bearer ")) {
            return Authorization.substring(7, Authorization.length());
        }

        return null;
    }
}
