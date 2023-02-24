package fr.sparkit.spring.security.jwt.security.jwt;

import com.fasterxml.jackson.databind.*;
import org.slf4j.*;
import org.springframework.http.*;
import org.springframework.security.access.*;
import org.springframework.security.core.*;
import org.springframework.security.core.context.*;
import org.springframework.security.web.access.*;
import org.springframework.stereotype.*;

import javax.servlet.*;
import javax.servlet.http.*;
import java.io.*;
import java.util.*;

@Component
public class CustomAccessDeniedHandler implements AccessDeniedHandler {

    private static final Logger logger = LoggerFactory.getLogger(CustomAccessDeniedHandler.class);

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException exc) throws IOException, ServletException {
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);


        final Map<String, Object> body = new HashMap<>();

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null) {
            body.put("status", HttpServletResponse.SC_UNAUTHORIZED);
            body.put("error", "Access Denied");
            body.put("message", exc.getMessage());
            body.put("path", request.getServletPath());
            logger.error(" error: {}", exc.getMessage());
            logger.error("User: " + auth.getName()
                    + " attempted to access the protected URL: "
                    + request.getRequestURI());
        }




        final ObjectMapper mapper = new ObjectMapper();
        mapper.writeValue(response.getOutputStream(), body);
    }
}
