package org.bfsi.auth.controller;

import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.bfsi.auth.model.JWTResponse;
import org.bfsi.auth.config.SecurityConstants;
import org.bfsi.auth.entity.UserAccount;
import org.bfsi.auth.serviceImpl.UserAccountServiceImpl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@AllArgsConstructor
@RequestMapping("/api/v1/auth")
public class AuthController {

    private UserAccountServiceImpl userService;

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody UserAccount user) {

        ResponseEntity response = null;

        if (userService.saveUser(user)) {
            response = ResponseEntity.status(HttpStatus.CREATED)
                    .body("User registered successfully");
        }

        return response;
    }

    @GetMapping("/token")
    public ResponseEntity<String> token(HttpServletResponse servletResponse) {

        ResponseEntity response = null;

        // Once this API hits, it will go to JWTGeneratorFilter and generate JWT and
        // set in 'response' object... so below code will get called after filer ends,
        // and it further responds with values set by filter.
        if (servletResponse.containsHeader(SecurityConstants.JWT_HEADER)) {

            String token = servletResponse.getHeader(SecurityConstants.JWT_HEADER);

            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            response = ResponseEntity.status(HttpStatus.OK)
                    .body(new JWTResponse(authentication.getName(), token));
        }

        return response;
    }

    @GetMapping("/welcome")
    public String welcome() {
        return "Welcome to Banking application";
    }

    @GetMapping("/validate")
    public ResponseEntity<String> validate() {

        ResponseEntity response = null;

        // Once this API is hit by user, it will be filtered by JWT ValidatorFilter as token is passed
        // and config is done in filter for this endpoint to filter...
        // After token is validated in Filter and auth token is set in Security ContextHolder, it means
        // that token is validated and proper response will be sent back

        Authentication authentication = SecurityContextHolder.getContext()
                .getAuthentication();

        if (null != authentication.getName()) {
            response = ResponseEntity.status(HttpStatus.OK)
                    .body("Validation successful");
        }

        return response;
    }
}
