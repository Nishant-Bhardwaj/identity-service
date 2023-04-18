package org.bfsi.auth.model;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class JWTResponse {
    String username;
    String token;
}
