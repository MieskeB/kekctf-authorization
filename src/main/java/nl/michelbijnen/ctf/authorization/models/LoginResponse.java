package nl.michelbijnen.ctf.authorization.models;

import lombok.Data;

@Data
public class LoginResponse {
    private boolean success;
    private String userId;
    private String token;
    private String role;
}
