package nl.michelbijnen.ctf.authorization.models;

import lombok.Data;

@Data
public class LoginRequest {
    private String username;
    private String password;
    private String code;
}
