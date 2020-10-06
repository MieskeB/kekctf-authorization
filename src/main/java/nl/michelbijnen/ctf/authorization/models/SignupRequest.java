package nl.michelbijnen.ctf.authorization.models;

import lombok.Data;

@Data
public class SignupRequest {
    private String username;
    private String password;
    private String team;
}
