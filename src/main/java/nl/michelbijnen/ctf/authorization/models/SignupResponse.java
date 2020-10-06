package nl.michelbijnen.ctf.authorization.models;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class SignupResponse {
    private String userId;
    private String token;
    private String secretKey;
}
