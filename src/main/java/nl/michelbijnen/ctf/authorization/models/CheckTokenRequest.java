package nl.michelbijnen.ctf.authorization.models;

import lombok.Data;

@Data
public class CheckTokenRequest {
    private String token;
}
