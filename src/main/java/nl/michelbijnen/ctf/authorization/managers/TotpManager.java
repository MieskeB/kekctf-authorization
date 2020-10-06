package nl.michelbijnen.ctf.authorization.managers;

public interface TotpManager {

    String generateSecret();

    boolean validateCode(String code, String secret);
}
