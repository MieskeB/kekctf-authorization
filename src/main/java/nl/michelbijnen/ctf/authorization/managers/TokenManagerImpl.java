package nl.michelbijnen.ctf.authorization.managers;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import nl.michelbijnen.ctf.authorization.errors.InvalidTokenException;
import nl.michelbijnen.ctf.authorization.models.CheckTokenResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.UUID;

@Component("TokenManager")
public class TokenManagerImpl implements TokenManager {
    private Logger logger = LoggerFactory.getLogger(this.getClass());

    private RSAKey key;

    public TokenManagerImpl() throws Exception {
        if (Boolean.parseBoolean(System.getenv("FIXED_RSA_KEY"))) {
            this.key = new RSAKey.Builder(new Base64URL("qo7AaaGyzYuVGJGcll1me-z8M7NuGbipADEyjoWiaCcu-dxy0rNDl_wX2HN_jZRMUhdRz8pVLwbpbLz4_OziH1LRBFPRUeeRwu3CpUkFHnD6L1XJGdlsT2zDx0B95v-2XDlpUPbw8JyIMgAWkyx7Z5Pj-uuRm4o6qsZhcaELbNuBwOWAAzewmgflKEeGHLMbLRMesUZRpgNh5SPXTTITQChNFrbDvQE7JG97G78v7upvjkJoj1SJcnx58hiEjzj0npAktuUNAMSqtK88XBd28DKU99lV8FlBEk6wi-RJ4qlhcJ_gztxxPHDTFVtSrrTp9qEq19LRxkyzhsj6z8JDzQ"), new Base64URL("AQAB"))
                    .firstPrimeFactor(new Base64URL("4Po_QqgVW-u9otnlJF5KCPDRVEltBFZSHhtjWU-x49Ngnkscce0B2y_Dabv470x7iYT0a-MR0lOwmVwQ01KA4kpKr6jJvcor9gBgod4pw5BEOhfd-kAViZ8GwVdfPvk-sf1-lstUdCJrct0M_yOGFyH_DtUwziS4KUCoyt4JmQ8"))
                    .secondPrimeFactor(new Base64URL("whN4gLfhu8YB2V3SZ_8QCGafNSUNJ8AvI36r41w-mdckwlaza7TfMBtq2rX_1TMKlGHiNTpVXkC9YcsYH7YZ-rbFLuYjh-NC8gzU8h13IFjm2aEVDNwEFPytGDAlz9mH57KgtuVH7vw7C2mS0isbMKnI8vSiOuDK35D-eus0vWM"))
                    .firstCRTCoefficient(new Base64URL("OOjKhZQfZJOGypnWnaGWORpC3mnG1Vq3Wdu0wYMvcvQjjphU5h84xx16TZutuEiyyjORevBpM_i8skS-ApHpQ3vDa_Jeg0N35Q8J4wqKIRnNBk1paU-uwXG8GlLOftCujIKg5yA0WslnJgO78HlGl6cEPVaw_FIIkv6oUJWI-9A"))
                    .firstFactorCRTExponent(new Base64URL("OxGZQHAPQ5YusS5SmmzjNVu9KkspA2WCpAL-37kr9KxQBt-jtUnMHfd5cC55WqMTIHU3E4iH6lgs2ucwR7u2uTNWTq6bYWhOiIVq2bUR9BXRxAr2LjlbLkoBpQvCpy8bxfHPpdn275MF8R-WxPpXv4UeiY9yA_3iGHqwlqsbjAM"))
                    .secondFactorCRTExponent(new Base64URL("KasyiThxz_YgeYIKZee-kn8uGaP94hYCSPWuhB9PFYq6yrsAxNRNwy9vzsuaxTSzRc6KWfFPWPA_eRq48D4R7-GEDqC86jUiL4QPyHgJFrnfvsQ2F8-5VKQ3qeTUiX7kDhwtI3ew7R_csYOWUWeN6_HYQknB9zBCfqPL76pGZY8"))
                    .build();
        } else {
            this.key = new RSAKeyGenerator(2048).keyID(UUID.randomUUID().toString()).generate();
        }
    }

    @Override
    public String issueToken(String userId, String role) {
        try {
            Date expirationDate = Date.from(Instant.now().plus(1, ChronoUnit.DAYS));

            JWSSigner signer = new RSASSASigner(key);

            JWTClaimsSet.Builder csBuilder = new JWTClaimsSet.Builder();
            csBuilder.subject(userId);
            csBuilder.expirationTime(expirationDate);
            csBuilder.claim("role", role);
            csBuilder.getClaims().forEach((key, value) -> this.logger.debug(key + " " + value));
            JWTClaimsSet cs = csBuilder.build();

            SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(), cs);
            signedJWT.sign(signer);
            String token = signedJWT.serialize();
            return token;
        } catch (Exception ex) {
            return null;
        }
    }

    @Override
    public Mono<CheckTokenResponse> parse(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            RSAPublicKey publicKey = key.toRSAPublicKey();
            JWSVerifier verifier = new RSASSAVerifier(publicKey);
            boolean success = signedJWT.verify(verifier);
            if (success) {
                Date expirationDate = signedJWT.getJWTClaimsSet().getExpirationTime();
                if (expirationDate.before(Date.from(Instant.now()))) {
                    return Mono.error(InvalidTokenException::new);
                }
                JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
                String userId = claimsSet.getSubject();
                String role = claimsSet.getClaim("role").toString();

//                Object authorities = signedJWT.getJWTClaimsSet().getClaim("authorities");
//                if (!(authorities instanceof List)) {
//                    return Mono.error(InvalidTokenException::new);
//                }
//                List<String> roles = (List<String>) authorities;

                return Mono.just(new CheckTokenResponse(userId, role));
            } else {
                return Mono.error(InvalidTokenException::new);
            }
        } catch (Exception ex) {
            return Mono.error(InvalidTokenException::new);
        }
    }
}
