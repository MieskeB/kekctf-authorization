package nl.michelbijnen.ctf.authorization.models;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.ElementCollection;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.OneToOne;
import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Entity
public class User {

    @Id
    private String id;
    private String username;
    @OneToOne
    private Team team;
    private String hash;
    private String salt;
    private String secretKey;
    @ElementCollection
    private List<String> roles;
}
