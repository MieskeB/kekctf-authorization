package nl.michelbijnen.ctf.authorization.models;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.Entity;
import javax.persistence.Id;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Entity
public class Challenge {
    @Id
    private String id;
    private String title;
    private String description;
    private String fileURL;
    private String flag;
    private int points;
}
