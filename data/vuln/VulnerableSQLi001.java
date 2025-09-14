package sample.vuln;

import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.*;
import jakarta.persistence.*;
import java.util.List;

@RestController
public class VulnerableSQLi001 {

    @PersistenceContext
    private EntityManager em;

    // VULN: builds JPQL dynamically by concatenation
    // Example: /owners?lastName=' OR '1'='1
    @GetMapping("/owners")
    public List<?> owners(@RequestParam String lastName) {
        String jpql = "SELECT o FROM Owner o WHERE o.lastName = '" + lastName + "'";
        return em.createQuery(jpql).getResultList();
    }
}
