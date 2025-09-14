// CWE-352: CSRF (VULN)
// Demo: Security config globally disables CSRF protection.
package demo.vuln;

import org.springframework.context.annotation.*;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class VulnCSRF001 {

    @Bean
    public SecurityFilterChain insecure(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable()) // ❌ disables CSRF
            .authorizeHttpRequests(auth -> auth.anyRequest().permitAll());
        return http.build();
    }
}
