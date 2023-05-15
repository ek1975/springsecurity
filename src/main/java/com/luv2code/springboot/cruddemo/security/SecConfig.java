package com.luv2code.springboot.cruddemo.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

@Configuration
public class SecConfig {

    @Bean
    public UserDetailsManager udm(DataSource ds) {
        JdbcUserDetailsManager jdbcUdm = new JdbcUserDetailsManager(ds);
        jdbcUdm.setUsersByUsernameQuery("select user_id, pw, active from members where user_id=?");
        jdbcUdm.setAuthoritiesByUsernameQuery("select user_id, role from roles where user_id=?");
        return jdbcUdm;
    }

/*  Commenting out the method below as it is the method for using default security tables (users and authorities)
    @Bean
    public UserDetailsManager udm(DataSource ds) {
        return new JdbcUserDetailsManager(ds);
    }
*/
/*  Commenting the method below because they pertain only to in memory authentication & authorization.
    @Bean
    public InMemoryUserDetailsManager udm() {
        UserDetails a = User.builder().username("e").password("{noop}e").roles("EMPLOYEE").build();
        UserDetails b = User.builder().username("m").password("{noop}m").roles("EMPLOYEE", "MANAGER").build();
        UserDetails c = User.builder().username("a").password("{noop}a").roles("EMPLOYEE", "MANAGER", "ADMIN").build();
        return new InMemoryUserDetailsManager(a, b, c);
    }
*/
    @Bean
    public SecurityFilterChain roles(HttpSecurity hs) throws Exception {
        hs.authorizeHttpRequests(configurer -> configurer
                .requestMatchers(HttpMethod.GET, "/api/employees").hasRole("EMPLOYEE")
                .requestMatchers(HttpMethod.GET, "/api/employees/**").hasRole("EMPLOYEE")
                .requestMatchers(HttpMethod.POST, "/api/employees").hasRole("MANAGER")
                .requestMatchers(HttpMethod.PUT, "/api/employees").hasRole("MANAGER")
                .requestMatchers(HttpMethod.DELETE, "/api/employees/**").hasRole("ADMIN"));

        hs.httpBasic();
        hs.csrf().disable(); //disable to stateless REST APIs
        return hs.build();
    }

}
