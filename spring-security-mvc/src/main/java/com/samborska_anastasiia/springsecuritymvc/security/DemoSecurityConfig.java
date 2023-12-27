package com.samborska_anastasiia.springsecuritymvc.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

@Configuration
public class DemoSecurityConfig {

    /*

    @Bean
    public InMemoryUserDetailsManager userDetailsManager(){



        UserDetails john = User.builder()
                .username("john")
                .password("{noop}test123")
                .roles("EMPLOYEE")
                .build();

        UserDetails mary = User.builder()
                .username("mary")
                .password("{noop}test123")
                .roles("EMPLOYEE","MANAGER")
                .build();

        UserDetails susan = User.builder()
                .username("susan")
                .password("{noop}test123")
                .roles("EMPLOYEE","MANAGER","ADMIN")
                .build();

        return new InMemoryUserDetailsManager(john,mary,susan);
    }
    */

   

    @Bean
    public UserDetailsManager userDetailsManager(DataSource dataSource){
        JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
        jdbcUserDetailsManager.setUsersByUsernameQuery(
                "select user_id, pw, active from members where user_id=?");
        jdbcUserDetailsManager.setAuthoritiesByUsernameQuery(
                "select user_id, role from roles where user_id=?");
        return jdbcUserDetailsManager;
    }

    

    //configure security of web paths in application, login, logout
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        //restrict access based on the HTTP request
        http.authorizeHttpRequests(configurer ->
               configurer
                       .requestMatchers("/").hasRole("EMPLOYEE")
                       .requestMatchers("/leaders/**").hasRole("MANAGER")
                       .requestMatchers("/systems/**").hasRole("ADMIN")
                       .anyRequest().authenticated() // any request to the app must be authenticated(logged in)
                )
                // Customizing the form login process
                .formLogin(form ->
                        form
                                .loginPage("/showMyLoginPage") // show the custom form at the request mapping
                                .loginProcessingUrl("/authenticateTheUser") // login form should POST data to this URL for processing (check user id and password)
                                .permitAll() //allow everyone to see login page
                )
                .logout(logout -> logout.permitAll()

                )
                .exceptionHandling(configurer ->
                configurer.accessDeniedPage("/access-denied")

                );
        return http.build();
    }
}
