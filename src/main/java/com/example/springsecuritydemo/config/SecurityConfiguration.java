package com.example.springsecuritydemo.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.authentication.BindAuthenticator;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.ldap.authentication.LdapAuthenticator;
import org.springframework.security.ldap.authentication.PasswordComparisonAuthenticator;
import org.springframework.security.ldap.authentication.ad.ActiveDirectoryLdapAuthenticationProvider;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.security.ldap.search.LdapUserSearch;
import org.springframework.security.ldap.userdetails.DefaultLdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;

import java.util.Arrays;
@EnableWebSecurity
@Configuration
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.authorizeRequests()
                .antMatchers("/secure/man/**").permitAll()
                .antMatchers("/secure/dev/**").permitAll()
                .and().formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/appLogin")
                .usernameParameter("username")
                .passwordParameter("password")
                .defaultSuccessUrl("/secure/dev")
                .and().logout()
                .logoutUrl("/appLogout")
                .logoutSuccessUrl("/login")
                .and().exceptionHandling()
                .accessDeniedPage("/accessDenied");
    }

//===============================================================================
//    //user: pwd => 123
//    //uid=ldapuser1,ou=People,dc=envieol,dc=com
//    //group:
//    //cn=ldapgroup1,ou=Group,dc=envieol,dc=com
//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
////        auth.ldapAuthentication()
////                .userDnPatterns("uid={0},ou=People")
////                .userSearchBase("ou=People")
////                .userSearchFilter("uid={0}")
////                .groupSearchBase("ou=Group")
////                .groupSearchFilter("memberUid={0}")
////                .contextSource()
////                .url("ldap://envieol.com:389/dc=envieol,dc=com")
////                .and()
////                .passwordCompare()
////                .passwordEncoder(passwordEncoder())
////                .passwordAttribute("userPassword");
//    }

    @Bean
     BaseLdapPathContextSource contextSource(){
            BaseLdapPathContextSource baseLdapPathContextSource = new DefaultSpringSecurityContextSource(Arrays.asList("ldap://envieol.com:389/"),"dc=envieol,dc=com");
            return baseLdapPathContextSource;
        }

    @Bean
    LdapAuthenticator authenticator(BaseLdapPathContextSource contextSource) {
        PasswordComparisonAuthenticator authenticator =
                new PasswordComparisonAuthenticator(contextSource);
        authenticator.setUserDnPatterns(new String[]{"uid={0},ou=People"});
        authenticator.setUserSearch( new FilterBasedLdapUserSearch("ou=People","uid={0}",contextSource) );
        authenticator.setPasswordAttributeName("userPassword");
        authenticator.setPasswordEncoder(passwordEncoder());
        return authenticator;
    }

    @Bean
    LdapAuthoritiesPopulator authoritiesPopulator(BaseLdapPathContextSource contextSource) {

        DefaultLdapAuthoritiesPopulator authoritiesPopulator = new DefaultLdapAuthoritiesPopulator(
                contextSource, "ou=Group");
        authoritiesPopulator.setGroupRoleAttribute("cn");
        authoritiesPopulator.setGroupSearchFilter("memberUid={1}");
        authoritiesPopulator.setRolePrefix("");

        return authoritiesPopulator;
    }

    @Bean
    LdapAuthenticationProvider authenticationProvider(LdapAuthenticator authenticator,LdapAuthoritiesPopulator authoritiesPopulator) {
        return new LdapAuthenticationProvider(authenticator,authoritiesPopulator);
    }

    @Bean
    AuthenticationManager authenticationManager(LdapAuthenticationProvider authenticationProvider){
        return new ProviderManager(Arrays.asList(authenticationProvider));
    }

    public PasswordEncoder passwordEncoder() {
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        return passwordEncoder;
    }

}
