package com.portfolio.todolist.config

import com.portfolio.todolist.filtrer.JWTAuthorizationFilter
import com.portfolio.todolist.filtrer.JWTAuthenticationFilter
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.config.web.server.ServerHttpSecurity.http
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter

@EnableWebSecurity
class SecurityConfig(
    val userDetailService: UserDetailsService,
    val JWTAuthorizationFilter: JWTAuthorizationFilter
) {

//    @Bean
//    fun  filterChain( http : HttpSecurity) : SecurityFilterChain{
//        return http.cors().disable().build()
//    }

    @Bean
    @Throws(Exception::class)
    fun filterChain(http: HttpSecurity, authenticationManager: AuthenticationManager?): SecurityFilterChain {
        val jwtAuthenticationFilter = JWTAuthenticationFilter(authenticationManager)
        jwtAuthenticationFilter.setFilterProcessesUrl("/api/v1/auth/login")
        return http
            .csrf().disable()
            .cors().disable()
            .authorizeRequests()
            .antMatchers("/api/v1/users/**").authenticated()
            .antMatchers(HttpMethod.POST, "/api/v1/users").permitAll()
            .anyRequest().permitAll()
            .and()
            .httpBasic()
            .and()
            .sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            .addFilter(jwtAuthenticationFilter)
            .addFilterBefore(JWTAuthorizationFilter, UsernamePasswordAuthenticationFilter::class.java)
            .build()
    }

    @Bean
    @Throws(Exception::class)
    fun authenticationManager(http: HttpSecurity): AuthenticationManager {
        return http
            .getSharedObject(AuthenticationManagerBuilder::class.java)
            .userDetailsService(userDetailService)
            .passwordEncoder(passwordEncoder())
            .and().build()
    }

    @Bean
    fun passwordEncoder(): PasswordEncoder {
        return BCryptPasswordEncoder()
    }
}