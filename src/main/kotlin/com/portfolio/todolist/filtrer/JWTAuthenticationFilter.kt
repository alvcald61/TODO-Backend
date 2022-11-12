package com.portfolio.todolist.filtrer

import com.fasterxml.jackson.databind.ObjectMapper
import com.google.gson.Gson
import com.portfolio.todolist.service.dto.LoginDto
import com.portfolio.todolist.util.JWTUtil
import org.modelmapper.ModelMapper
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.userdetails.User
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.stereotype.Component
import java.util.Collections
import javax.servlet.FilterChain
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

//defines login endpoint. This replaces the method login in the controller
@Component
class JWTAuthenticationFilter(authenticationManager: AuthenticationManager?) :
    UsernamePasswordAuthenticationFilter(authenticationManager) {

    override fun attemptAuthentication(request: HttpServletRequest?, response: HttpServletResponse?): Authentication {
        val user: LoginDto
        try {
            user =  ObjectMapper().readValue(request?.inputStream, LoginDto::class.java)
            println(user)
        } catch (e: Exception) {
            TODO(e.message.toString())
        }
        val usernamePassword = UsernamePasswordAuthenticationToken(user.username, user.password, Collections.emptyList())
        return authenticationManager.authenticate(usernamePassword)
    }

    override fun successfulAuthentication(
        request: HttpServletRequest?,
        response: HttpServletResponse?,
        chain: FilterChain?,
        authResult: Authentication?
    ) {
        val principal = authResult?.principal as User
        val token = JWTUtil.createToken(principal.username)
        response?.addHeader("Authorization", "Bearer $token")
        addJwtToResponse(response, token, principal)
        response?.writer?.flush()
        super.successfulAuthentication(request, response, chain, authResult)
    }

    private fun addJwtToResponse(response: HttpServletResponse?, token: String?, principal: User) {
        response?.contentType = "application/json"
        response?.characterEncoding = "UTF-8"
        response?.writer?.println(Gson().toJson(LoginDto(principal.username, token)))
    }
}