package com.portfolio.todolist.filtrer

import com.portfolio.todolist.util.JWTUtil
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter
import javax.servlet.FilterChain
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@Component
class JWTAuthorizationFilter : OncePerRequestFilter() {
    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        val bearerToken = request.getHeader("Authorization")
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            val usernamePAT = JWTUtil.getAuthentication(bearerToken)
            SecurityContextHolder.getContext().authentication = usernamePAT
        }
        filterChain.doFilter(request, response) 
    }
}