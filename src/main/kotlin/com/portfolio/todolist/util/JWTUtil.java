package com.portfolio.todolist.util;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.Date;
import java.util.Map;

@Component
public class JWTUtil {

	private final static String SECRET = "yN2ckBFklLIZszkObEuMaataKOEMf1iC";
	private final static String TOKEN_PREFIX = "Bearer ";
	private final static String HEADER_STRING = "Authorization";
	private static final Long EXPIRATION_TIME = 86400000L;

	public static String createToken(String username) {
		Date expirationDate = new Date(System.currentTimeMillis() + EXPIRATION_TIME);
		Map<String, Object> claims = Map.of("username", username);
		return Jwts.builder()
			.setClaims(claims)
			.setSubject(username)
			.setExpiration(expirationDate)
			.signWith(Keys.hmacShaKeyFor(SECRET.getBytes()))
			.compact();
	}

	public static UsernamePasswordAuthenticationToken getAuthentication(String token) {
		Claims claims = Jwts.parserBuilder()
			.setSigningKey(Keys.hmacShaKeyFor(SECRET.getBytes()))
			.build()
			.parseClaimsJws(token.replace(TOKEN_PREFIX, ""))
			.getBody();
		String username = claims.getSubject();
		return new UsernamePasswordAuthenticationToken(username, null, Collections.emptyList());
	}   
	
}
