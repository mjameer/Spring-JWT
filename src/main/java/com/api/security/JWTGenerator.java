package com.api.security;

import java.util.Date;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
//import java.security.KeyPair;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.SignatureAlgorithm;

import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

@Component
public class JWTGenerator {
	private static final Key key = Keys.secretKeyFor(SignatureAlgorithm.HS512);
	private static final long JWT_EXPIRATION = 70000;

	public String generateToken(Authentication authentication) {
		String username = authentication.getName();
		Date currentDate = new Date();
		Date expireDate = new Date(currentDate.getTime() + JWT_EXPIRATION);
		
		String token = Jwts.builder()
				.setSubject(username)
				.setIssuedAt( new Date())
				.setExpiration(expireDate)
				.signWith(key,SignatureAlgorithm.HS512)
				.compact();
		System.out.println(token);
		return token;
	}


	public Claims getClaim(String token){
		return Jwts.parserBuilder()
				.setSigningKey(key)
				.build()
				.parseClaimsJws(token)
				.getBody();
	}


	public String getUsernameFromJWT(String token){
		return getClaim(token).getSubject();
	}


	public Date getExpiryDate(String token){
		return getClaim(token).getExpiration();
	}


	public boolean isTokenExpired(String token){
		Date expiryDate = getExpiryDate(token);
		return expiryDate.before(new Date(System.currentTimeMillis()));
	}
	
	public boolean validateToken(String token) {
		try {
			if(!isTokenExpired(token)) {
				Jwts.parserBuilder()
						.setSigningKey(key)
						.build()
						.parseClaimsJws(token);
				return true;
			} else
				throw new AuthenticationCredentialsNotFoundException("JWT was expired");
		} catch (Exception ex) {
			throw new AuthenticationCredentialsNotFoundException("JWT is incorrect",ex.fillInStackTrace());
		}
	}

}
