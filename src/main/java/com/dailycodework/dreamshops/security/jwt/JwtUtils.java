package com.dailycodework.dreamshops.security.jwt;

import com.dailycodework.dreamshops.security.user.ShopUserDetails;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;
import java.util.List;

@Component
public class JwtUtils {

    @Value("${auth.token.jwtSecret}")
    private String jwtSecret;

    @Value("${auth.token.expirationInMils}")
    private int expirationTime;

    /**
     * Genera una clave secreta segura de 256 bits (32 bytes).
     *
     * @return SecretKey para firma HMAC
     */
    public SecretKey generateSecretKey() {
        return Keys.secretKeyFor(SignatureAlgorithm.HS256);
    }

    /**
     * Genera un JWT para un usuario autenticado.
     *
     * @param authentication El objeto de autenticación que contiene la información del usuario
     * @return El token JWT generado
     */
    public String generateTokenForUser(Authentication authentication) {
        ShopUserDetails userPrincipal = (ShopUserDetails) authentication.getPrincipal();
        List<String> roles = extractRoles(userPrincipal);

        return Jwts.builder()
                .setSubject(userPrincipal.getEmail())
                .claim("id", userPrincipal.getId())
                .claim("roles", roles)
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + expirationTime))
                .signWith(key(), SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * Extrae los roles del usuario.
     *
     * @param userPrincipal El objeto de detalles del usuario
     * @return Lista de roles del usuario
     */
    private List<String> extractRoles(ShopUserDetails userPrincipal) {
        return userPrincipal.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
    }

    /**
     * Obtiene la clave secreta a partir de la configuración.
     *
     * @return La clave secreta para firmar/verificar el JWT
     */
    private Key key() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }

    /**
     * Extrae el nombre de usuario (correo electrónico) del token.
     *
     * @param token El JWT desde el que extraer el nombre de usuario
     * @return El nombre de usuario extraído del token
     */
    public String getUsernameFromToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key())
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    /**
     * Valida la validez del JWT.
     *
     * @param token El JWT que se va a validar
     * @return true si el token es válido, false de lo contrario
     */
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(key())
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (ExpiredJwtException e) {
            throw new JwtException("El token ha expirado", e);
        } catch (UnsupportedJwtException e) {
            throw new JwtException("El token no es soportado", e);
        } catch (MalformedJwtException e) {
            throw new JwtException("El token está mal formado", e);
        } catch (SignatureException e) {
            throw new JwtException("La firma del token no es válida", e);
        } catch (IllegalArgumentException e) {
            throw new JwtException("El token no es válido", e);
        }
    }
}
