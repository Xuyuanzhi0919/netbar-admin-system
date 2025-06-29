package edu.ahut.util;

import edu.ahut.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

@Component
public class JwtUtil {
    
    // JWT密钥，从配置文件中获取，或使用默认值
    @Value("${jwt.secret:}")
    private String secret;
    
    // Token有效期（毫秒），默认24小时
    @Value("${jwt.expiration:86400000}")
    private long expiration;
    
    // 生成的安全密钥
    private SecretKey secretKey;
    
    // 使用ConcurrentHashMap存储无效的令牌
    private final Map<String, Date> invalidatedTokens = new ConcurrentHashMap<>();
    
    /**
     * 初始化JWT密钥
     * 如果配置的secret为空或长度不足，则生成一个安全的密钥
     */
    @PostConstruct
    public void initializeSecretKey() {
        if (secret == null || secret.trim().isEmpty() || secret.getBytes(StandardCharsets.UTF_8).length < 32) {
            // 如果密钥为空或不够安全，生成一个安全的HMAC-SHA256密钥
            secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);
            System.out.println("Generated secure JWT key as the configured secret was insufficient");
        } else {
            // 使用配置的密钥
            secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
            System.out.println("Using configured JWT secret");
        }
    }
    
    // 生成JWT令牌
    public String generateToken(User user) {
        Map<String, Object> claims = new HashMap<>();
        // 可以在claims中存储额外的用户信息
        claims.put("id", user.getId());
        claims.put("username", user.getUsername());
        
        return createToken(claims, user.getUsername());
    }
    
    // 从令牌中获取用户名
    public String getUsernameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }
    
    // 从令牌中获取用户ID
    public Long getUserIdFromToken(String token) {
        final Claims claims = getAllClaimsFromToken(token);
        return ((Number) claims.get("id")).longValue();
    }
    
    // 验证令牌是否有效
    public boolean validateToken(String token) {
        try {
            // 检查令牌是否在黑名单中
            if (isBlacklisted(token)) {
                return false;
            }
            return !isTokenExpired(token);
        } catch (Exception e) {
            return false;
        }
    }
    
    // 验证令牌是否属于指定用户
    public boolean validateToken(String token, User user) {
        // 检查令牌是否在黑名单中
        if (isBlacklisted(token)) {
            return false;
        }
        
        final String username = getUsernameFromToken(token);
        return (username.equals(user.getUsername()) && !isTokenExpired(token));
    }
    
    // 检查令牌是否过期
    private boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }
    
    // 从令牌中获取过期时间
    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }
    
    // 从令牌中获取指定的claim
    private <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }
    
    // 获取令牌中的所有claim
    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
    
    // 创建令牌
    private String createToken(Map<String, Object> claims, String subject) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(secretKey)
                .compact();
    }

    /**
     * 将令牌添加到黑名单
     * @param token JWT令牌
     */
    public void addToBlacklist(String token) {
        try {
            // 获取令牌的过期时间
            Date expiryDate = getExpirationDateFromToken(token);
            invalidatedTokens.put(token, expiryDate);
        } catch (Exception e) {
            // 如果令牌已经无效或格式错误，忽略异常
        }
    }

    /**
     * 检查令牌是否在黑名单中
     * @param token JWT令牌
     * @return 如果令牌在黑名单中返回true
     */
    public boolean isBlacklisted(String token) {
        return invalidatedTokens.containsKey(token);
    }

    /**
     * 定时清理过期的黑名单令牌
     * 每小时执行一次
     */
    @Scheduled(fixedRate = 3600000)
    public void cleanupExpiredTokens() {
        Date now = new Date();
        invalidatedTokens.entrySet().removeIf(entry -> entry.getValue().before(now));
    }
} 