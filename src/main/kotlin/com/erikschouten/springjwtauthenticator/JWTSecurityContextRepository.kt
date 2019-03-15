package com.erikschouten.springjwtauthenticator

import io.jsonwebtoken.ExpiredJwtException
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.security.Keys
import io.jsonwebtoken.security.SignatureException
import org.slf4j.LoggerFactory
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource
import org.springframework.security.web.context.HttpRequestResponseHolder
import org.springframework.security.web.context.SaveContextOnUpdateOrErrorResponseWrapper
import org.springframework.security.web.context.SecurityContextRepository
import org.springframework.web.util.WebUtils
import java.util.*
import javax.crypto.SecretKey
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

private const val AUTHORIZATION_HEADER = "Authorization"
private const val HEADER_START = "Bearer "

class JWTSecurityContextRepository(
        private val userDetailsService: UserDetailsService,
        private val tokenTtlMs: Int = 30 * 60 * 1000,
        private val key: SecretKey = Keys.secretKeyFor(SignatureAlgorithm.HS512))
    : SecurityContextRepository {

    private val logger = LoggerFactory.getLogger(JWTSecurityContextRepository::class.java)

    override fun loadContext(requestResponseHolder: HttpRequestResponseHolder): SecurityContext {
        val context = SecurityContextHolder.createEmptyContext()

        try {
            requestResponseHolder.request.getHeader(AUTHORIZATION_HEADER)?.let { token ->
                validateTokenAndExtractEmail(token).let { email ->
                    val userDetails = this.userDetailsService.loadUserByUsername(email)
                    val authentication =
                            UsernamePasswordAuthenticationToken(userDetails, null, userDetails.authorities)
                    authentication.details =
                            WebAuthenticationDetailsSource().buildDetails(requestResponseHolder.request)
                    context.authentication = authentication
                }
            }
        } catch (ex: SignatureException) {
            logger.info("Old/invalid signature detected")
        } catch (ex: ExpiredJwtException) {
            logger.info("Token is expired")
        } catch (ex: UsernameNotFoundException) {
            logger.info("Username not found")
        } finally {
            requestResponseHolder.response =
                    SaveContextAsJWTOnUpdateOrErrorResponseWrapper(requestResponseHolder.response)

            return context
        }
    }

    override fun saveContext(context: SecurityContext, request: HttpServletRequest, response: HttpServletResponse) {
        val responseWrapper =
                WebUtils.getNativeResponse(response, SaveContextAsJWTOnUpdateOrErrorResponseWrapper::class.java)
                        ?: throw IllegalStateException("Cannot invoke saveContext on response $response. " +
                                "You must use the HttpRequestResponseHolder.response after invoking loadContext")

        responseWrapper.saveContext(context)
    }

    override fun containsContext(request: HttpServletRequest) = request.getHeader(AUTHORIZATION_HEADER) != null

    private inner class SaveContextAsJWTOnUpdateOrErrorResponseWrapper(private val response: HttpServletResponse) :
            SaveContextOnUpdateOrErrorResponseWrapper(response, true) {

        public override fun saveContext(context: SecurityContext) {
            if (!isContextSaved) {
                context.authentication.let {
                    val token = HEADER_START + createJWT(it)
                    response.setHeader(AUTHORIZATION_HEADER, token)
                }
            }
        }
    }

    private fun createJWT(auth: Authentication): String {
        val jwts = Jwts.builder()
                .setSubject(auth.name)
                .claim("roles", auth.authorities)
                .signWith(key)

        if (tokenTtlMs != -1) {
            val expiryDate = Date(System.currentTimeMillis().plus(tokenTtlMs))
            jwts.setExpiration(expiryDate)
        }

        return jwts.compact()
    }

    fun validateTokenAndExtractEmail(header: String): String {
        val token = if (header.startsWith(HEADER_START)) header.removePrefix(HEADER_START) else header
        return Jwts.parser()
                .setSigningKey(key)
                .parseClaimsJws(token)
                .body.subject
    }
}
