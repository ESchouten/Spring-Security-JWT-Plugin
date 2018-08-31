package com.erikschouten.springjwtauthenticator

import io.jsonwebtoken.ExpiredJwtException
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.SignatureException
import org.slf4j.LoggerFactory
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource
import org.springframework.security.web.context.HttpRequestResponseHolder
import org.springframework.security.web.context.SaveContextOnUpdateOrErrorResponseWrapper
import org.springframework.security.web.context.SecurityContextRepository
import org.springframework.web.util.WebUtils
import java.security.SecureRandom
import java.util.*
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

private const val AUTHORIZATION_HEADER = "Authorization"
private const val HEADER_BEGIN = "Bearer "

class JWTSecurityContextRepository(private val userDetailsService: UserDetailsService,
                                   private val tokenTtlMs: Int = 30 * 60 * 1000,
                                   private val secret: ByteArray = ByteArray(256).apply { SecureRandom().nextBytes(this) })
    : SecurityContextRepository {

    private val logger = LoggerFactory.getLogger(JWTSecurityContextRepository::class.java)

    override fun loadContext(requestResponseHolder: HttpRequestResponseHolder): SecurityContext {
        val context = SecurityContextHolder.createEmptyContext()

        try {
            val jwt = requestResponseHolder.request.getHeader(AUTHORIZATION_HEADER)
            if (jwt != null) {
                validateTokenAndExtractEmail(jwt).let { email ->
                    val userDetails = this.userDetailsService.loadUserByUsername(email)
                    val authentication =
                            UsernamePasswordAuthenticationToken(userDetails, null, userDetails.authorities)
                    authentication.details =
                            WebAuthenticationDetailsSource().buildDetails(requestResponseHolder.request)
                    context.authentication = authentication
                }
            }
        } catch (ex: SignatureException) {
            logger.debug("Old/invalid signature detected")
        } catch (ex: ExpiredJwtException) {
            logger.debug("Token is expired")
        } catch (ex: UsernameNotFoundException) {
            logger.debug("Username not found")
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

    override fun containsContext(request: HttpServletRequest): Boolean = request.getHeader(AUTHORIZATION_HEADER) != null

    private inner class SaveContextAsJWTOnUpdateOrErrorResponseWrapper(private val response: HttpServletResponse) :
            SaveContextOnUpdateOrErrorResponseWrapper(response, true) {

        public override fun saveContext(context: SecurityContext) {
            if (!isContextSaved) {
                val authentication = context.authentication as? UsernamePasswordAuthenticationToken
                authentication?.name?.let { email ->
                    val token = "Bearer " + createJWTForEmail(email)
                    response.setHeader(AUTHORIZATION_HEADER, token)
                }
            }
        }
    }

    private fun createJWTForEmail(email: String): String {
        val jwts = Jwts.builder()
                .setSubject(email)
                .signWith(SignatureAlgorithm.HS512, secret.copyOf())

        if (tokenTtlMs != -1) {
            val expiryDate = Date(System.currentTimeMillis().plus(tokenTtlMs))
            jwts.setExpiration(expiryDate)
        }

        return jwts.compact()
    }

    private fun validateTokenAndExtractEmail(header: String): String {
        val token = if (header.startsWith(HEADER_BEGIN)) header.substring(7) else header

        return Jwts.parser().setSigningKey(secret.copyOf()).parseClaimsJws(token).body.subject
    }

}
