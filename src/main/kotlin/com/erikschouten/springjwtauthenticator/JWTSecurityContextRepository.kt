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
        private val key: SecretKey = Keys.secretKeyFor(SignatureAlgorithm.HS512),
        vararg val claimFunctions: (String) -> Pair<String, Any>)
    : SecurityContextRepository {

    private val logger = LoggerFactory.getLogger(JWTSecurityContextRepository::class.java)

    override fun loadContext(requestResponseHolder: HttpRequestResponseHolder): SecurityContext {
        val context = SecurityContextHolder.createEmptyContext()

        try {
            requestResponseHolder.request.getHeader(AUTHORIZATION_HEADER)?.let { token ->
                validateTokenAndExtractEmail(token).let { email ->
                    context.authentication = this.userDetailsService.loadUserByUsername(email).let { userDetails ->
                        UsernamePasswordAuthenticationToken(userDetails, null, userDetails.authorities).apply {
                            details = WebAuthenticationDetailsSource().buildDetails(requestResponseHolder.request)
                        }
                    }
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
                response.setHeader(
                        AUTHORIZATION_HEADER,
                        HEADER_START + createJWT(context.authentication)
                )
            }
        }
    }

    private fun createJWT(auth: Authentication): String {
        val jwtBuilder = Jwts.builder()
                .setSubject(auth.name)
                .claim("roles", auth.authorities.map { it.authority })
                .signWith(key).apply {
                    if (tokenTtlMs != -1) {
                        setExpiration(Date(System.currentTimeMillis().plus(tokenTtlMs)))
                    }
                }

        claimFunctions.forEach {
            val pair = it(auth.name)
            jwtBuilder.claim(pair.first, pair.second)
        }

        return jwtBuilder.compact()
    }

    fun validateTokenAndExtractEmail(header: String) =
            Jwts.parser()
                    .setSigningKey(key)
                    .parseClaimsJws(header.removePrefix(HEADER_START))
                    .body.subject!!
}
