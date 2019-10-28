package com.erikschouten.springjwtauthenticator.validator

import org.springframework.security.core.userdetails.UserDetails
import org.springframework.stereotype.Service

@Service
class Validator {
    @Throws(ValidationException::class)
    fun validate(userDetails: UserDetails) {}
}
