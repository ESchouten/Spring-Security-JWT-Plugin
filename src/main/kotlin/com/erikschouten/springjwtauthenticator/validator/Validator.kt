package com.erikschouten.springjwtauthenticator.validator

open class Validator {
    @Throws(ValidationException::class)
    open fun validate(email: String) {}
}
