#Spring JWT Authenticator
This library is a standalone implementation of JWT (Json Web Token) into Spring Security.

##Dependency
**Maven:**
```
<repositories>
    <repository>
    	<id>jitpack.io</id>
    	<url>https://jitpack.io</url>
	</repository>
</repositories>

<dependency>
    <groupId>com.github.ESchouten</groupId>
    <artifactId>SpringJWTAuthenticator</artifactId>
    <version>0.1.5</version>
</dependency>
```
**Gradle:**
```
repositories {
	maven { url 'https://jitpack.io' }
}

dependencies {
	implementation 'com.github.ESchouten:SpringJWTAuthenticator:0.1.5'
}
```
##Implementation
To use this library, you have to implement it into your Spring Security configuration.

**Example:**
```
    /**
     * The [JWTSecurityContextRepository] is responsible for
     * storing and retrieving JWTs in and from HTTP headers.
     */
    @Bean
    public JWTSecurityContextRepository jwtSecurityContextRepository() {
        return new JWTSecurityContextRepository(appUserUtil);
    }

    /**
     * The [APIAuthenticationFilter] is responsible for validating
     * username and password combinations when provided through the API.
     * (It is essentially the API version of a login form.)
     */
    @Bean
    public APIAuthenticationFilter apiAuthenticationFilter() throws Exception {
        APIAuthenticationFilter aaf = new APIAuthenticationFilter();
        aaf.setAuthenticationManager(super.authenticationManager());
        return aaf;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .securityContext().securityContextRepository(jwtSecurityContextRepository())
                .and()
                .csrf()
                .disable()
                .authorizeRequests()

                .mvcMatchers("/user/**").hasRole("USERS")
                
                **Etc**
```
##Built with
* Spring Security - https://spring.io/
* JJWT - https://www.jsonwebtoken.io/