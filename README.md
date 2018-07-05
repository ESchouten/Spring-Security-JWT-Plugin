Spring JWT Authenticator

Maven:
<repositories>
	<repository>
    	<id>jitpack.io</id>
    	<url>https://jitpack.io</url>
	</repository>
</repositories>

<dependency>
    <groupId>com.github.ESchouten</groupId>
    <artifactId>SpringJWTAuthenticator</artifactId>
    <version>0.1.2</version>
</dependency>

Gradle:
repositories {
	maven { url 'https://jitpack.io' }
}

dependencies {
	implementation 'com.github.ESchouten:SpringJWTAuthenticator:0.1.2'
}
