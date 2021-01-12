package jwt;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.security.*;
import java.security.interfaces.*;
import com.nimbusds.jose.*;
import com.nimbusds.jwt.*;
import com.nimbusds.jose.crypto.*;

public class JWTDemo {

	 
	public KeyPair generateKeyPair() throws NoSuchAlgorithmException {
	 
		// Instantiate KeyPairGenerator with RSA algorithm.
		KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
	 
		// Set key size to 1024 bits.
		keyGenerator.initialize(1024);
	 
		// Generate and return public/private key pair.
		return keyGenerator.genKeyPair();
	 
	}
	public String buildEncryptedJWT(PublicKey publicKey) throws JOSEException {
	 
		// Create a claim set.
		JWTClaimsSet jwtClaims = new JWTClaimsSet();
		
		// Set the value of the issuer.
		jwtClaims.setIssuer("https://apress.com");
		
		// Set the subject value - JWT belongs to this subject.
		jwtClaims.setSubject("Matthew");
		
		// Set values for audience restriction.
		List<String> aud = new ArrayList<String>();
		aud.add("https://app1.example.com");
		aud.add("https://app2.example.com");
		jwtClaims.setAudience(aud);
		
		// Set expiration time to 10 minutes.
		jwtClaims.setExpirationTime(new Date(new Date().getTime() + 1000 * 60 * 10));
		Date currentTime = new Date();
		
		// Set the valid from time to current time.
		jwtClaims.setNotBeforeTime(currentTime);
		
		// Set issued time to current time.
		jwtClaims.setIssueTime(currentTime);
		
		// Set a generated UUID as the JWT identifier.
		jwtClaims.setJWTID(UUID.randomUUID().toString());
		
		// Create JWE header with RSA-OAEP and AES/GCM.
		JWEHeader jweHeader = new JWEHeader(JWEAlgorithm.RSA_OAEP,EncryptionMethod.A128GCM);
		
		// Create encrypter with the RSA public key.
		JWEEncrypter encrypter = new RSAEncrypter((RSAPublicKey) publicKey);
		
		// Create the encrypted JWT with the JWE header and the JWT payload.
		EncryptedJWT encryptedJWT = new EncryptedJWT(jweHeader, jwtClaims);
		
		// Encrypt JWT.
		encryptedJWT.encrypt(encrypter);
		
		// Serialize into base64-encoded text.
		String jwtInText = encryptedJWT.serialize();
		
		// Print the value of the JWT.
		System.out.println("JSON Web Token in text:\n" + jwtInText);
		
		return jwtInText;
		
	}
	
	public void decryptJWT() throws NoSuchAlgorithmException, JOSEException, ParseException {
		// Generate private/public key pair.
		KeyPair keyPair = generateKeyPair();
		
		// Get the public key - used to encrypt the message.
		PublicKey publicKey = keyPair.getPublic();
				
		// Get the private key - used to decrypt the message.
		PrivateKey privateKey = keyPair.getPrivate();
				
		// Get encrypted JWT in base64-encoded text.
		String jwtInText = buildEncryptedJWT(publicKey);
		
		// Create a decrypter.
		JWEDecrypter decrypter = new RSADecrypter((RSAPrivateKey) privateKey);
		
		// Create the encrypted JWT with the base64-encoded text.
		EncryptedJWT encryptedJWT = EncryptedJWT.parse(jwtInText);
		
		// Decrypt JWT.
		encryptedJWT.decrypt(decrypter);
		
		// Print the value of JOSE header.
		System.out.println("\nJWE Header:\n" + encryptedJWT.getHeader());
		
		// JWE content encryption key.
		System.out.println("\nJWE Content Encryption Key:\n" + encryptedJWT.getEncryptedKey());
		
		// Initialization vector.
		System.out.println("\nInitialization Vector:\n" + encryptedJWT.getInitializationVector());
		
		// Ciphertext.
		System.out.println("\nCiphertext:\n" + encryptedJWT.getCipherText());
		
		// Authentication tag.
		System.out.println("\nAuthentication Tag:\n" + encryptedJWT.getAuthenticationTag());
		
		// Print the value of JWT body
		System.out.println("\nDecrypted Payload:\n" + encryptedJWT.getPayload());

	}
	
	public static void main(String[] args) throws Exception {
		JWTDemo jwt = new JWTDemo();
		jwt.decryptJWT();
	}
}
