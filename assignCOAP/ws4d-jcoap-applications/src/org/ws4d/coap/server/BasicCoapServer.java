package org.ws4d.coap.server;

import java.io.FileInputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.ws4d.coap.connection.BasicCoapChannelManager;
import org.ws4d.coap.interfaces.CoapChannelManager;
import org.ws4d.coap.interfaces.CoapMessage;
import org.ws4d.coap.interfaces.CoapRequest;
import org.ws4d.coap.interfaces.CoapServer;
import org.ws4d.coap.interfaces.CoapServerChannel;
import org.ws4d.coap.messages.CoapMediaType;
import org.ws4d.coap.messages.CoapResponseCode;

public class BasicCoapServer implements CoapServer {
    private static final int PORT = 5683;
    static int counter = 0;
    byte[] AESkey = null; // suppose only 1 client - if more, create a hashmap with the objectid and instance
    public static void main(String[] args) {
        System.out.println("Start CoAP Server on port " + PORT);
        BasicCoapServer server = new BasicCoapServer();
        CoapChannelManager channelManager = BasicCoapChannelManager.getInstance();
        channelManager.createServerListener(server, PORT);
    }

	@Override
	public CoapServer onAccept(CoapRequest request){
		System.out.println("Accept connection...");
		return this;
	}

	@Override
	public void onRequest(CoapServerChannel channel, CoapRequest request) {
		System.out.println("Received message: " + request.toString()+ " URI: " + request.getUriPath());
		// load client cert for signature verification
		PublicKey pkClient = null;
		try {
			FileInputStream fCertInClient = new FileInputStream("CoAPClientX509.cer");
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509Certificate client = (X509Certificate) cf.generateCertificate(fCertInClient);
			pkClient = client.getPublicKey();
			fCertInClient.close();
		} catch (Exception e) {
			e.printStackTrace();
		}

		if (request.getUriPath().equals("/generate")) {
			byte[] cipheredAESkey = null;
			try {
				// generate random AES key for encryption
				SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
				this.AESkey = new byte[16];
				secureRandom.nextBytes(this.AESkey);
				System.out.println("Generated session key is: " + getHex(this.AESkey));
				// init RSA cipher and encrypt AES key with clients public key
				Cipher RSAcipher = Cipher.getInstance("RSA");
				RSAcipher.init(Cipher.ENCRYPT_MODE, pkClient);
				cipheredAESkey = RSAcipher.doFinal(this.AESkey);
			} catch (Exception e) {
				e.printStackTrace();
			}
			
			CoapMessage response = channel.createResponse(request,
					CoapResponseCode.Content_205);
			response.setContentType(CoapMediaType.octet_stream);
			response.setPayload(cipheredAESkey);
			channel.sendMessage(response);
		}
		else {
			CoapMessage response = channel.createResponse(request,
					CoapResponseCode.Content_205);
			response.setContentType(CoapMediaType.text_plain);
			byte[] recvPayload = request.getPayload();
			// obtain signature and encrypted payload
			byte[] aux = new byte[4];
			for(int i = 0; i < 4; i++) {
				aux[i] = recvPayload[i];
			}
			ByteBuffer bb = ByteBuffer.wrap(aux);
			int sizeOfSign = bb.getInt();
			byte[] sign = new byte[sizeOfSign];
			for(int i = 0; i < sizeOfSign; i++) {
				sign[i] = recvPayload[i + 4];
			}
			byte[] encPayload = new byte[recvPayload.length - sign.length - 4];
			for(int i = 0; i < encPayload.length; i++) {
				encPayload[i] = recvPayload[i + sign.length + 4];
			}
			try {
				// verify signature
				Signature signature = Signature.getInstance("SHA512withRSA");
				signature.initVerify(pkClient);
				signature.update(encPayload);
				boolean isCorrect = signature.verify(sign);
				if(isCorrect) {
					// decrypt payload
					System.out.println("Signature verified successfully");
					Cipher AEScipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
					SecretKeySpec keySpec = new SecretKeySpec(this.AESkey, "AES");
					AEScipher.init(Cipher.DECRYPT_MODE, keySpec);
					byte[] decryptedPayload = AEScipher.doFinal(encPayload);
					String recvJson = new String(decryptedPayload, StandardCharsets.UTF_8);
					System.out.println("Received data:\n" + recvJson);
					response.setPayload("Success");
				}	
				else {
					// panic
					System.out.println("Signature mismatch...client aborting");
					response.setPayload("Signature mismatch");
				}
			} catch (Exception e) {
				e.printStackTrace();
			}	
			channel.sendMessage(response);
		}	
	}

	@Override
	public void onSeparateResponseFailed(CoapServerChannel channel) {
		System.out.println("Separate response transmission failed.");
		
	}
	
	public static String getHex(byte[] value) {
		String output = "";
		for(byte byteValue : value) {
			output += String.format("%02x", byteValue);
		}
		return output;
	}
}
