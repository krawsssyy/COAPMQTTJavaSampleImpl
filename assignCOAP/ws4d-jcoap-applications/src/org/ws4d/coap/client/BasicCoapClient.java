package org.ws4d.coap.client;

import java.io.File;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.ws4d.coap.Constants;
import org.ws4d.coap.connection.BasicCoapChannelManager;
import org.ws4d.coap.interfaces.CoapChannelManager;
import org.ws4d.coap.interfaces.CoapClient;
import org.ws4d.coap.interfaces.CoapClientChannel;
import org.ws4d.coap.interfaces.CoapRequest;
import org.ws4d.coap.interfaces.CoapResponse;
import org.ws4d.coap.messages.CoapRequestCode;

public class BasicCoapClient implements CoapClient {
    private static String SERVER_ADDRESS = "localhost";
    private static int PORT = Constants.COAP_DEFAULT_PORT;
    static int counter = 0;
    CoapChannelManager channelManager = null;
    CoapClientChannel clientChannel = null;
    byte[] AESkey = null;
    PrivateKey privKey = null;

    public static void main(String[] args) {
	if (args != null && args.length >= 1) {
		SERVER_ADDRESS = args[0];
		if (args.length >= 2)
			PORT = Integer.parseInt(args[1]);
	}
        System.out.println("Start CoAP Client: " + SERVER_ADDRESS);
        BasicCoapClient client = new BasicCoapClient();
        client.channelManager = BasicCoapChannelManager.getInstance();
        client.runTestClient();
    }
    
    public void runTestClient(){
    	try {
			clientChannel = channelManager.connect(this, InetAddress.getByName(SERVER_ADDRESS), PORT);
			// send generate request
			CoapRequest coapRequest = clientChannel.createRequest(true, CoapRequestCode.POST);
			coapRequest.setToken("gen".getBytes());
			coapRequest.setUriPath("/generate");
			clientChannel.sendMessage(coapRequest);
			System.out.println("Sent generate request\nSleeping for 10s awaiting for the key");
			Thread.sleep(10000); // awaiting for session key to be received
			// suppose we have a temperature sensor which sends its values => objectId = 3303, resourceId = 5700
			while(true) {
				// generate a float for the temp value and build the JSON according to IPSO
				SecureRandom r = new SecureRandom();
				float random = -40f + r.nextFloat() * 80f;
				CoapRequest coapRequestTemp = clientChannel.createRequest(true,  CoapRequestCode.POST);
				coapRequestTemp.setUriPath("3303/0/5700");
				coapRequestTemp.setToken("temp".getBytes());//set token to not have it somehow match the first letter of generation token "gen"
				String jsonIPSO = "{\n\t\"timestamp\": " + System.currentTimeMillis() + ",\n\t\"values\": [{\n\t\t\"objectId\": 3303,\n\t\t\"instanceId\": 0,\n\t\t\"resourceId\": 5700,\n\t\t\"datatype\": Float,\n\t\t\"value\": " + random + "\n\t]}\n}";
				System.out.println("Data to be sent:\n" + jsonIPSO);
				// init AES cipher for encryption of payload and encrypt it
				Cipher AEScipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
				SecretKeySpec keySpec = new SecretKeySpec(this.AESkey, "AES");
				AEScipher.init(Cipher.ENCRYPT_MODE, keySpec);
				byte[] encPayload = AEScipher.doFinal(jsonIPSO.getBytes());
				// prepare to sign and sign the encrypted payload
				Signature signature = Signature.getInstance("SHA512withRSA");
				signature.initSign(this.privKey);
				signature.update(encPayload);
				byte[] sign = signature.sign();
				// add signature length at first position in payload; then add signature; then the actual encrypted payload
				int sizeOfPayload = 4 + sign.length + encPayload.length;
				byte[] payload = new byte[sizeOfPayload];
				ByteBuffer aux = ByteBuffer.allocate(4);
				aux.putInt(sign.length);
				for(int i = 0; i < 4; i++) {
					payload[i] = aux.array()[i];
				}
				for(int i = 4; i < sign.length + 4; i++) {
					payload[i] = sign[i - 4];
				}
				// payload[5] = (byte) 0xf5; - uncomment to test sign mismatch
				for(int i = sign.length + 4; i < sizeOfPayload; i++) {
					payload[i] = encPayload[i - sign.length - 4];
				}
				coapRequestTemp.setPayload(payload);
				clientChannel.sendMessage(coapRequestTemp);
				System.out.println("Sent request\nSleeping for 5s before sending another");
				Thread.sleep(5000);
			}
			
		} catch (Exception e) {
			e.printStackTrace();
		}
    }

	@Override
	public void onConnectionFailed(CoapClientChannel channel, boolean notReachable, boolean resetByServer) {
		System.out.println("Connection Failed");
	}

	@Override
	public void onResponse(CoapClientChannel channel, CoapResponse response) {
		System.out.println("Received response:" + response.toString());
		if (response.getToken()[0] == "g".getBytes()[0]) {
			System.out.println("Received key");
			// read private key from file
			try {
				String key = new String(Files.readAllBytes(new File("/home/pi/workspaceJava/COAP/ws4d-jcoap-applications/key.pem").toPath()), Charset.defaultCharset());
				String privateKeyPEM = key
					      .replace("-----BEGIN PRIVATE KEY-----", "")
					      .replaceAll(System.lineSeparator(), "")
					      .replace("-----END PRIVATE KEY-----", "");
				byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
				KeyFactory keyFactory = null;
				keyFactory = KeyFactory.getInstance("RSA");
				PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
			    this.privKey = (PrivateKey) keyFactory.generatePrivate(keySpec);
			    // decrypt payload and get session key
			    Cipher RSAcipher = Cipher.getInstance("RSA");
			    RSAcipher.init(Cipher.DECRYPT_MODE, this.privKey);
			    this.AESkey = RSAcipher.doFinal(response.getPayload());
			    System.out.println("Decrypted session key is: " + getHex(this.AESkey));
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		else {
			System.out.println("Received some message!");
			String respString = new String(response.getPayload(), StandardCharsets.UTF_8);
			if (respString.equals("Signature mismatch")) {
				// client compromised or intruder in network
				System.out.println("Signature mismatch...aborting");
				System.exit(1);
			}
			else if (respString.equals("Success")) {
				System.out.println("Server received and decrypted data successfully!");
			}
		}
	}
	
	public static String getHex(byte[] value) {
		String output = "";
		for(byte byteValue : value) {
			output += String.format("%02x", byteValue);
		}
		return output;
	}
}
