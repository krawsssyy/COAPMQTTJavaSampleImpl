package mqtt_paho_eclipse_mosquitto.client;

import java.io.File;
import java.io.FileInputStream;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.eclipse.paho.client.mqttv3.IMqttDeliveryToken;
import org.eclipse.paho.client.mqttv3.MqttCallback;
import org.eclipse.paho.client.mqttv3.MqttClient;
import org.eclipse.paho.client.mqttv3.MqttConnectOptions;
import org.eclipse.paho.client.mqttv3.MqttException;
import org.eclipse.paho.client.mqttv3.MqttMessage;
import org.eclipse.paho.client.mqttv3.persist.MemoryPersistence;

public class MqttSubscribeClient implements MqttCallback {
	String broker;
	String clientId;
	int qos;
	byte[] AESkey;
	PublicKey publKeyPub;
	PrivateKey privKeySub;
	MqttClient sampleClient;
	
	public MqttSubscribeClient(String brokerp, String clientIdp, int qosp) {
		this.broker = brokerp;
		this.clientId = clientIdp;
		this.qos = qosp;
		try {
			// load publishers public key from certificate
			FileInputStream fCertInPub = new FileInputStream("MqttPublisherX509.cer");
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509Certificate pub = (X509Certificate) cf.generateCertificate(fCertInPub);
			this.publKeyPub = pub.getPublicKey();
			fCertInPub.close();
			// load subscribers private key from PEM
			String key = new String(Files.readAllBytes(new File("C:\\Users\\alex\\Desktop\\fac\\materialeMaster\\an2\\sem1\\embedded robotics iot\\assignMQTT\\JavaDioADC-SpiGpioMqttCoap\\key_sub.pem").toPath()), Charset.defaultCharset());
			String privateKeyPEM = key
				      .replace("-----BEGIN PRIVATE KEY-----", "")
				      .replaceAll(System.lineSeparator(), "")
				      .replace("-----END PRIVATE KEY-----", "");
			byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
			KeyFactory keyFactory = null;
			keyFactory = KeyFactory.getInstance("RSA");
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
		    this.privKeySub = (PrivateKey) keyFactory.generatePrivate(keySpec);
		    // init mqtt connection and subscribe to given topic
 			this.sampleClient = new MqttClient(this.broker, this.clientId, new MemoryPersistence());
 			MqttConnectOptions connOpts = new MqttConnectOptions();
 			connOpts.setCleanSession(true);
 			sampleClient.setCallback(this);
            System.out.println("SUBSCRIBER - MQTT Connecting to broker: "+broker);
            this.sampleClient.connect(connOpts);
            System.out.println("SUBSCRIBER - Connected");

		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public void subscribe(String topic) {
		try {
			// subscribe to given topic
			sampleClient.subscribe(topic, this.qos);
		} catch (MqttException e) {
			e.printStackTrace();
		}
	}

	@Override
	public void connectionLost(Throwable arg0) {
		System.out.println("SUBSCRIBER - Connection lost due to:");
		arg0.printStackTrace();
		System.out.println(arg0.getMessage() + '\n' + arg0.getLocalizedMessage());
		System.out.println("SUBSCRIBER - Closing client");
		try {
			this.sampleClient.disconnect();
		} catch (MqttException e) {
			e.printStackTrace();
		}
		System.exit(1);
	}

	@Override
	public void deliveryComplete(IMqttDeliveryToken arg0) {
		try {
			System.out.println("SUBSCRIBER - Delivery complete:" + arg0.isComplete() + " for message " + arg0.getMessage());
		} catch (MqttException e) {
			e.printStackTrace();
		}
	}

	@Override
	public void messageArrived(String arg0, MqttMessage arg1) throws Exception {
		System.out.println("SUBSCRIBER - Message arrived on topic:" + arg0);
		if (arg0.equals("1smBaC/test/gen")) {
			Cipher RSAcipher = Cipher.getInstance("RSA");
		    RSAcipher.init(Cipher.DECRYPT_MODE, this.privKeySub);
		    this.AESkey = RSAcipher.doFinal(arg1.getPayload());
		    System.out.println("SUBSCRIBER - Decrypted session key is: " + getHex(this.AESkey));
		}
		else {
			byte[] recvPayload = arg1.getPayload();
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
				signature.initVerify(this.publKeyPub);
				signature.update(encPayload);
				boolean isCorrect = signature.verify(sign);
				if(isCorrect) {
					// decrypt payload
					System.out.println("SUBSCRIBER - Signature verified successfully");
					Cipher AEScipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
					SecretKeySpec keySpec = new SecretKeySpec(this.AESkey, "AES");
					AEScipher.init(Cipher.DECRYPT_MODE, keySpec);
					byte[] decryptedPayload = AEScipher.doFinal(encPayload);
					String recvJson = new String(decryptedPayload, StandardCharsets.UTF_8);
					System.out.println("SUBSCRIBER - Received data:\n" + recvJson);
				}	
				else {
					// panic
					System.out.println("SUBSCRIBER - Signature mismatch...publisher/connection compromised");
				}
			} catch (Exception e) {
				e.printStackTrace();
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
	
	protected void finalize() throws MqttException {
		this.sampleClient.disconnect();
		System.out.println("SUBSCRIBER - MQTT Disconnected");
	}
}
