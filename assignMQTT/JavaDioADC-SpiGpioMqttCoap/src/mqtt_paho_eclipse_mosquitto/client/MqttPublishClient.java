package mqtt_paho_eclipse_mosquitto.client;
import java.io.File;
import java.io.FileInputStream;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.eclipse.paho.client.mqttv3.MqttClient;
import org.eclipse.paho.client.mqttv3.MqttConnectOptions;
import org.eclipse.paho.client.mqttv3.MqttException;
import org.eclipse.paho.client.mqttv3.MqttMessage;
import org.eclipse.paho.client.mqttv3.persist.MemoryPersistence;

public class MqttPublishClient {
	String broker;
	String clientId;
	int qos;
	byte[] AESkey;
	PublicKey publKeySub;
	PrivateKey privKeyPub;
	MqttClient sampleClient;
	
	public MqttPublishClient(String brokerp, String clientIdp, int qosp) {
		this.broker = brokerp;
		this.clientId = clientIdp;
		this.qos = qosp;
		try {
			// load subscribers public key from certificate
			FileInputStream fCertInSub = new FileInputStream("MqttSubscriberX509.cer");
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509Certificate sub = (X509Certificate) cf.generateCertificate(fCertInSub);
			this.publKeySub = sub.getPublicKey();
			fCertInSub.close();
			// load publishers private key from PEM
			String key = new String(Files.readAllBytes(new File("C:\\Users\\alex\\Desktop\\fac\\materialeMaster\\an2\\sem1\\embedded robotics iot\\assignMQTT\\JavaDioADC-SpiGpioMqttCoap\\key_pub.pem").toPath()), Charset.defaultCharset());
			String privateKeyPEM = key
				      .replace("-----BEGIN PRIVATE KEY-----", "")
				      .replaceAll(System.lineSeparator(), "")
				      .replace("-----END PRIVATE KEY-----", "");
			byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
			KeyFactory keyFactory = null;
			keyFactory = KeyFactory.getInstance("RSA");
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
		    this.privKeyPub = (PrivateKey) keyFactory.generatePrivate(keySpec);
		    // init mqtt client and connect
            this.sampleClient = new MqttClient(broker, clientId, new MemoryPersistence());
            MqttConnectOptions connOpts = new MqttConnectOptions();
            connOpts.setCleanSession(true);
            System.out.println("PUBLISHER - MQTT Connecting to broker: "+broker);
            this.sampleClient.connect(connOpts);
            System.out.println("PUBLISHER - Connected");
		} catch (Exception e) {
			e.printStackTrace();
		}
		
	}

    public void publish(String topic) {
        try {

            if (topic.equals("1smBaC/test/gen")) {
            	// generate session key
            	SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
				this.AESkey = new byte[16];
				secureRandom.nextBytes(this.AESkey);
				System.out.println("PUBLISHER - Generated session key is: " + getHex(this.AESkey));
				// init RSA cipher and encrypt AES key with subscribers public key
				Cipher RSAcipher = Cipher.getInstance("RSA");
				RSAcipher.init(Cipher.ENCRYPT_MODE, publKeySub);
				byte[] cipheredAESkey = RSAcipher.doFinal(this.AESkey);
				// send encrypted session key
				MqttMessage message = new MqttMessage(cipheredAESkey);
	            message.setQos(qos);
	            sampleClient.publish(topic, message);
	            System.out.println("PUBLISHER - Message published");
            }
            else {
            	// suppose we have a temperature sensor which sends its values => objectId = 3303, resourceId = 5700, instanceId = 0
            	SecureRandom r = new SecureRandom();
				float random = -40f + r.nextFloat() * 80f;
				String jsonIPSO = "{\n\t\"timestamp\": " + System.currentTimeMillis() + ",\n\t\"values\": [{\n\t\t\"objectId\": 3303,\n\t\t\"instanceId\": 0,\n\t\t\"resourceId\": 5700,\n\t\t\"datatype\": Float,\n\t\t\"value\": " + random + "\n\t]}\n}";
				// init AES cipher to encrypt the JSON
				Cipher AEScipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
				SecretKeySpec keySpec = new SecretKeySpec(this.AESkey, "AES");
				AEScipher.init(Cipher.ENCRYPT_MODE, keySpec);
				byte[] encPayload = AEScipher.doFinal(jsonIPSO.getBytes());
				// prepare to sign and sign the encrypted payload
				Signature signature = Signature.getInstance("SHA512withRSA");
				signature.initSign(this.privKeyPub);
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
				MqttMessage message = new MqttMessage(payload);
                message.setQos(qos);
                sampleClient.publish(topic, message);
                System.out.println("PUBLISHER - Data:\n" + jsonIPSO);
                System.out.println("PUBLISHER - Message published");
            }
            
        } catch(Exception me) {
            me.printStackTrace();
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
		System.out.println("PUBLISHER - MQTT Disconnected");
	}
}

