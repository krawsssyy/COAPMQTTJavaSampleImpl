package mqtt_paho_eclipse_mosquitto.client;

public class MqttMiddleman {

	public static void main(String[] args) throws InterruptedException {
		// create subscriber
		MqttSubscribeClient sub = new MqttSubscribeClient("tcp://127.0.0.1:1883", "subIsmBacTest", 2);
		sub.subscribe("1smBaC/test/gen");
		sub.subscribe("1smBaC/test/3303/0/5700");
		//create publisher
		MqttPublishClient pub = new MqttPublishClient("tcp://127.0.0.1:1883", "pubIsmBacTest", 2);
		pub.publish("1smBaC/test/gen");
		Thread.sleep(10000); // sleep 10s awaiting for key to be processed
		while(true) {
			pub.publish("1smBaC/test/3303/0/5700");
			Thread.sleep(10000); // sleep 10s before publishing again
		} 

	}

}
