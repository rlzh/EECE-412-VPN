import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import javax.crypto.NoSuchPaddingException;




public class VPNManager {

	private VPNEntity vpnInstance;
	private VPNUserInterface ui;
	
	public VPNManager(VPNUserInterface ui) {
		this.ui = ui;
		this.vpnInstance = null;
	}
	
	public void createVPNInstance(VPNEntity.InstanceType instanceType, String ipAddress, int portNumber, String sharedSecret) {
		
		switch(instanceType) {
		
		case Client:
			vpnInstance = new VPNClient(VPNEntity.InstanceType.Client, ipAddress, portNumber, sharedSecret);
			break;
		case Server:
			vpnInstance = new VPNServer(VPNEntity.InstanceType.Server, ipAddress, portNumber, sharedSecret);
			break;
		default:
			break;
		
		}
		
		this.logHeader("NEW INSTANCE");
		StringBuilder sb = new StringBuilder();
		sb.append("Created " + instanceType.toString() + " instance" );
		sb.append(" | IP: " + ipAddress);
		sb.append(" | port: " + Integer.toString(portNumber));
		sb.append(" | secret: " + sharedSecret);
		this.log(sb.toString());	

		ConnectionSetupHelper helper = new ConnectionSetupHelper(this.vpnInstance, this.ui);
		this.vpnInstance.setSetupHelper(helper);
		setupVPNInstance();
	}
	
	private void setupVPNInstance() {
		this.logHeader("SETUP");
		this.log("Setting up vpn instance...");
		this.log("Generating symmetric key...");
		try {
			log("The symmetric key is: " + this.vpnInstance.calcSymmetricKey());
		} catch (NoSuchAlgorithmException e) {
			//e.printStackTrace();
			this.logError(e.toString());
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			this.logError(e.toString());
		}
		
		this.log("Generating asymmetric key...");
		try {
			KeyPair kp = this.vpnInstance.calcAsymmetricKey();
			log("The public key is: " + kp.getPublic().toString());
			log("The private key is: " + kp.getPrivate().toString());
		} catch (NoSuchAlgorithmException e1) {
			// TODO Auto-generated catch block
			//e1.printStackTrace();
			this.logError(e1.toString());
		}
		
		this.log("Creating thread to setup connection...");
		this.vpnInstance.setupConnection();
	}
	
	public VPNEntity getVPNInstance() {
		return this.vpnInstance;
	}
	
	public void setupUI() {
		this.ui.SetVPNManager(this);
		this.ui.open();
	}
	
	private void log(String msg) {
		this.ui.logMessage(msg);
	}
	
	private void logError(String msg) {
		this.ui.logError(msg);
	}
	
	private void logHeader(String header) {
		this.ui.logHeader(header);
	}
	
	public void sendMessage(String message) {
		try {
			log("Preparing to send data: " + "\"" + message + "\"");
			
			// encrypt data
			log("Encrypting " + "\"" + message + "\"...");
			byte[] encryptedData = this.vpnInstance.encryptText(message);
			log("Encrypted result is: " + encryptedData);
			
			// sign data
			log("Signing encrypted data...");
			byte[] signedEncryptedData = this.vpnInstance.sign(encryptedData);
			log("Signed result is: " + signedEncryptedData);
			
			// send data
			this.vpnInstance.sendMessage(signedEncryptedData);
			log("Sending signed encrypted data: " + signedEncryptedData);
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			//e.printStackTrace();
			logError(e.toString());
		}
	}
	
	public void setupThroughSend(String message) {
		byte[] encryptedData = new byte[0];
		byte[] signedEncryptedData = new byte[0];
		switch (this.vpnInstance.dataSendState) {
		case Idle:
			log("Preparing to send data: " + "\"" + message + "\"");
			this.vpnInstance.dataSendState = VPNEntity.DataSendState.Encrypt;
			break;
		case Encrypt:
			// encrypt data
			log("Encrypting " + "\"" + message + "\"...");
			try {
				encryptedData = this.vpnInstance.encryptText(message);
				log("Encrypted result is: " + encryptedData);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				logError(e.toString());
			}
			this.vpnInstance.dataSendState = VPNEntity.DataSendState.Sign;
			break;
		case Sign:
			// sign data
			try {
				log("Signing encrypted data...");
				encryptedData = this.vpnInstance.encryptText(message);
				signedEncryptedData = this.vpnInstance.sign(encryptedData);
				log("Signed result is: " + signedEncryptedData);
			} catch (Exception e) {
				logError(e.toString());
			}
			this.vpnInstance.dataSendState = VPNEntity.DataSendState.Send;
			break;
		case Send:
			// send data
			try {
				encryptedData = this.vpnInstance.encryptText(message);
				signedEncryptedData = this.vpnInstance.sign(encryptedData);
				this.vpnInstance.sendMessage(signedEncryptedData);
				log("Sending signed encrypted data: " + signedEncryptedData);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			this.vpnInstance.dataSendState = VPNEntity.DataSendState.Idle;
		default:
			break;
		}
	}
	
	public void stepThroughReceive() {
		byte[] signedEncryptedData = vpnInstance.receivedData;
		byte[] encryptedData = new byte[0];
		String message = "";
		
		switch (this.vpnInstance.dataReceiveState) {
		case Idle:
			log("Preparing to unsign " + vpnInstance.receivedData);
			this.vpnInstance.dataReceiveState = VPNEntity.DataReceiveState.Unsign;
			break;
		case Unsign:
			// unsign encrypted data
			log("Unsigning " + signedEncryptedData + "...");
			try {
				encryptedData = this.vpnInstance.unsign(signedEncryptedData);
				log("Unsigned result is: " + encryptedData);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				logError(e.toString());
			}
			this.vpnInstance.dataReceiveState = VPNEntity.DataReceiveState.Decrypt;
			break;
		case Decrypt:
			// decrypt data
			log("Decrypting " + encryptedData + "...");
			try {
				encryptedData = this.vpnInstance.unsign(signedEncryptedData);
				message = this.vpnInstance.decryptText(encryptedData);
				log("Decrypting encrypted data to be: " + "\"" + message + "\"");
				// display message received in message received box
				ui.displayDataReceived(message);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				logError(e.toString());
			}
			this.vpnInstance.dataReceiveState = VPNEntity.DataReceiveState.Idle;
			break;
		default:
			break;
		}
	}
	
	public void setStepThroughReceive(Boolean b) {
		System.out.println("setting step through receive: " + b);
		this.vpnInstance.stepThroughReceive = b;
	}
	
	public String getServerIP() {
		try {
			InetAddress IP = InetAddress.getLocalHost();
			return IP.getHostAddress();
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return "";
	}
	
	public void closeVPN() {
		if(this.vpnInstance != null) {
			System.out.println("Closing vpn and ending threads!");
			try {
				this.vpnInstance.tearDownConnection();
			} catch (IOException e) {
				// TODO: handle exception
				e.printStackTrace();
				logError(e.toString());
			}
		}
	}
	
}
