import java.io.IOException;
import java.security.PublicKey;
import java.security.SignatureException;


public class AuthenticationHandler implements Runnable {
	
	private VPNEntity instance;
	private VPNUserInterface ui;
	private String authConfirmation;
	private MessageHandler messageHandler;
	private Boolean authenticationFailed = false;

	private Boolean shouldRun = true;
	
	public AuthenticationHandler(VPNEntity instance, VPNUserInterface ui) {
		this.instance = instance;
		this.ui = ui;
		this.authConfirmation = this.instance.authConfirmation;
	}
	
	public void stopThread() {
		this.shouldRun = false;
	}
	
	private void challengeAuth() throws Exception {
		byte[] data = null;
		String dataString = "";
		if(!authenticationFailed) {
			// send challenge
			String authToken = this.instance.sendAuthChallenge();
			this.ui.logMessageAsync("Sending challenge token: " + "\"" + authToken + "\"");
			
			// wait for auth response
			// unsign response 
			dataString = new String(this.instance.decryptText(this.instance.unsign(this.instance.receiveMessage())));
			
			// log data
			this.ui.logMessageAsync("Receiving response: " + data);
			this.ui.logMessageAsync("Validating response...");
			
			// decrypt unsigned data and checks if auth token match expect result
			if(!this.instance.validateAuthResponse(dataString)) {
				authenticationFailed = true;
				return;
			}
			this.ui.logMessageAsync("Received valid response!");
			this.ui.logMessageAsync("Sent authentication confirmation: " + "\"" + authConfirmation + "\"");
		}
	}
	
	private void respondAuth() throws Exception {
		String dataString = null;
		byte[] data = null;
		byte[] unsignedData = null;
		if(!authenticationFailed) {
			
			this.ui.logMessageAsync("Waiting for challenge token...");
			// wait for challenge
			do {
				data = this.instance.receiveMessage();
			} while(data.equals(null));
			
			// unsign challenge
			unsignedData = this.instance.unsign(data);
			
			// convert challenge into string
			dataString = new String(unsignedData);
			this.ui.logMessageAsync("Receiving challenge token: " + "\"" + dataString + "\"");
			
			// build authentication token string
			StringBuilder sb = new StringBuilder();
			sb.append(dataString).append(this.instance.getSharedSecret());
			this.ui.logMessageAsync("Generated token/shared secret combination: " + "\"" + sb.toString() + "\"");
			this.ui.logMessageAsync("Generating response...");
			
			// send authentication response
			byte[] authResponse = this.instance.sendAuthResponse(sb.toString());
			this.ui.logMessageAsync("Sending response: " + authResponse);

			data = null;
			this.ui.logMessageAsync("Waiting for authentiation confirmation...");
			// wait for auth confirmation
			// check if servers replies "AUTHENTICATED"
			dataString = new String(instance.decryptText(instance.unsign(this.instance.receiveMessage())));
				
			if(!(dataString).equals(authConfirmation)) {
				authenticationFailed = true;
				return;
			}
			
			this.ui.logMessageAsync("Received authentication confirmation: " + "\"" + authConfirmation + "\"");
		}
	}
	
	private void sendPublicKey() throws IOException {
		PublicKey key = this.instance.sendPublicKey();
		this.ui.logMessageAsync("Sending my public key: " + key.toString());
	}
	
	private void receivePublicKey() throws IOException, ClassNotFoundException {
		PublicKey key = this.instance.receivePublicKey();
		this.ui.logMessageAsync("Receiving other public key: " + key.toString());
	}
	
	@Override
	public void run() {
		// TODO Auto-generated method stub
		this.ui.logHeaderAsync("AUTHENTICATION");
		while(shouldRun && !authenticationFailed) {
			try {
				if(this.instance.getInstanceType() == VPNEntity.InstanceType.Server) 
				{
					// send public key to client 
					sendPublicKey();
					// get public key of client
					receivePublicKey();
					
					// server starts mutual authentication
					challengeAuth();
					// server then responds to client authentication
					respondAuth();	
				} else {
					// get public key of server 
					receivePublicKey();
					// send public key to server
					sendPublicKey();
					
					// client first responds to server authentication
					respondAuth();
					// client then sends authentication
					challengeAuth();
				}
				
			} catch(SignatureException e ) {
				e.printStackTrace();
				ui.logErrorAsync(e.toString());
				authenticationFailed = true;
			} catch (Exception e) {
				// TODO: handle exception
				e.printStackTrace();
				ui.logErrorAsync(e.toString());
			}
			
			// check if authentication failed 
			if(authenticationFailed) {
				this.ui.logMessageAsync("Oops, the authentication failed");
				// if failed, we need to terminate connection
				this.stopThread();
				System.out.println("Auth failed!");
				try {
					this.instance.tearDownConnection();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				return;
			}
			
			// start message handler thread
			messageHandler = new MessageHandler(this.instance, this.ui);
			Thread t = new Thread(messageHandler);
			t.start();
			ui.enableSendButtonAsync();
			
			break;
		}
		
		
		return;
	}
}
