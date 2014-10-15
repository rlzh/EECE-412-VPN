import java.io.IOException;



public class MessageHandler implements Runnable {
	
	private VPNEntity instance;
	private VPNUserInterface ui;
	
	private Boolean shouldRun = true;
	
	public MessageHandler(VPNEntity instance, VPNUserInterface ui) {
		this.instance = instance;
		this.ui = ui;
	}
	
	public void stopThread() {
		this.shouldRun = false;
	}
	
	private void sendMessage(String msg) throws Exception {
		this.instance.sign(	this.instance.encryptText(msg));
	}
	
	
	@Override
	public void run() {
		
		String message = "You are now connected!";
		byte[] signedEncryptedData = null;
		byte[] encryptedData = null;
		byte[] data = null;
		// send message to server to notify they are connected
		if(this.instance.getInstanceType() == VPNEntity.InstanceType.Server) 
		{
			try {
				// send signed encrypted notification to user to let them know they are connected
				this.instance.sendMessage(this.instance.sign(this.instance.encryptText(message)));
				
			} catch (Exception e) {
				// TODO: handle exception
				e.printStackTrace();
				ui.logErrorAsync(e.toString());
			}
		}
		this.ui.logHeaderAsync("CONNECTED");
		do {
			try{
				if(shouldRun) {
					// receive signed encrypted data
					signedEncryptedData = this.instance.receiveMessage();
					ui.logMessageAsync("Receiving signed encrypted data: " + signedEncryptedData);
					
					System.out.println("set through receive is :" + this.instance.stepThroughReceive);
					
					if(!this.instance.stepThroughReceive) {
						// unsign encrypted data
						ui.logMessageAsync("Unsigning " + signedEncryptedData + "...");
						encryptedData = this.instance.unsign(signedEncryptedData);
						ui.logMessageAsync("Unsigned result is: " + encryptedData);
						
						// decrypt data
						ui.logMessageAsync("Decrypting " + encryptedData + "...");
						message = this.instance.decryptText(encryptedData);
						ui.logMessageAsync("Decrypting encrypted data to be: " + "\"" + message + "\"");
						
						// display message received in message received box
						ui.displayDataReceivedAsync(message);
					} else {
						this.instance.receivedData = new byte[0];
						this.instance.receivedData = signedEncryptedData;
					}
					
				}
			} catch(Exception e) {
				e.printStackTrace();
				ui.logErrorAsync(e.toString());
				break;
			}
			
		} while (!message.equals("CLIENT - END") && !message.equals("SERVER - END") 
				 && shouldRun);
			
		
		ui.logMessageAsync("Connection has ended");
		
		try {
			this.instance.tearDownConnection();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		System.out.println("Message handler thread ended.");
		return;
	}
}

