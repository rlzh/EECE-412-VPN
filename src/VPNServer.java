import java.net.ServerSocket;


public class VPNServer extends VPNEntity {

	private ServerSocket listenerSocket;
	private int maxBackLog = 100;
	
	public VPNServer(InstanceType instanceType, String ipAddress, int portNumber, String sharedSecret) {
		super(instanceType, ipAddress, portNumber, sharedSecret);
		// TODO Auto-generated constructor stub
	}
		
	public void setListenerSocket(ServerSocket socket) {
		this.listenerSocket = socket;
	}

	public ServerSocket getListenerSocket() {
		return this.listenerSocket;
	}
	
	public int getMaxBackLog() {
		return this.maxBackLog;
	}

}
