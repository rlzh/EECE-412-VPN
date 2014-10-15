import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;



public class ConnectionSetupHelper implements Runnable{
	
	private VPNEntity instance;
	private VPNUserInterface ui;
	private ServerSocket serverSocket;
	private Socket connection;
	private ObjectOutputStream output;
	private ObjectInputStream input;
	
	private Boolean shouldRun = true;
	private AuthenticationHandler authenticationHandler;
	
	public ConnectionSetupHelper(VPNEntity instance, VPNUserInterface ui) {
		this.instance = instance;
		this.connection = this.instance.getConnection();
		this.output = this.instance.getOutputStream();
		this.input = this.instance.getInputStream();
		this.ui = ui;
		if(instance.getInstanceType() == VPNEntity.InstanceType.Server) {
			int portNum = this.instance.getPortNumber();
			try {
				this.serverSocket = new ServerSocket(portNum, 100);
				((VPNServer) this.instance).setListenerSocket(this.serverSocket);;
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				ui.logMessageAsync(e.toString());
			}
		}
	}
	
	public void stopThread() {
		if(authenticationHandler != null) 
		{
			System.out.println("Stopping message handler thread");
			authenticationHandler.stopThread();
		}
		this.shouldRun = false;
	}
	
	private void setUpServer() throws IOException {
		ui.logMessageAsync("Waiting for connection...");
		// wait for connection while there is none and while the thread is not interrupted
		do{
			connection = serverSocket.accept();
		}while(!connection.isConnected() && !Thread.currentThread().isInterrupted());
		ui.logMessageAsync("Established connection to client: " + connection.getInetAddress().getHostName());
	}
	
	private void setUpClient() throws UnknownHostException, IOException {
		connection = new Socket(this.instance.getIp(), this.instance.getPortNumber());
		ui.logMessageAsync("Established connected to server: " + connection.getInetAddress().getHostName());

	}
	
	private void setUpConnectionStreams() throws IOException {
		output = new ObjectOutputStream(this.connection.getOutputStream());
		output.flush();
		input = new ObjectInputStream(this.connection.getInputStream());
		ui.logMessageAsync("Established connection streams");
	}
	
	@Override
	public void run() {
		// TODO Auto-generated method stub
		while(shouldRun) {
			try {
				
				if(this.instance.getInstanceType() == VPNEntity.InstanceType.Server) {
					// wait for connection if server
					setUpServer();
				} else {
					// connect to ip and port if client
					setUpClient();
				}
				
				// setup the output and input streams
				setUpConnectionStreams();

				// set instance with initalized parameters
				this.instance.setConnection(this.connection);
				this.instance.setOutputStream(this.output);
				this.instance.setInputStream(this.input);
				
				// TO-DO: authentication and key establishment here!

				ui.logMessageAsync("Finishing setting up vpn instance");
				this.instance.setConnectionState(VPNEntity.ConnectionState.Connected);
				
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				ui.logErrorAsync(e.toString());
			}
			
			// start authentication thread
			authenticationHandler = new AuthenticationHandler(this.instance, this.ui);
			Thread t = new Thread(authenticationHandler);
			t.start();
			
			break;
		}
		System.out.println("Connection setup helper thread ended.");
		return;
	}
}
