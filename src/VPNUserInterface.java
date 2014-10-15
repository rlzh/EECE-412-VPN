import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.swt.widgets.Text;
import org.eclipse.swt.SWT;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.custom.StyledText;
import org.eclipse.swt.widgets.Event;
import org.eclipse.swt.widgets.Listener;
import org.eclipse.swt.widgets.ToolBar;
import org.eclipse.swt.widgets.ToolItem;
import org.eclipse.swt.graphics.Point;
import org.eclipse.swt.widgets.Group;
import org.eclipse.swt.layout.FillLayout;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.layout.GridData;
import org.eclipse.wb.swt.SWTResourceManager;


public class VPNUserInterface {

	protected Shell shell;
	private Display display;
	private Text portNumberValue;
	private Text secretValue;
	private Text ipValue;
	private ToolItem tltmClient;
	private ToolItem tltmServer;
	private Button btnSend;
	private Button btnCreatInstance;
	private StyledText dataToSendValue;
	private StyledText log;
	
	private VPNManager vpnManager;
	private Label lblDataToSend;
	private StyledText dataReceivedValue;

	private String logPrefix = " > ";
	private String errorPrefix = logPrefix + "ERROR: ";
	private Label label;
	private Label label_1;
	private Label label_2;
	private Button btnContinue;
	private Button btnStepThroughReceive;
	private Button btnStepThroughReceive_1;
	
	//--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
	//
	//			MAIN
	//
	//--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
			
		
	public static void main(String[] args) {
		
		VPNUserInterface ui = new VPNUserInterface();
		VPNManager manager = new VPNManager(ui);
		ui.vpnManager = manager;
		try {
			ui.open();
		} catch (Exception e) {
			// TODO: handle exception
			e.printStackTrace();
		}
	}
	
	public void SetVPNManager(VPNManager manager) {
		this.vpnManager = manager;
	}
	
	/**
	 * Open the window.
	 */
	public void open() {
		display = Display.getDefault();
		createContents();
		shell.open();
		shell.layout();
		while (!shell.isDisposed()) {
			if (!display.readAndDispatch()) {
				display.sleep();
			}
		}
		
	}

	/**
	 * Create contents of the window.
	 * @wbp.parser.entryPoint
	 */
	protected void createContents() {
		shell = new Shell();
		shell.setMinimumSize(new Point(600, 700));
		shell.setSize(600, 700);
		shell.setText("VPN");
		shell.setLayout(new FillLayout(SWT.VERTICAL));
		shell.addListener(SWT.Close, new Listener() {

			@Override
			public void handleEvent(Event arg0) {
				// TODO Auto-generated method stub
				vpnManager.closeVPN();
			}
			
		});
		
		
		Group grpOptions = new Group(shell, SWT.NONE);
		grpOptions.setText("Options");
		grpOptions.setLayout(new GridLayout(2, false));
		
		label_1 = new Label(grpOptions, SWT.SEPARATOR | SWT.HORIZONTAL);
		GridData gd_label_1 = new GridData(SWT.LEFT, SWT.CENTER, false, false, 2, 1);
		gd_label_1.widthHint = 574;
		label_1.setLayoutData(gd_label_1);
		
		Label lblIp = new Label(grpOptions, SWT.NONE);
		lblIp.setLayoutData(new GridData(SWT.RIGHT, SWT.CENTER, false, false, 1, 1));
		lblIp.setText("IP");
		
		ipValue = new Text(grpOptions, SWT.BORDER);
		ipValue.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false, 1, 1));
		
		Label lblPort = new Label(grpOptions, SWT.NONE);
		lblPort.setLayoutData(new GridData(SWT.RIGHT, SWT.CENTER, false, false, 1, 1));
		lblPort.setText("Port #");
		
		portNumberValue = new Text(grpOptions, SWT.BORDER);
		GridData gd_portNumberValue = new GridData(SWT.LEFT, SWT.CENTER, true, false, 1, 1);
		gd_portNumberValue.widthHint = 91;
		portNumberValue.setLayoutData(gd_portNumberValue);
		
		Label lblInstanceType = new Label(grpOptions, SWT.NONE);
		lblInstanceType.setLayoutData(new GridData(SWT.RIGHT, SWT.CENTER, false, false, 1, 1));
		lblInstanceType.setText("Instance Type");
		
		ToolBar toolBar = new ToolBar(grpOptions, SWT.FLAT | SWT.RIGHT);
		toolBar.setToolTipText("Select the type of this instance");
		
		tltmClient = new ToolItem(toolBar, SWT.RADIO);
		tltmClient.setSelection(true);
		tltmClient.setText("Client");
		
		tltmServer = new ToolItem(toolBar, SWT.RADIO);
		tltmServer.setText("Server");
		tltmServer.addListener(SWT.Selection, new Listener() {
			
			@Override
			public void handleEvent(Event arg0) {
				// TODO Auto-generated method stub
				if (!ipValue.isDisposed()) {
	  				ipValue.setText(vpnManager.getServerIP());
	  			}
			}
		});
		
		Label lblSharedSecretValue = new Label(grpOptions, SWT.NONE);
		lblSharedSecretValue.setLayoutData(new GridData(SWT.RIGHT, SWT.CENTER, false, false, 1, 1));
		lblSharedSecretValue.setText("Shared Secret Value");
		
		secretValue = new Text(grpOptions, SWT.BORDER | SWT.PASSWORD);
		secretValue.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false, 1, 1));
		new Label(grpOptions, SWT.NONE);
		
		btnCreatInstance = new Button(grpOptions, SWT.NONE);
		btnCreatInstance.setLayoutData(new GridData(SWT.CENTER, SWT.CENTER, false, false, 1, 1));
		btnCreatInstance.setText("Creat Instance");
		btnCreatInstance.addListener(SWT.Selection, new Listener() {
			
			@Override
			public void handleEvent(Event e) {
				// TODO Auto-generated method stub
				switch(e.type) {
				case SWT.Selection:
					if(validateInput()) {
						String ip = ipValue.getText();
						String portNum = portNumberValue.getText();
						String secret = secretValue.getText();
						if(tltmClient.getSelection())
							vpnManager.createVPNInstance(VPNEntity.InstanceType.Client, ip, Integer.parseInt(portNum), secret);

						else 
							vpnManager.createVPNInstance(VPNEntity.InstanceType.Server, ip, Integer.parseInt(portNum), secret);
					}
					break;
				default:
					break;
				}
				
			}
		});
		
		label = new Label(grpOptions, SWT.SEPARATOR | SWT.HORIZONTAL);
		label.setLayoutData(new GridData(SWT.FILL, SWT.TOP, false, false, 2, 1));
		
		lblDataToSend = new Label(grpOptions, SWT.NONE);
		lblDataToSend.setLayoutData(new GridData(SWT.CENTER, SWT.CENTER, false, false, 1, 1));
		lblDataToSend.setText("Data To Send");
		
		dataToSendValue = new StyledText(grpOptions, SWT.BORDER | SWT.WRAP);
		dataToSendValue.setAlwaysShowScrollBars(false);
		dataToSendValue.setLayoutData(new GridData(SWT.FILL, SWT.FILL, true, true, 1, 1));
		
		Label lblDataReceived = new Label(grpOptions, SWT.BORDER | SWT.WRAP | SWT.READ_ONLY | SWT.V_SCROLL);
		lblDataReceived.setLayoutData(new GridData(SWT.CENTER, SWT.CENTER, false, false, 1, 1));
		lblDataReceived.setText("Data Received");
		
		dataReceivedValue = new StyledText(grpOptions, SWT.BORDER | SWT.READ_ONLY | SWT.WRAP);
		dataReceivedValue.setLayoutData(new GridData(SWT.FILL, SWT.FILL, true, true, 1, 1));
		
		btnContinue = new Button(grpOptions, SWT.NONE);
		btnContinue.setEnabled(false);
		btnContinue.setLayoutData(new GridData(SWT.CENTER, SWT.CENTER, false, false, 1, 1));
		btnContinue.setText("Step Through Send");
		btnContinue.addListener(SWT.Selection, new Listener() {
			
			@Override
			public void handleEvent(Event arg0) {
				// TODO Auto-generated method stub
				if(!dataToSendValue.getText().isEmpty()) {
					vpnManager.setupThroughSend(dataToSendValue.getText());
				}
			}
		});
		
		btnSend = new Button(grpOptions, SWT.NONE);
		btnSend.setLayoutData(new GridData(SWT.CENTER, SWT.CENTER, false, false, 1, 1));
		btnSend.setEnabled(false);
		btnSend.setText("Send");
		btnSend.addListener(SWT.Selection, new Listener() {
			
			@Override
			public void handleEvent(Event e) {
				// TODO Auto-generated method stub
				switch(e.type) {
				case SWT.Selection:
					if(!dataToSendValue.getText().isEmpty()) {
						vpnManager.sendMessage(dataToSendValue.getText());
					}
					break;
				default:
					break;
				}
				
				
			}
		});
		
		btnStepThroughReceive = new Button(grpOptions, SWT.NONE);
		btnStepThroughReceive.setEnabled(false);
		btnStepThroughReceive.setText("Step Through Receive");
		btnStepThroughReceive.addListener(SWT.Selection, new Listener() {
			
			@Override
			public void handleEvent(Event arg0) {
				// TODO Auto-generated method stub
				if(!btnStepThroughReceive.isDisposed()) {
					vpnManager.stepThroughReceive();
				}
			}
		});
		
		btnStepThroughReceive_1 = new Button(grpOptions, SWT.CHECK);
		btnStepThroughReceive_1.setEnabled(false);
		btnStepThroughReceive_1.setText("Step Through Receive");
		btnStepThroughReceive_1.addListener(SWT.Selection, new Listener() {
			
			@Override
			public void handleEvent(Event arg0) {
				// TODO Auto-generated method stub
				vpnManager.setStepThroughReceive(btnStepThroughReceive_1.getSelection());
			}
		});
		
		label_2 = new Label(grpOptions, SWT.SEPARATOR | SWT.HORIZONTAL);
		label_2.setLayoutData(new GridData(SWT.FILL, SWT.FILL, false, false, 2, 1));
		
		Group grpLog = new Group(shell, SWT.NONE);
		grpLog.setText("Log");
		grpLog.setLayout(new FillLayout(SWT.HORIZONTAL));
		
		log = new StyledText(grpLog, SWT.BORDER | SWT.V_SCROLL | SWT.MULTI | SWT.WRAP | SWT.READ_ONLY);
		log.setBackground(SWTResourceManager.getColor(SWT.COLOR_BLACK));
		log.setForeground(SWTResourceManager.getColor(SWT.COLOR_WHITE));
		log.setAlwaysShowScrollBars(false);
		log.setEditable(false);
		
		log.addListener(SWT.Modify, new Listener() {
			
			@Override
			public void handleEvent(Event arg0) {
				// TODO Auto-generated method stub
				log.setTopIndex(log.getLineCount() - 1);
			}
		});

	}
	
	
	//-----------------------------------------------------------------------------------------------------
	// 		HELPER FUNCTIONS
	//-----------------------------------------------------------------------------------------------------
	public VPNUserInterface getInstance(){
		return this;
	}
	
	public Button getCreateInstanceButton() {
		return this.btnCreatInstance;
	}
	
	public Button getSendButton() {
		return this.btnSend;
	}
	
	public String getPortNumberValue() {
		return this.portNumberValue.getText();
	}
	
	public String getIpAddressValue() {
		return this.ipValue.getText();
	}
	
	public String getSecretValue() {
		return this.secretValue.getText();
	}
	
	public String getDataToSend() {
		return this.dataToSendValue.getText();
	}
	
	public VPNEntity.InstanceType getInstanceType() {
		if(this.tltmClient.getSelection())
			return VPNEntity.InstanceType.Client;
		else
			return VPNEntity.InstanceType.Server;
	}
	
	public void logMessage(String msg) {
		String logStr = logPrefix + msg + "\n";
		this.log.setText(this.log.getText().concat(logStr));
	}
	
	public void logError(String msg) {
		String logStr = errorPrefix + msg + "\n";
		this.log.setText(this.log.getText().concat(logStr));
	}
	
	public void logHeader(String header) {
		this.logMessage("");
		this.logMessage("-------------------------------------------------------------------------");
		this.logMessage("          " + header);
		this.logMessage("-------------------------------------------------------------------------");
	}
	
	public void logMessageAsync(final String msg) {
	  	display.asyncExec(new Runnable() {
	  		@Override
	  		public void run() {
	  			if (!log.isDisposed()) {
	  				logMessage(msg);
	  			}
	  		}
	  	});
	}
	
	public void logErrorAsync(final String msg) {
	  	display.asyncExec(new Runnable() {
	  		@Override
	  		public void run() {
	  			if (!log.isDisposed()) {
	  				logError(msg); 
	  			}
	  		}
	  	});
	}
	
	public void logHeaderAsync(final String header) {
		display.asyncExec(new Runnable() {
	  		@Override
	  		public void run() {
	  			if (!log.isDisposed()) {
	  				logHeader(header); 
	  			}
	  		}
	  	});
	}
	
	public void enableSendButtonAsync() {
		display.asyncExec(new Runnable() {
			@Override
			public void run() {
				// TODO Auto-generated method stub
				if(!btnSend.isDisposed()) {
					btnSend.setEnabled(true);
					btnStepThroughReceive.setEnabled(true);
					btnStepThroughReceive_1.setEnabled(true);
					btnContinue.setEnabled(true);
				}
 			}
		});
	}
	
	public void displayDataReceived(String msg) {
		if(!dataReceivedValue.isDisposed()) {
			dataReceivedValue.setText(msg);
		}
	}
	
	public void displayDataReceivedAsync(final String msg) {
		display.asyncExec(new Runnable() {
			@Override
			public void run() {
				// TODO Auto-generated method stub
				if(!dataReceivedValue.isDisposed()) {
					dataReceivedValue.setText(msg);
				}
 			}
		});
	}
	
	public Boolean validateInput() {
		
		if(portNumberValue.getText().isEmpty()) {
			logMessage("Error : Invalid port number!");
			return false;
		} 
		else if(ipValue.getText().isEmpty()) {
			logMessage("Error : Invalid IP!");
			return false;
		}
		else if(secretValue.getText().isEmpty()) {
			logMessage("Error : Invalid secret!");
			return false;
		}
		
		return true;
	}
}
