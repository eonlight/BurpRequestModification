package configtab;

import java.awt.Component;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
import java.io.File;
import java.io.IOException;

import javax.swing.GroupLayout;
import javax.swing.GroupLayout.ParallelGroup;
import javax.swing.GroupLayout.SequentialGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;

import burp.ITab;
import utils.BurpUtils;

public class RequestModificationConfigTab implements ITab {

	private static final int HEADER_SIZE = 17;
	private static final int MSG_SIZE = 12;
	private static final int LABEL_SIZE = 14;

	private JPanel tab;
	
	private static final String NAME = "Configuration Tab";
	private static final String VERSION = "1.0.0";
	
	public RequestModificationConfigTab() {
		this.initGui();
		BurpUtils.getInstance().write("[*] Loaded " + NAME + " v" + VERSION);
	}
	
	private void saveVariable(JLabel feedback, String variable, String value){
		if(variable.toLowerCase().equals("path")){
			String path = BurpUtils.getInstance().path;
			if(!path.equals(value)){
				BurpUtils.getInstance().path = value;
				BurpUtils.getInstance().saveConfigs();
				feedback.setText("Executable path saved: " + value);
				return;
			}
			feedback.setText("Executable path not saved.");
		} else if(variable.toLowerCase().equals("header")){
			String header = BurpUtils.getInstance().header;
			if(!header.equals(value)){
				BurpUtils.getInstance().header = value;
				BurpUtils.getInstance().saveConfigs();
				feedback.setText("Header saved: " + header);
				return;
			}
			feedback.setText("Header not saved.");
		}
	}
	
	private void initGui(){		
		this.tab = new JPanel();
		
		GroupLayout layout = new GroupLayout(this.tab); 
		this.tab.setLayout(layout);
		
		layout.setAutoCreateGaps(true);
		layout.setAutoCreateContainerGaps(true);
		
		/* Configuration Layout Creation */
		
		// Executable components
		final JLabel feedbackMsg  = new JLabel();
		feedbackMsg.setFont(new Font("Tahoma", 1, MSG_SIZE));
		
		JLabel requestModifierLabel = new JLabel("Request Modifier Settings");
		requestModifierLabel.setFont(new Font("Tahoma", 1, HEADER_SIZE));
		
		final JTextField executablePathText = new JTextField(BurpUtils.getInstance().path);
		executablePathText.addFocusListener(new FocusListener() {
			@Override
			public void focusLost(FocusEvent e) {
				saveVariable(feedbackMsg, "path", executablePathText.getText());
			}
			
			@Override
			public void focusGained(FocusEvent e) {
				// Nothing to do when focus is gained
			}
		});
		
		JButton executablePathChooseFileButton = new JButton("Choose File");
		executablePathChooseFileButton.addActionListener(new ActionListener() {			
			@Override
			public void actionPerformed(ActionEvent event) {
				JFileChooser chooseFile = new JFileChooser();
				int ret = chooseFile.showDialog(tab, "Choose a file");
				
				if(ret == JFileChooser.APPROVE_OPTION){
					File file = chooseFile.getSelectedFile();
					String path = BurpUtils.getInstance().path;
					try {
						path = file.getCanonicalPath();
					} catch (IOException e) {
						if(BurpUtils.DEBUG)
							e.printStackTrace(BurpUtils.getInstance().stderr);
					}
					executablePathText.setText(path);
					saveVariable(feedbackMsg, "path", path);
				}
				            
			}
		});
				
		JButton executablePathResetPathButton = new JButton("Reset Path");
		executablePathResetPathButton.addActionListener(new ActionListener() {			
			@Override
			public void actionPerformed(ActionEvent event) {
				saveVariable(feedbackMsg, "path", "");
			}
		});
		
		JLabel executablePathTextLabel = new JLabel("Executable Path: ");
		executablePathTextLabel.setFont(new Font("Tahoma", 1, LABEL_SIZE));
		
		
		// Header components
		JLabel headerTextLabel = new JLabel("Request Modification Header: ");
		headerTextLabel.setFont(new Font("Tahoma", 1, LABEL_SIZE));
		
		final JTextField headerText = new JTextField(BurpUtils.getInstance().header);
		headerText.addFocusListener(new FocusListener() {
			@Override
			public void focusLost(FocusEvent e) {
				saveVariable(feedbackMsg, "header", headerText.getText());
			}
			
			@Override
			public void focusGained(FocusEvent e) {
				// Nothing to do when focus is gained
			}
		});
		
		final JCheckBox headerActiveCheckBox = new JCheckBox("Check to run the modification script on all Scanner, Repeater and Intruder requests.");
		headerActiveCheckBox.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				if(headerActiveCheckBox.isSelected()){
					BurpUtils.getInstance().header = "";
					BurpUtils.getInstance().saveConfigs();
					headerText.setText("");
					feedbackMsg.setText("Modifying all requests sent through Sanner, Repeater and Intruder.");
				} else { 
					BurpUtils.getInstance().header = BurpUtils.DEFAULT_HEADER;
					BurpUtils.getInstance().saveConfigs();
					headerText.setText(BurpUtils.DEFAULT_HEADER);
					feedbackMsg.setText("Modifying requests with '" + BurpUtils.getInstance().header + "' header sent through Sanner, Repeater and Intruder.");
				}
			}
		});
		headerActiveCheckBox.setSelected(BurpUtils.getInstance().header == null || BurpUtils.getInstance().header.isEmpty());
		
		
		// Setting layout groups
		ParallelGroup executablePathHorizontalLayout = layout.createParallelGroup(GroupLayout.Alignment.LEADING)
				.addComponent(requestModifierLabel)
				.addGroup(layout.createSequentialGroup()
						.addComponent(executablePathTextLabel)
						.addComponent(executablePathText)
						.addComponent(executablePathChooseFileButton)
						.addComponent(executablePathResetPathButton)
				)
				.addGroup(layout.createSequentialGroup()
						.addComponent(headerTextLabel)
						.addComponent(headerText)
				)
				.addComponent(headerActiveCheckBox)
				.addComponent(feedbackMsg);

		SequentialGroup executablePathVertialLayout = layout.createSequentialGroup()
				.addComponent(requestModifierLabel)
				.addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
						.addComponent(executablePathTextLabel)
						.addComponent(executablePathText)
						.addComponent(executablePathChooseFileButton)
						.addComponent(executablePathResetPathButton)
				)
				.addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
						.addComponent(headerTextLabel)
						.addComponent(headerText)	
				)
				.addComponent(headerActiveCheckBox)
				.addComponent(feedbackMsg);
		
		

		/* Final Layout */
		
		layout.setHorizontalGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
				.addGap(20, 20, 20)
				.addGroup(executablePathHorizontalLayout)
				/*.addGap(20, 20, 20)
				.addGroup(infoDisclosureHorizontalLayout)
				.addGap(20, 20, 20)
				.addGroup(missingHeadersHorizontalLayout)
				.addGap(20, 20, 20)
				.addGroup(versionCheckerHorizontalLayout)*/
		);
		
		layout.setVerticalGroup(layout.createSequentialGroup()
				.addGap(20, 20, 20)
				.addGroup(executablePathVertialLayout)
				/*.addGap(20, 20, 20)
				.addGroup(infoDisclosureVerticalLayout)
				.addGap(20, 20, 20)
				.addGroup(missingHeadersVerticalLayout)
				.addGap(20, 20, 20)
				.addGroup(versionCheckerVerticalLayout)*/
		);
		
	}
	
	@Override
	public String getTabCaption() {
		return "Request Modification Config";
	}

	@Override
	public Component getUiComponent() {
		return this.tab;
	}

}
