package gui;

import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;

import javax.swing.JTextField;

import burp.BurpExtender;
import burp.IMessageEditor;
import gui.controllerPanels.MessageEditorController;
import gui.utils.AbstractEntityPanel;

@SuppressWarnings("serial")
public class ReplaceFromResponsePanel extends AbstractEntityPanel
{
	private JTextField requestURLField;
	private JTextField regexMatchField;
	private JTextField extractRegexField;
	private IMessageEditor requestViewer;
	
	public ReplaceFromResponsePanel(String requestURL, String regexMatch, String extractRegex, byte[] request)
	{
		super();
		this.setLayout(new GridBagLayout());
		
		this.requestURLField = super.addLabeledTextField("Request URL:", requestURL);
		this.regexMatchField = super.addLabeledTextField("Replace Regex:", regexMatch);
		this.extractRegexField = super.addLabeledTextField("Extract Regex:", extractRegex);
		
		this.requestViewer = BurpExtender.callbacks.createMessageEditor(new MessageEditorController(), true);
		
		this.requestViewer.getComponent().setPreferredSize(new Dimension(800,600));
		
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.gridwidth = GridBagConstraints.REMAINDER;
		this.addComponent(this.requestViewer.getComponent(), gbc);
	}
	
	public ReplaceFromResponsePanel()
	{
		this("", "", "", null);
	}
	
	public String getRequestURL()
	{
		return this.requestURLField.getText();
	}
	
	public String getReplaceRegex()
	{
		return this.regexMatchField.getText();
	}
	
	public String getExtractRegex()
	{
		return this.extractRegexField.getText();
	}
	
	public byte[] getRequest()
	{
		return requestViewer.getMessage();
	}
}
