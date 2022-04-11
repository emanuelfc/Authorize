package gui;

import java.awt.GridBagLayout;
import javax.swing.JTextField;

import authorize.sessionManagement.HeaderSessionHandler;
import gui.utils.AbstractEntityPanel;

@SuppressWarnings("serial")
public class HeaderSessionHandlerPanel extends AbstractEntityPanel
{
	private JTextField headerField;
	private JTextField sessionField;
	private JTextField descriptionField;
	
	public HeaderSessionHandlerPanel(String header, String session, String description)
	{
		super();
		this.setLayout(new GridBagLayout());
		
		this.headerField = super.addLabeledTextField("Header:", header);
		this.sessionField = super.addLabeledTextField("Value:", session);
		this.descriptionField = super.addLabeledTextField("Description:", description);
	}
	
	public HeaderSessionHandlerPanel(HeaderSessionHandler headerSessionHandler)
	{
		this(headerSessionHandler.getLocation(), headerSessionHandler.getSession(), headerSessionHandler.getDescription());
	}
	
	public HeaderSessionHandlerPanel()
	{
		this("", "", "");
	}
	
	public HeaderSessionHandler create()
	{	
		return new HeaderSessionHandler(this.headerField.getText(), this.sessionField.getText(), this.descriptionField.getText(), true);
	}
	
	public void edit(HeaderSessionHandler headerSessionHandler)
	{
		headerSessionHandler.setLocation(this.headerField.getText());
		headerSessionHandler.setSession(this.sessionField.getText());
		headerSessionHandler.setDescription(this.descriptionField.getText());
	}
}
