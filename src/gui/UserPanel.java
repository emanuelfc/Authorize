package gui;

import java.awt.GridBagLayout;

import javax.swing.JTextField;

import authorize.user.User;
import gui.utils.AbstractEntityPanel;

@SuppressWarnings("serial")
public class UserPanel extends AbstractEntityPanel
{
	private JTextField nameField;
	
	public UserPanel(String name)
	{
		super();
		this.setLayout(new GridBagLayout());
		
		this.nameField = super.addLabeledTextField("Name:", name);
	}
	
	public UserPanel(User user)
	{
		this(user.getName());
		//this.nameField.setEditable(false);
		//this.nameField.setBackground(Color.LIGHT_GRAY);
	}
	
	public UserPanel()
	{
		this("");
	}
	
	// getName is a method of JPanel. Do not override
	public String getUsername()
	{
		return this.nameField.getText();
	}
}
