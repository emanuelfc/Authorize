package gui;

import java.awt.GridBagLayout;

import javax.swing.JTextField;

import authorize.principal.Principal;
import gui.utils.AbstractEntityPanel;

@SuppressWarnings("serial")
public class PrincipalPanel extends AbstractEntityPanel
{
	private JTextField nameField;
	
	public PrincipalPanel(String name)
	{
		super();
		this.setLayout(new GridBagLayout());
		
		this.nameField = super.addLabeledTextField("Name:", name);
	}
	
	public PrincipalPanel(Principal principal)
	{
		this(principal.getName());
		//this.nameField.setEditable(false);
		//this.nameField.setBackground(Color.LIGHT_GRAY);
	}
	
	public PrincipalPanel()
	{
		this("");
	}
	
	// getName is a method of JPanel. Do not override
	public String getPrincipalName()
	{
		return this.nameField.getText();
	}
}
