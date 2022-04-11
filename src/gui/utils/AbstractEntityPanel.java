package gui.utils;

import java.awt.Component;
import java.awt.GridBagConstraints;
import java.awt.Insets;

import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;

@SuppressWarnings("serial")
public class AbstractEntityPanel extends JPanel
{
	public void addComponent(Component c)
	{
		GridBagConstraints gbc = this.createBaseConstraints();
		
		gbc.gridy = this.getComponentCount();
		gbc.gridx = 0;
		this.add(c, gbc);
	}
	
	public void addComponent(Component c, int x, int y)
	{
		GridBagConstraints gbc = this.createBaseConstraints();
		
		gbc.gridx = x;
		gbc.gridy = y;
		this.add(c, gbc);
	}
	
	public void addComponent(Component c, GridBagConstraints gbc)
	{
		gbc.gridy = this.getComponentCount();
		this.add(c, gbc);
	}
	
	public void addPairComponent(Component c1, Component c2)
	{
		GridBagConstraints gbc = this.createBaseConstraints();
		
		gbc.gridy = this.getComponentCount();
		
		gbc.gridx = 0;
		this.add(c1, gbc);
		
		gbc.weightx = 1;
		gbc.weighty = 0;
		
		gbc.gridx = 1;
		this.add(c2, gbc);
	}
	
	public GridBagConstraints createBaseConstraints()
	{
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.anchor = GridBagConstraints.WEST;
		gbc.fill = GridBagConstraints.NONE;
		gbc.insets = new Insets(0, 0, 5, 10);
		gbc.gridx = 0;
		gbc.gridy = 0;
		return gbc;
	}
	
	public JTextField addLabeledTextField(String labelText, String text)
	{
		JTextField textField = new JTextField(text, 20);
		this.addLabeledComponent(labelText, textField);
		return textField;
	}
	
	public void addLabeledComponent(String labelText, Component c)
	{
		JLabel label = new JLabel(labelText);
		this.addPairComponent(label, c);
	}
}
