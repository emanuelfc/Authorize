package gui;

import java.awt.GridBagLayout;

import javax.swing.JCheckBox;
import javax.swing.JTextField;

import authorize.user.PrivateInfo;
import gui.utils.AbstractEntityPanel;

@SuppressWarnings("serial")
public class PrivateInfoPanel extends AbstractEntityPanel
{
	private JTextField info;
	private JCheckBox isRegex;
	private JTextField description;
	
	public PrivateInfoPanel(String info, boolean isRegex, String description)
	{
		super();
		this.setLayout(new GridBagLayout());
		
		this.info = super.addLabeledTextField("Info:", info);
		
		this.isRegex = new JCheckBox("Regex Match");
		this.isRegex.setSelected(isRegex);
		super.addComponent(this.isRegex, 1, this.getComponentCount());
		
		this.description = super.addLabeledTextField("Description:", description);
	}
	
	public PrivateInfoPanel(PrivateInfo privateInfo)
	{
		this(privateInfo.getInfo(), privateInfo.isRegex(), privateInfo.getDescription());
	}
	
	public PrivateInfoPanel()
	{
		this("", false, "");
	}
	
	public PrivateInfo create()
	{
		return new PrivateInfo(this.info.getText(), this.isRegex.isSelected(), this.description.getText(), true);
	}
	
	public void edit(PrivateInfo privateInfo)
	{
		privateInfo.setInfo(this.info.getText());
		privateInfo.setRegex(this.isRegex.isSelected());
		privateInfo.setDescription(this.description.getText());
	}
}