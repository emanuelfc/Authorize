package gui.modifier;

import java.awt.GridBagLayout;

import javax.swing.JTextField;

import authorize.modifier.Modifier;
import authorize.modifier.add.AddHeaderModifier;

@SuppressWarnings("serial")
public class AddHeaderModifierPanel extends ModifierPanel
{
	private JTextField headerField;
	
	public AddHeaderModifierPanel(String header)
	{
		super();
		
		this.setLayout(new GridBagLayout());
		
		this.headerField = super.addLabeledTextField("Header:", header);
	}
	
	public AddHeaderModifierPanel(AddHeaderModifier modifier)
	{
		this(modifier.getHeader());
	}
	
	public AddHeaderModifierPanel()
	{
		this("");
	}

	@Override
	public Modifier createModifier()
	{
		return new AddHeaderModifier(this.headerField.getText());
	}

	@Override
	public void editModifier(Modifier modifier)
	{
		AddHeaderModifier addHeaderModifier = (AddHeaderModifier) modifier;
		
		addHeaderModifier.setHeader(this.headerField.getText());
	}
}
