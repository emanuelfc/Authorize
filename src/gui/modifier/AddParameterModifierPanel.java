package gui.modifier;

import java.awt.GridBagLayout;

import javax.swing.JTextField;

import authorize.modifier.Modifier;
import authorize.modifier.add.AddParameterModifier;

@SuppressWarnings("serial")
public class AddParameterModifierPanel extends ModifierPanel
{
	private JTextField keyField, valueField;
	private byte paramType;
	
	public AddParameterModifierPanel(String key, String value, byte paramType)
	{
		super();
		
		this.setLayout(new GridBagLayout());
		
		this.keyField = super.addLabeledTextField("Name:", key);
		this.valueField = super.addLabeledTextField("Value:", value);
		
		this.paramType = paramType;
	}
	
	public AddParameterModifierPanel(AddParameterModifier modifier)
	{
		this(modifier.getKey(), modifier.getValue(), modifier.getParamType());
	}
	
	public AddParameterModifierPanel(byte paramType)
	{
		this("", "", paramType);
	}

	@Override
	public Modifier createModifier()
	{
		return new AddParameterModifier(this.keyField.getText(), this.valueField.getText(), this.paramType);
	}

	@Override
	public void editModifier(Modifier modifier)
	{
		AddParameterModifier addParameterModifier = (AddParameterModifier) modifier;
		
		addParameterModifier.setKey(this.keyField.getText());
		addParameterModifier.setValue(this.valueField.getText());
		addParameterModifier.setParamType(this.paramType);
	}
}
