package gui.modifier;

import java.awt.GridBagLayout;

import javax.swing.JCheckBox;
import javax.swing.JTextField;

import authorize.modifier.Modifier;
import authorize.modifier.remove.RemoveParameterModifier;

@SuppressWarnings("serial")
public class RemoveParameterModifierPanel extends ModifierPanel
{
	private JTextField paramNameField;
	private JCheckBox isRegexField;
	private byte paramType;
	
	public RemoveParameterModifierPanel(String paramName, boolean isRegex, byte paramType)
	{
		super();
		
		this.setLayout(new GridBagLayout());
		
		this.paramNameField = super.addLabeledTextField("Name:", paramName);
		this.isRegexField = new JCheckBox("Regex Match");
		this.isRegexField.setSelected(isRegex);
		super.addComponent(this.isRegexField, 1, this.getComponentCount());
		
		this.paramType = paramType;
	}
	
	public RemoveParameterModifierPanel(RemoveParameterModifier modifier)
	{
		this(modifier.getMatch(), modifier.isRegex(), modifier.getParamType());
	}
	
	public RemoveParameterModifierPanel(byte paramType)
	{
		this("", false, paramType);
	}

	@Override
	public Modifier createModifier()
	{
		return new RemoveParameterModifier(this.paramNameField.getText(), this.isRegexField.isSelected(), this.paramType);
	}

	@Override
	public void editModifier(Modifier modifier)
	{
		RemoveParameterModifier removeParameterModifier = (RemoveParameterModifier) modifier;
		
		removeParameterModifier.setMatch(this.paramNameField.getText());
		removeParameterModifier.setRegex(this.isRegexField.isSelected());
		removeParameterModifier.setParamType(this.paramType);
	}
}
