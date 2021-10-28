package gui.modifier;

import java.awt.GridBagLayout;

import javax.swing.JCheckBox;
import javax.swing.JTextField;

import authorize.modifier.Modifier;
import authorize.modifier.remove.RemoveHeaderModifier;

@SuppressWarnings("serial")
public class RemoveHeaderModifierPanel extends ModifierPanel
{
	private JTextField headerField;
	private JCheckBox isRegexField;
	
	public RemoveHeaderModifierPanel(String header, boolean isRegex)
	{
		super();
		
		this.setLayout(new GridBagLayout());
		
		this.headerField = super.addLabeledTextField("Header:", header);
		this.isRegexField = new JCheckBox("Regex Match");
		this.isRegexField.setSelected(isRegex);
		super.addComponent(this.isRegexField, 1, this.getComponentCount());
	}
	
	public RemoveHeaderModifierPanel(RemoveHeaderModifier modifier)
	{
		this(modifier.getHeader(), modifier.isRegex());
	}
	
	public RemoveHeaderModifierPanel()
	{
		this("", false);
	}

	@Override
	public Modifier createModifier()
	{
		return new RemoveHeaderModifier(this.headerField.getText(), this.isRegexField.isSelected());
	}

	@Override
	public void editModifier(Modifier modifier)
	{
		RemoveHeaderModifier removeHeaderModifier = (RemoveHeaderModifier) modifier;
		
		removeHeaderModifier.setHeader(this.headerField.getText());
		removeHeaderModifier.setRegex(this.isRegexField.isSelected());
	}
}
