package gui.modifier;

import java.awt.GridBagLayout;

import javax.swing.JCheckBox;
import javax.swing.JTextField;

import authorize.modifier.Modifier;
import authorize.modifier.replace.ReplaceModifier;
import authorize.modifier.replace.ReplaceModifierFactory;
import authorize.types.ModifierType;

@SuppressWarnings("serial")
public class ReplaceModifierPanel extends ModifierPanel
{
	private JTextField matchField, replaceField;
	private JCheckBox isRegexField;
	private ModifierType type;
	
	public ReplaceModifierPanel(ModifierType type, String match, boolean isRegex, String replace)
	{
		super();
		this.type = type;
		
		this.setLayout(new GridBagLayout());
		
		this.matchField = super.addLabeledTextField("Match:", match);
		
		this.isRegexField = new JCheckBox("Regex Match");
		this.isRegexField.setSelected(isRegex);
		super.addComponent(this.isRegexField, 1, this.getComponentCount());
		
		this.replaceField = super.addLabeledTextField("Replace:", replace);
	}
	
	public ReplaceModifierPanel(ModifierType type, ReplaceModifier modifier)
	{
		this(type, modifier.getMatch(), modifier.isRegex(), modifier.getReplace());
	}
	
	public ReplaceModifierPanel(ModifierType type)
	{
		this(type, "", false, "");
	}
	
	public ModifierType getType()
	{
		return this.type;
	}
	
	public void setType(ModifierType newType)
	{
		this.type = newType;
	}

	@Override
	public Modifier createModifier()
	{
		return ReplaceModifierFactory.createReplaceModifier(this.type, this.matchField.getText(), this.isRegexField.isSelected(), this.replaceField.getText());
	}

	@Override
	public void editModifier(Modifier modifier)
	{
		ReplaceModifier replaceModifier = (ReplaceModifier) modifier;
		
		replaceModifier.setMatch(this.matchField.getText());
		replaceModifier.setRegex(this.isRegexField.isSelected());
		replaceModifier.setReplace(this.replaceField.getText());
	}
}
