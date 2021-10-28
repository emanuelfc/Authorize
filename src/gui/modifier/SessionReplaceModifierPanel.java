package gui.modifier;

import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JComboBox;

import authorize.modifier.Modifier;
import authorize.modifier.replace.ReplaceModifier;
import authorize.types.ModifierType;

@SuppressWarnings("serial")
public class SessionReplaceModifierPanel extends ModifierPanel
{
	private JComboBox<ModifierType> replaceTypeComboBox;
	private ReplaceModifierPanel replaceModifierPanel;
	
	public SessionReplaceModifierPanel(ModifierType type, String match, boolean isRegex, String replace)
	{
		super();
		
		this.setLayout(new GridBagLayout());
		
		this.replaceTypeComboBox = new JComboBox<ModifierType>(ModifierType.values());
		this.replaceTypeComboBox.addActionListener(new ActionListener()
		{

			@Override
			public void actionPerformed(ActionEvent e)
			{
				SessionReplaceModifierPanel.this.replaceModifierPanel.setType((ModifierType) SessionReplaceModifierPanel.this.replaceTypeComboBox.getSelectedItem());
			}
			
		});
		this.addLabeledComponent("Type", this.replaceTypeComboBox);
		
		this.replaceModifierPanel = new ReplaceModifierPanel(type);
		
		this.add(this.replaceModifierPanel);
	}
	
	public SessionReplaceModifierPanel(ModifierType type, ReplaceModifier modifier)
	{
		this(type, modifier.getMatch(), modifier.isRegex(), modifier.getReplace());
	}
	
	public SessionReplaceModifierPanel(ModifierType type)
	{
		this(type, "", false, "");
	}

	@Override
	public Modifier createModifier()
	{
		return this.replaceModifierPanel.createModifier();
	}

	@Override
	public void editModifier(Modifier modifier)
	{
		this.replaceModifierPanel.editModifier(modifier);
	}
}
