package gui.modifier;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.JComboBox;
import javax.swing.JTextField;

import authorize.modifier.Modifier;
import authorize.modifier.ModifierRule;
import authorize.modifier.add.AddHeaderModifier;
import authorize.modifier.add.AddParameterModifier;
import authorize.modifier.remove.RemoveHeaderModifier;
import authorize.modifier.remove.RemoveParameterModifier;
import authorize.modifier.replace.ReplaceModifier;
import authorize.types.ModifierType;
import authorize.types.ParameterType;
import gui.utils.AbstractEntityPanel;

@SuppressWarnings("serial")
public class ModifierRulePanel extends AbstractEntityPanel
{
	private JComboBox<ModifierType> modifierTypeComboBox;
	private ModifierPanel modifierPanel;
	private JTextField description;
	
	public ModifierRulePanel(ModifierRule modifierRule)
	{
		super();
		this.setLayout(new GridBagLayout());

		this.modifierTypeComboBox = new JComboBox<ModifierType>(ModifierType.values());
		super.addLabeledComponent("Type:", this.modifierTypeComboBox);
		if(modifierRule != null)
		{
			this.modifierTypeComboBox.setSelectedItem(modifierRule.getType());
			this.modifierTypeComboBox.setEditable(false);
			this.modifierPanel = createModifierPanel(modifierRule.getType(), modifierRule.getModifier());
		}
		else
		{
			this.modifierPanel = createModifierPanel((ModifierType) this.modifierTypeComboBox.getSelectedItem());
		}
		
		this.modifierTypeComboBox.addActionListener(new ActionListener()
		{

			@Override
			public void actionPerformed(ActionEvent e)
			{			
				ModifierRulePanel.this.setModifierPanel(ModifierRulePanel.createModifierPanel((ModifierType) ModifierRulePanel.this.modifierTypeComboBox.getSelectedItem()));
			}
			
		});
		
		this.description = new JTextField(modifierRule != null ? modifierRule.getDescription() : "", 20);
		
		this.setModifierPanel(this.modifierPanel);
	}
	
	private void setModifierPanel(ModifierPanel modifierPanel)
	{
		this.remove(this.modifierPanel);
		this.modifierPanel = modifierPanel;
		GridBagConstraints gbc = super.createBaseConstraints();
		gbc.gridwidth = 2;
		this.modifierPanel.addLabeledComponent("Description:", this.description);
		super.addComponent(this.modifierPanel, gbc);
	}
	
	public ModifierRulePanel()
	{
		this(null);
	}
	
	private static final ModifierPanel createModifierPanel(ModifierType type)
	{
		switch(type)
		{			
			case ADD_HEADER:
				return new AddHeaderModifierPanel();
				
			case ADD_COOKIE:
				return new AddParameterModifierPanel(ParameterType.COOKIE.getType());
				
			case ADD_URL_PARAM:
				return new AddParameterModifierPanel(ParameterType.URL.getType());
				
			case ADD_URL_PARAM_BODY:
				return new AddParameterModifierPanel(ParameterType.URL_BODY.getType());
				
			case ADD_JSON_PARAM:
				return new AddParameterModifierPanel(ParameterType.JSON.getType());
			
			case REMOVE_HEADER:
				return new RemoveHeaderModifierPanel();
				
			case REMOVE_COOKIE:
				return new RemoveParameterModifierPanel(ParameterType.COOKIE.getType());
				
			case REMOVE_URL_PARAM:
				return new RemoveParameterModifierPanel(ParameterType.URL.getType());
				
			case REMOVE_URL_PARAM_BODY:
				return new RemoveParameterModifierPanel(ParameterType.URL_BODY.getType());
				
			case REMOVE_JSON_PARAM:
				return new RemoveParameterModifierPanel(ParameterType.JSON.getType());
			
			case MATCH_REPLACE_REQUEST:
			case MATCH_REPLACE_HEADER:
			case MATCH_REPLACE_HEADER_VALUE:
			case MATCH_REPLACE_BODY:
			case MATCH_REPLACE_COOKIE:
			case MATCH_REPLACE_URL_PARAM:
			case MATCH_REPLACE_URL_PARAM_BODY:
			case MATCH_REPLACE_JSON_PARAM:
				return new ReplaceModifierPanel(type);
				
			default:
				throw new IllegalArgumentException("Invalid ModifierType type for createModifierPanel: " + type.toString());
		}
	}
	
	private static final ModifierPanel createModifierPanel(ModifierType type, Modifier modifier)
	{
		switch(type)
		{			
			case ADD_HEADER:
				return new AddHeaderModifierPanel((AddHeaderModifier) modifier);
				
			case ADD_COOKIE:
			case ADD_URL_PARAM:
			case ADD_URL_PARAM_BODY:
			case ADD_JSON_PARAM:
				return new AddParameterModifierPanel((AddParameterModifier) modifier);
			
			case REMOVE_HEADER:
				return new RemoveHeaderModifierPanel((RemoveHeaderModifier) modifier);
				
			case REMOVE_COOKIE:
			case REMOVE_URL_PARAM:
			case REMOVE_URL_PARAM_BODY:
			case REMOVE_JSON_PARAM:
				return new RemoveParameterModifierPanel((RemoveParameterModifier) modifier);
			
			case MATCH_REPLACE_REQUEST:
			case MATCH_REPLACE_HEADER:
			case MATCH_REPLACE_HEADER_VALUE:
			case MATCH_REPLACE_BODY:
			case MATCH_REPLACE_COOKIE:
			case MATCH_REPLACE_URL_PARAM:
			case MATCH_REPLACE_URL_PARAM_BODY:
			case MATCH_REPLACE_JSON_PARAM:
				return new ReplaceModifierPanel(type, (ReplaceModifier) modifier);
				
			default:
				throw new IllegalArgumentException("Invalid ModifierType type for createModifierPanel: " + type.toString());
		}
	}
	
	public ModifierRule createModifierRule()
	{
		return new ModifierRule(this.modifierPanel.createModifier(), (ModifierType) this.modifierTypeComboBox.getSelectedItem(), false, this.description.getText());
	}
	
	public void editModifierRule(ModifierRule modifierRule)
	{
		modifierRule.setDescription(this.description.getText());
		modifierRule.setType((ModifierType) this.modifierTypeComboBox.getSelectedItem());
		
		this.modifierPanel.editModifier(modifierRule.getModifier());
	}
}
