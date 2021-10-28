package gui;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JComboBox;
import javax.swing.JTextField;

import authorize.modifier.replace.ReplaceModifier;
import authorize.sessionManagement.MatchReplaceSessionHandler;
import authorize.types.ModifierType;
import gui.modifier.ReplaceModifierPanel;
import gui.utils.AbstractEntityPanel;

@SuppressWarnings("serial")
public class RequestSessionHandlerPanel extends AbstractEntityPanel
{
	public static final ModifierType[] replaceModifierTypes = {ModifierType.MATCH_REPLACE_BODY, ModifierType.MATCH_REPLACE_COOKIE, 
			ModifierType.MATCH_REPLACE_HEADER_VALUE, ModifierType.MATCH_REPLACE_JSON_PARAM, 
			ModifierType.MATCH_REPLACE_REQUEST, ModifierType.MATCH_REPLACE_URL_PARAM, 
			ModifierType.MATCH_REPLACE_URL_PARAM_BODY};
	
	private JComboBox<ModifierType> replaceModifierTypeComboBox;
	private ReplaceModifierPanel replaceModifierPanel;
	
	private JTextField descriptionField;
	
	public RequestSessionHandlerPanel(ModifierType sessionModifierType, ReplaceModifier sessionModifier, String description)
	{
		super();
		this.setLayout(new GridBagLayout());
		
		GridBagConstraints gbc = super.createBaseConstraints();
		gbc.gridwidth = 2;
		
		this.replaceModifierTypeComboBox = new JComboBox<ModifierType>(replaceModifierTypes);
		super.addLabeledComponent("Type:", this.replaceModifierTypeComboBox);
		if(sessionModifier != null)
		{
			this.replaceModifierTypeComboBox.setSelectedItem(sessionModifierType);
			this.replaceModifierTypeComboBox.setEditable(false);
			this.replaceModifierPanel = new ReplaceModifierPanel(sessionModifierType, sessionModifier.getMatch(), sessionModifier.isRegex(), sessionModifier.getReplace());
		}
		else
		{
			this.replaceModifierPanel = new ReplaceModifierPanel((ModifierType) this.replaceModifierTypeComboBox.getSelectedItem());
		}
		
		super.addComponent(this.replaceModifierPanel, gbc);
		
		this.replaceModifierTypeComboBox.addActionListener(new ActionListener()
		{

			@Override
			public void actionPerformed(ActionEvent e)
			{			
				RequestSessionHandlerPanel.this.replaceModifierPanel.setType((ModifierType) RequestSessionHandlerPanel.this.replaceModifierTypeComboBox.getSelectedItem());
			}
			
		});
		
		 this.descriptionField = this.replaceModifierPanel.addLabeledTextField("Description:", description);
	}
	
	public RequestSessionHandlerPanel(MatchReplaceSessionHandler requestSessionHandler)
	{
		this(requestSessionHandler.getSessionModifierType(), requestSessionHandler.getSessionModifier(), requestSessionHandler.getDescription());
	}
	
	public RequestSessionHandlerPanel()
	{
		this(null, null, "");
	}
	
	public MatchReplaceSessionHandler create()
	{	
		return new MatchReplaceSessionHandler((ModifierType) this.replaceModifierTypeComboBox.getSelectedItem(), (ReplaceModifier) this.replaceModifierPanel.createModifier(), null, this.descriptionField.getText(), false);
	}
	
	public void edit(MatchReplaceSessionHandler requestSessionHandler)
	{
		this.replaceModifierPanel.editModifier(requestSessionHandler.getSessionModifier());
		requestSessionHandler.setSessionModifier(requestSessionHandler.getSessionModifier(), (ModifierType) this.replaceModifierTypeComboBox.getSelectedItem());
		requestSessionHandler.setDescription(this.descriptionField.getText());
	}
}
