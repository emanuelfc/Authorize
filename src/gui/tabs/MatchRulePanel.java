package gui.tabs;

import java.awt.GridBagLayout;

import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JTextField;

import authorize.interception.MatchRule;
import authorize.interception.InterceptionRuleFactory;
import authorize.types.MatchType;
import authorize.types.RelationshipType;
import gui.utils.AbstractEntityPanel;

@SuppressWarnings("serial")
public class MatchRulePanel extends AbstractEntityPanel
{
	private JComboBox<MatchType> matchType;
	private JTextField condition;
	private JCheckBox isRegex;
	private JComboBox<RelationshipType> relationship;
	private JTextField description;
	
	public MatchRulePanel(MatchType[] matchTypes, MatchType type, boolean relationship, String match, boolean isRegex, String description)
	{
		super();
		this.setLayout(new GridBagLayout());
		
		this.matchType = new JComboBox<MatchType>(matchTypes);
		if(type != null) this.matchType.setSelectedItem(type);
		super.addLabeledComponent("Location:", this.matchType);
		
		this.relationship = new JComboBox<RelationshipType>(RelationshipType.values());
		this.relationship.setSelectedItem(relationship ? RelationshipType.MATCH : RelationshipType.DONT_MATCH);
		super.addLabeledComponent("Relationship:", this.relationship);
		
		this.condition = super.addLabeledTextField("Match:", match);
		
		this.isRegex = new JCheckBox("Regex Match");
		this.isRegex.setSelected(isRegex);
		super.addComponent(this.isRegex, 1, this.getComponentCount());
		
		this.description = super.addLabeledTextField("Description:", description);
	}
	
	public MatchRulePanel(MatchType[] matchTypes, MatchRule matchRule)
	{
		this(matchTypes, matchRule.getMatchType(), matchRule.getRelationship(), matchRule.getCondition(), matchRule.isRegex(), matchRule.getDescription());
	}
	
	public MatchRulePanel(MatchType[] matchTypes)
	{
		this(matchTypes, null, true, "", false, "");
	}
	
	public MatchRule create()
	{
		return InterceptionRuleFactory.createMatchRule((MatchType) this.matchType.getSelectedItem(), this.condition.getText(), ((RelationshipType)this.relationship.getSelectedItem()).getRelationship(), this.isRegex.isSelected(), this.description.getText(), ((RelationshipType) this.relationship.getSelectedItem()).getRelationship());
	}
	
	public void edit(MatchRule matchRule)
	{
		matchRule.setDescription(this.description.getText());
		matchRule.setRelationship(((RelationshipType) this.relationship.getSelectedItem()).getRelationship());
		matchRule.setCondition(this.condition.getText());
		matchRule.setRegex(this.isRegex.isSelected());
		matchRule.setMatchFunction((MatchType) this.matchType.getSelectedItem());
	}
}
