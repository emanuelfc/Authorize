package gui.tableModels;

import java.util.List;

import authorize.matcher.MatchRule;
import authorize.types.MatchType;
import authorize.types.RelationshipType;
import gui.utils.ListBasedAbstractTableModel;

@SuppressWarnings("serial")
public class MatchTableModel extends ListBasedAbstractTableModel<MatchRule>
{
	private static String[] columnNames = {"Enabled", "Match Type", "Relationship", "Match", "Regex", "Description"};
	private static Class<?>[] columnTypes = {Boolean.class, MatchType.class, RelationshipType.class, String.class, String.class, String.class};
	
	public MatchTableModel(List<MatchRule> matchRules)
	{
		super(columnNames, columnTypes, matchRules);
	}

	@Override
	public Object getValueAt(int row, int col)
	{
		MatchRule matchRule = super.list.get(row);
		
		switch(col)
		{
			// Enabled
			case 0:
				return matchRule.isEnabled();
			
			// Location / Item
			case 1:
				return matchRule.getMatchType();
				
			// Relationship
			case 2:
				if(matchRule.getRelationship()) return RelationshipType.MATCH.toString();
				else return RelationshipType.DONT_MATCH.toString();
				
			// Match
			case 3:
				return matchRule.getMatcher().getMatch();
			
			// Regex
			case 4:
				return matchRule.getMatcher().isRegex();

			// Description
			case 5:
				return matchRule.getDescription();
				
			default:
				throw new IllegalArgumentException("Invalid column = " + col);
		}
	}
	
	@Override
	public boolean isCellEditable(int row, int col)
	{
		return col == 0;
	}
	
	public void setValueAt(Object val, int row, int col)
	{
		if(super.list != null)
		{
			MatchRule matchRule = super.list.get(row);
			
			if(col == 0) matchRule.toggleEnable();
		}
	}
}
