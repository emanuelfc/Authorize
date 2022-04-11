package gui.tabs;

import authorize.interception.MatchRule;
import authorize.types.MatchType;
import authorize.types.RelationshipType;
import gui.utils.SimpleAbstractTableModel;

@SuppressWarnings("serial")
public abstract class MatchTableModel extends SimpleAbstractTableModel
{
	private static String[] columnNames = {"Enabled", "Match Type", "Relationship", "Match", "Regex", "Description"};
	private static Class<?>[] columnTypes = {Boolean.class, MatchType.class, RelationshipType.class, String.class, String.class, String.class};
	
	public MatchTableModel()
	{
		super(columnNames, columnTypes);
	}
	
	protected abstract MatchRule getEntry(int row, int col);

	@Override
	public Object getValueAt(int row, int col)
	{
		MatchRule matchRule = this.getEntry(row, col);
		
		if(matchRule != null)
		{
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
					return matchRule.getCondition();
				
				// Regex
				case 4:
					return matchRule.isRegex();

				// Description
				case 5:
					return matchRule.getDescription();
					
				default:
					throw new IllegalArgumentException("Invalid column = " + col);
			}
		}
		
		return null;
	}
	
	public void setValueAt(Object val, int row, int col)
	{
		MatchRule matchRule = this.getEntry(row, col);
		
		if(matchRule != null)
		{
			if(col == 0) matchRule.toggleEnable();
		}
	}
}
