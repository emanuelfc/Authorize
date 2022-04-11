package gui.tabs.configTab;

import authorize.modifier.ModifierRule;
import gui.utils.SimpleAbstractTableModel;

@SuppressWarnings("serial")
public abstract class ModifierRuleTableModel extends SimpleAbstractTableModel
{
	private static String[] columnNames = {"Enabled", "Type", "Description"};
	private static Class<?>[] columnTypes = {Boolean.class, String.class, String.class};
	
	public ModifierRuleTableModel()
	{
		super(columnNames, columnTypes);
	}
	
	protected abstract ModifierRule getEntry(int row, int col);

	@Override
	public Object getValueAt(int row, int col)
	{
		ModifierRule modifier = this.getEntry(row, col);
		
		if(modifier != null)
		{
			switch(col)
			{
				// Enabled
				case 0:
					return modifier.isEnabled();
				
				// Type
				case 1:
					return modifier.toString();
					
				// Description
				case 2:
					return modifier.getDescription();
					
				default:
					throw new IllegalArgumentException("Invalid column = " + col);
			}
		}
			
		return null;
	}
	
	public boolean isCellEditable(int row, int col)
	{
		return col == 0;
	}
	
	public void setValueAt(Object val, int row, int col)
	{
		ModifierRule modifier = this.getEntry(row, col);
		
		if(modifier != null)
		{
			if(col == 0) modifier.toggleEnable();
		}
	}
	
}
