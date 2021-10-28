package gui.tableModels;

import java.util.List;

import authorize.modifier.ModifierRule;
import gui.utils.ListBasedAbstractTableModel;

@SuppressWarnings("serial")
public abstract class ModifierRuleTableModel extends ListBasedAbstractTableModel<ModifierRule>
{
	private static String[] columnNames = {"Enabled", "Type", "Description"};
	private static Class<?>[] columnTypes = {Boolean.class, String.class, String.class};
	
	public ModifierRuleTableModel(List<ModifierRule> modifiers)
	{
		super(columnNames, columnTypes, modifiers);
	}
	
	public ModifierRuleTableModel()
	{
		this(null);
	}

	@Override
	public Object getValueAt(int row, int col)
	{
		if(super.list != null && !super.list.isEmpty())
		{
			ModifierRule modifier = super.list.get(row);
			
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
		if(super.list != null)
		{
			ModifierRule modifier = super.list.get(row);
			
			if(col == 0) modifier.toggleEnable();
		}
	}
	
}
