package gui.tabs.usersTab;

import authorize.user.User;
import authorize.user.UsersManager;
import burp.BurpExtender;
import gui.utils.SimpleAbstractTableModel;

@SuppressWarnings("serial")
public class UsersTableModel extends SimpleAbstractTableModel
{
	private static String[] columnNames = {"Enabled", "Name"};
	private static Class<?>[] columnTypes = {Boolean.class, String.class};
	
	private UsersManager usersManager;
	
	public UsersTableModel()
	{
		super(columnNames, columnTypes);
		
		this.usersManager = BurpExtender.instance.getAuthorize().getUserManager();
	}

	@Override
	public int getRowCount()
	{
		return this.usersManager.getOrderedUsers().size();
	}

	@Override
	public Object getValueAt(int row, int col)
	{		
		if(this.getRowCount() > row && col < 2)
		{
			User user = this.usersManager.getOrderedUsers().get(row);
			
			if(user != null)
			{
				switch(col)
				{
					case 0:
						return user.isEnabled();
						
					case 1:
						return user.getName();
					
					default:
						return null;
				}
			}
		}
		
		return null;
	}

	public boolean isCellEditable(int row, int col)
	{
		return col == 0 || col == 2;
	}
	
	public void setValueAt(Object val, int row, int col)
	{
		if(col == 0)
		{
			this.usersManager.getOrderedUsers().get(row).toggleEnable();
		}
	}
	
	@Override
	public void fireTableDataChanged()
	{
		super.fireTableDataChanged();
		BurpExtender.instance.getView().getProxyTab().getTable().getModel().fireTableStructureChanged();
	}
}
