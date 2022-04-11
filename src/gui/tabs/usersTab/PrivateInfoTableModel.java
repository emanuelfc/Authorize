package gui.tabs.usersTab;

import java.util.List;

import authorize.user.PrivateInfo;
import authorize.user.User;
import gui.utils.SelectionListener;
import gui.utils.SimpleAbstractTableModel;

@SuppressWarnings("serial")
public class PrivateInfoTableModel extends SimpleAbstractTableModel implements SelectionListener<User>
{
	private static String[] columnNames = {"Enabled", "Info", "Regex", "Description"};
	private static Class<?>[] columnTypes = {Boolean.class, String.class, Boolean.class, String.class};
	
	private List<PrivateInfo> privateInfo;
	
	public PrivateInfoTableModel()
	{
		super(columnNames, columnTypes);
		this.privateInfo = null;
	}

	@Override
	public Object getValueAt(int row, int col)
	{
		if(this.privateInfo != null && !this.privateInfo.isEmpty())
		{
			PrivateInfo privateInfo = this.privateInfo.get(row);
			
			switch(col)
			{
				// Enabled
				case 0:
					return privateInfo.isEnabled();
				
				// Info
				case 1:
					return privateInfo.getInfo();
					
				// Regex
				case 2:
					return privateInfo.isRegex();
					
				// Description
				case 3:
					return privateInfo.getDescription();
					
				default:
					return null;
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
		if(this.privateInfo != null)
		{
			PrivateInfo privateInfo = this.privateInfo.get(row);
			
			switch(col)
			{
				// Enabled
				case 0:
					privateInfo.toggleEnable();
					break;
			}
		}
	}

	@Override
	public void onSelection(User selectedUser)
	{
		this.privateInfo = selectedUser != null ? selectedUser.getPrivateInfo() : null;
		this.fireTableDataChanged();
	}

	@Override
	public int getRowCount()
	{
		return this.privateInfo != null ? this.privateInfo.size() : 0;
	}

}
