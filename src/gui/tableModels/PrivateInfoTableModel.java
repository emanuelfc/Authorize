package gui.tableModels;

import java.util.List;

import authorize.principal.Principal;
import authorize.principal.PrivateInfo;
import gui.utils.ListBasedAbstractTableModel;
import gui.utils.SelectionListener;

@SuppressWarnings("serial")
public class PrivateInfoTableModel extends ListBasedAbstractTableModel<PrivateInfo> implements SelectionListener<Principal>
{
	private static String[] columnNames = {"Enabled", "Info", "Regex", "Description"};
	private static Class<?>[] columnTypes = {Boolean.class, String.class, Boolean.class, String.class};
	
	public PrivateInfoTableModel(List<PrivateInfo> privateInfo)
	{
		super(columnNames, columnTypes, privateInfo);
	}
	
	public PrivateInfoTableModel()
	{
		this(null);
	}

	@Override
	public Object getValueAt(int row, int col)
	{
		if(super.list != null && !super.list.isEmpty())
		{
			PrivateInfo privateInfo = super.list.get(row);
			
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
		if(super.list != null)
		{
			PrivateInfo privateInfo = super.list.get(row);
			
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
	public void onSelection(Principal selectedPrincipal)
	{
		List<PrivateInfo> newPrivateInfoList = selectedPrincipal != null ? selectedPrincipal.getPrivateInfo() : null;
		super.setList(newPrivateInfoList);
	}

}
