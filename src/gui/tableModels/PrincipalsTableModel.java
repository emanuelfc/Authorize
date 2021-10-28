package gui.tableModels;

import java.util.Iterator;

import authorize.principal.Principal;
import burp.BurpExtender;
import gui.utils.SimpleAbstractTableModel;

@SuppressWarnings("serial")
public class PrincipalsTableModel extends SimpleAbstractTableModel
{
	private static String[] columnNames = {"Enabled", "Name"};
	private static Class<?>[] columnTypes = {Boolean.class, String.class};
	
	public PrincipalsTableModel()
	{
		super(columnNames, columnTypes);
	}

	@Override
	public int getRowCount()
	{
		return BurpExtender.instance.getAuthorize().getPrincipals().size();
	}
	
	public Principal getPrincipalByRowIndex(int row)
	{
		Iterator<Principal> iterPrincipals = BurpExtender.instance.getAuthorize().getPrincipals().values().iterator();
		while(row-- > 0)
		{
			iterPrincipals.next();
		}
		
		return iterPrincipals.next();
	}

	@Override
	public Object getValueAt(int row, int col)
	{		
		Principal principal = this.getPrincipalByRowIndex(row);
		
		if(principal != null)
		{
			switch(col)
			{
				case 0:
					return principal.isEnabled();
					
				case 1:
					return principal.getName();
				
				default:
					return null;
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
		Principal principal = this.getPrincipalByRowIndex(row);
		
		switch(col)
		{
			case 0:
				principal.toggleEnable();
				break;
		}
	}
	
	@Override
	public void fireTableDataChanged()
	{
		super.fireTableDataChanged();
		BurpExtender.instance.getView().getProxyTab().getTable().getModel().fireTableStructureChanged();
	}
}
