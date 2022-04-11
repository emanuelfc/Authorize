package gui.tabs.usersTab;

import authorize.sessionManagement.CookiesSessionHandler;
import authorize.sessionManagement.HeaderSessionHandler;
import authorize.sessionManagement.SessionHandler;
import authorize.sessionManagement.SessionManager;
import authorize.types.SessionHandlerType;
import authorize.user.User;
import gui.utils.SelectionListener;
import gui.utils.SimpleAbstractTableModel;

@SuppressWarnings("serial")
public class SessionHandlerTableModel extends SimpleAbstractTableModel implements SelectionListener<User>
{
	private static String[] columnNames = {"Enabled", "Type", "Match", "Session", "Description"};
	private static Class<?>[] columnTypes = {Boolean.class, SessionHandlerType.class, String.class, String.class, String.class};
	
	private SessionManager userSessionManager;
	
	public SessionHandlerTableModel()
	{
		super(columnNames, columnTypes);
	}

	@Override
	public Object getValueAt(int row, int col)
	{
		if(this.userSessionManager != null && !this.userSessionManager.getSessionHandlers().isEmpty())
		{
			SessionHandler sessionHandler = this.userSessionManager.getSessionHandlers().get(row);
			
			if(sessionHandler instanceof CookiesSessionHandler)
			{
				switch(col)
				{
					// Enabled
					case 0:
						return sessionHandler.isEnabled();
					
					// Type
					case 1:
						return SessionHandlerType.COOKIES;
						
					// Location
					case 2:
						return SessionHandlerType.COOKIES;
					
					// Session Token
					case 3:
						return sessionHandler.getSession();
						
					// Description
					case 4:
						return sessionHandler.getDescription();
						
					default:
						throw new IllegalArgumentException("Invalid column for CookiesSessionHandler = " + col);
				}
			}
			else if(sessionHandler instanceof HeaderSessionHandler)
			{
				HeaderSessionHandler headerSessionHandler = (HeaderSessionHandler) sessionHandler;
				
				switch(col)
				{
					// Enabled
					case 0:
						return sessionHandler.isEnabled();
					
					// Type
					case 1:
						return SessionHandlerType.HEADER;
						
					// Location
					case 2:
						return headerSessionHandler.getLocation();
					
					// Session Token
					case 3:
						return sessionHandler.getSession();
						
					// Description
					case 4:
						return sessionHandler.getDescription();
						
					default:
						throw new IllegalArgumentException("Invalid column for MatchReplaceSessionHandler = " + col);
				}
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
		if(this.userSessionManager != null && !this.userSessionManager.getSessionHandlers().isEmpty())
		{
			SessionHandler sessionHandler = this.userSessionManager.getSessionHandlers().get(row);
			
			switch(col)
			{
				// Enabled
				case 0:
					sessionHandler.toggleEnable();
					break;
			}
		}
	}
	
	@Override
	public void onSelection(User selectedUser)
	{
		this.userSessionManager = selectedUser != null ? this.userSessionManager = selectedUser.getSessionManager() : null;
		this.fireTableDataChanged();
	}

	@Override
	public int getRowCount()
	{
		return this.userSessionManager != null ? this.userSessionManager.getSessionHandlers().size() : 0;
	}
	
}
