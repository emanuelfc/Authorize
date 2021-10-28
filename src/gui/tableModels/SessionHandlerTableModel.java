package gui.tableModels;

import java.util.List;

import authorize.principal.Principal;
import authorize.sessionManagement.CookiesSessionHandler;
import authorize.sessionManagement.MatchReplaceSessionHandler;
import authorize.sessionManagement.SessionHandler;
import authorize.sessionManagement.SessionHandlerType;
import gui.utils.ListBasedAbstractTableModel;
import gui.utils.SelectionListener;

@SuppressWarnings("serial")
public class SessionHandlerTableModel extends ListBasedAbstractTableModel<SessionHandler> implements SelectionListener<Principal>
{
	private static String[] columnNames = {"Enabled", "Type", "Match", "Session", "Regex", "Description"};
	private static Class<?>[] columnTypes = {Boolean.class, SessionHandlerType.class, String.class, String.class, String.class, String.class};
	
	private Principal selectedPrincipal;
	
	public SessionHandlerTableModel(List<SessionHandler> sessionHandlers)
	{
		super(columnNames, columnTypes, sessionHandlers);
		this.selectedPrincipal = null;
	}
	
	public SessionHandlerTableModel()
	{
		this(null);
	}

	@Override
	public Object getValueAt(int row, int col)
	{
		if(super.list != null && !super.list.isEmpty())
		{
			SessionHandler sessionHandler = super.list.get(row);
			
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
						
					// Match
					case 2:
						return SessionHandlerType.COOKIES;
					
					// Replace
					case 3:
						return sessionHandler.getSession();
						
					// Regex
					case 4:
						return false;
						
					// Description
					case 5:
						return sessionHandler.getDescription();
						
					default:
						throw new IllegalArgumentException("Invalid column for CookiesSessionHandler = " + col);
				}
			}
			else if(sessionHandler instanceof MatchReplaceSessionHandler)
			{
				MatchReplaceSessionHandler matchReplaceSessionHandler = (MatchReplaceSessionHandler) sessionHandler;
				
				switch(col)
				{
					// Enabled
					case 0:
						return sessionHandler.isEnabled();
					
					// Type
					case 1:
						return matchReplaceSessionHandler.toString();
						
					// Match
					case 2:
						return matchReplaceSessionHandler.getSessionModifier().getMatch();
					
					// Replace
					case 3:
						return sessionHandler.getSession();
						
					// Regex
					case 4:
						return matchReplaceSessionHandler.getSessionModifier().isRegex();
						
					// Description
					case 5:
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
		if(super.list != null)
		{
			SessionHandler sessionHandler = super.list.get(row);
			
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
	public void fireTableDataChanged()
	{
		if(this.selectedPrincipal != null)
		{
			super.list = this.selectedPrincipal.getSessionManager().getSessionHandlers();
		}
		
		super.fireTableDataChanged();
	}
	
	@Override
	public void onSelection(Principal selectedPrincipal)
	{
		this.selectedPrincipal = selectedPrincipal;
		List<SessionHandler> newSessionHandlerList = selectedPrincipal != null ? selectedPrincipal.getSessionManager().getSessionHandlers() : null;
		super.setList(newSessionHandlerList);
	}
	
}
