package gui.tabs.usersTab;

import java.awt.event.ActionEvent;
import java.util.List;

import javax.swing.JOptionPane;
import javax.swing.JTable;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;

import authorize.sessionManagement.CookiesSessionHandler;
import authorize.sessionManagement.HeaderSessionHandler;
import authorize.sessionManagement.SessionHandler;
import authorize.sessionManagement.SessionManager;
import authorize.user.User;
import burp.BurpExtender;
import gui.HeaderSessionHandlerPanel;
import gui.utils.AdjustableConfirmDialog;
import gui.utils.EntityTableController;
import gui.utils.SelectionListener;

@SuppressWarnings("serial")
public class SessionManagerPanel extends EntityTableController<SessionHandler> implements SelectionListener<User>
{
	private SessionManager userSessionManager;
	
	public SessionManagerPanel()
	{
		super(new SessionHandlerTableModel());
		
		this.userSessionManager = null;
	}
	
	@Override
	public List<SessionHandler> getEntries()
	{
		return SessionManagerPanel.this.userSessionManager.getSessionHandlers();
	}
	
	@Override
	public void onSelection(User selectedEntry)
	{
		if(selectedEntry != null)
		{
			this.userSessionManager = selectedEntry.getSessionManager();
			((SessionHandlerTableModel)super.tableModel).onSelection(selectedEntry);
		}
		else this.userSessionManager = null;
		
		super.setSelectedEntry(null);
	}

	protected boolean addAction(ActionEvent e)
	{
		if(this.userSessionManager != null)
		{
			HeaderSessionHandlerPanel headerSessionHandlerPanel = new HeaderSessionHandlerPanel();
			BurpExtender.callbacks.customizeUiComponent(headerSessionHandlerPanel);

			int result = AdjustableConfirmDialog.showAdjustableConfirmDialog(null, headerSessionHandlerPanel, "Add Header Session Handler", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
			
			if(result == JOptionPane.OK_OPTION)
			{
				this.userSessionManager.addSessionHandler(headerSessionHandlerPanel.create());				
				super.tableModel.fireTableDataChanged();
				
				return true;
			}
		}
		else JOptionPane.showMessageDialog(null, "Please select a User to add a Session Handler!");
		
		return false;
	}
	
	protected boolean editAction(ActionEvent e)
	{
		if(this.selection != null && this.userSessionManager != null)
		{
			if(this.selection instanceof CookiesSessionHandler)
			{
				CookieSessionHandlerPanel cookieSessionHandlerPanel = new CookieSessionHandlerPanel((CookiesSessionHandler)this.selection);
				BurpExtender.callbacks.customizeUiComponent(cookieSessionHandlerPanel);
				
				int result = JOptionPane.showConfirmDialog(null, cookieSessionHandlerPanel, "Edit Cookie Session Handler", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
				
				if(result == JOptionPane.OK_OPTION)
				{
					this.userSessionManager.getCookieSessionHandler().setSession(cookieSessionHandlerPanel.getCookies());
					super.tableModel.fireTableDataChanged();
					
					return true;
				}
			}
			else if(this.selection instanceof HeaderSessionHandler)
			{
				HeaderSessionHandlerPanel headerSessionHandlerPanel = new HeaderSessionHandlerPanel((HeaderSessionHandler)this.selection);
				BurpExtender.callbacks.customizeUiComponent(headerSessionHandlerPanel);
				
				int result = AdjustableConfirmDialog.showAdjustableConfirmDialog(null, headerSessionHandlerPanel, "Edit Match & Replace Session Handler", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
				
				if(result == JOptionPane.OK_OPTION)
				{
					headerSessionHandlerPanel.edit((HeaderSessionHandler)this.selection);
					super.tableModel.fireTableDataChanged();
					
					return true;
				}
			}
			
		}
		else JOptionPane.showMessageDialog(null, "Please select a Session Handler to edit!");
		
		return false;
	}
	
	@Override
	protected boolean removeAction(ActionEvent e)
	{
		if(this.selection != null && this.userSessionManager != null)
		{
			if(this.selection instanceof HeaderSessionHandler)
			{
				if(this.userSessionManager.removeSessionHandler(this.selection))
				{
					super.setSelectedEntry(null);
					super.tableModel.fireTableDataChanged();
					
					return true;
				}
			}
		}
		else JOptionPane.showMessageDialog(null, "Please select a Session Handler to remove!");
		
		return false;
	}
	
	@Override
	protected void customizeTable()
	{
		super.table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
		
		TableColumnModel columnModel = super.table.getColumnModel();
		
		TableColumn enabledColumn = columnModel.getColumn(0);
		enabledColumn.setMinWidth(70);
		enabledColumn.setMaxWidth(70);
		
		columnModel.getColumn(1).setPreferredWidth(50);
		//columnModel.getColumn(2).setPreferredWidth(300);
	}
}
