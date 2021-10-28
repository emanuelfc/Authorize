package gui.sessionManagement;

import java.awt.event.ActionEvent;
import java.util.List;

import javax.swing.JOptionPane;
import javax.swing.JTable;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;

import authorize.principal.Principal;
import authorize.sessionManagement.CookiesSessionHandler;
import authorize.sessionManagement.MatchReplaceSessionHandler;
import authorize.sessionManagement.SessionHandler;
import authorize.sessionManagement.SessionManager;
import burp.BurpExtender;
import gui.tableModels.SessionHandlerTableModel;
import gui.utils.AdjustableConfirmDialog;
import gui.utils.EntryControllerPanel;
import gui.utils.SelectionListener;

@SuppressWarnings("serial")
public class SessionManagerPanel extends EntryControllerPanel<SessionHandler> implements SelectionListener<Principal>
{
	public static final String SESSION_HANDLER_TABLE_NAME = "Session Handlers";
	
	private SessionManager principalSessionManager;
	
	public SessionManagerPanel()
	{
		super(null, new SessionHandlerTableModel(), SESSION_HANDLER_TABLE_NAME);
		
		this.table.getSelectionModel().addListSelectionListener(new EntrySelectionListener()
		{

			@Override
			public List<SessionHandler> getEntriesList()
			{
				return SessionManagerPanel.this.principalSessionManager.getSessionHandlers();
			}
	
		});
		
		this.principalSessionManager = null;
	}
	
	@Override
	public void onSelection(Principal selectedEntry)
	{
		if(selectedEntry != null)
		{
			this.principalSessionManager = selectedEntry.getSessionManager();
			((SessionHandlerTableModel)super.tableModel).onSelection(selectedEntry);
		}
		else this.principalSessionManager = null;
		
		super.setSelectedEntry(null);
	}

	protected void addAction(ActionEvent e)
	{
		if(this.principalSessionManager != null)
		{
			MatchReplaceSessionHandlerPanel matchReplaceSessionHandlerPanel = new MatchReplaceSessionHandlerPanel();
			BurpExtender.callbacks.customizeUiComponent(matchReplaceSessionHandlerPanel);

			int result = AdjustableConfirmDialog.showAdjustableConfirmDialog(null, matchReplaceSessionHandlerPanel, "Add Match & Replace Session Handler", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
			
			if(result == JOptionPane.OK_OPTION)
			{
				this.principalSessionManager.addSessionHandler(matchReplaceSessionHandlerPanel.create());
				
				this.elements = this.principalSessionManager.getSessionHandlers();
				
				super.tableModel.fireTableDataChanged();
			}
		}
		else JOptionPane.showMessageDialog(null, "Please select a Principal to add a Session Handler!");
	}
	
	protected void editAction(ActionEvent e)
	{
		if(this.selection != null && this.principalSessionManager != null)
		{
			if(this.selection instanceof CookiesSessionHandler)
			{
				CookieSessionHandlerPanel cookieSessionHandlerPanel = new CookieSessionHandlerPanel((CookiesSessionHandler)this.selection);
				BurpExtender.callbacks.customizeUiComponent(cookieSessionHandlerPanel);
				
				int result = JOptionPane.showConfirmDialog(null, cookieSessionHandlerPanel, "Edit Cookie Session Handler", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
				
				if(result == JOptionPane.OK_OPTION)
				{
					this.principalSessionManager.getCookieSessionHandler().setSession(cookieSessionHandlerPanel.getCookies());
				}
			}
			else if(this.selection instanceof MatchReplaceSessionHandler)
			{
				MatchReplaceSessionHandlerPanel matchReplaceSessionHandlerPanel = new MatchReplaceSessionHandlerPanel((MatchReplaceSessionHandler)this.selection);
				BurpExtender.callbacks.customizeUiComponent(matchReplaceSessionHandlerPanel);
				
				int result = AdjustableConfirmDialog.showAdjustableConfirmDialog(null, matchReplaceSessionHandlerPanel, "Edit Match & Replace Session Handler", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
				
				if(result == JOptionPane.OK_OPTION)
				{
					matchReplaceSessionHandlerPanel.edit((MatchReplaceSessionHandler)this.selection);
				}
			}
			
			super.tableModel.fireTableDataChanged();
		}
		else JOptionPane.showMessageDialog(null, "Please select a Session Handler to edit!");
	}
	
	@Override
	protected void removeAction(ActionEvent e)
	{
		if(this.selection != null && this.principalSessionManager != null)
		{
			if(this.selection instanceof MatchReplaceSessionHandler)
			{
				if(this.principalSessionManager.removeSessionHandler(this.selection))
				{
					super.setSelectedEntry(null);
					super.tableModel.fireTableDataChanged();
				}
			}
		}
		else JOptionPane.showMessageDialog(null, "Please select a Session Handler to remove!");
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
