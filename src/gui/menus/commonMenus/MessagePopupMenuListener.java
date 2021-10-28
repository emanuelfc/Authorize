package gui.menus.commonMenus;

import java.awt.Point;
import java.util.LinkedList;
import java.util.List;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import javax.swing.JTable;
import javax.swing.event.PopupMenuEvent;
import javax.swing.event.PopupMenuListener;

import authorize.messages.Message;
import authorize.principal.Principal;

public abstract class MessagePopupMenuListener<T extends Message> implements PopupMenuListener
{
	protected JTable table;
	
	public MessagePopupMenuListener(JTable table)
	{	
		this.table = table;
	}
	
	public abstract List<JMenuItem> createMenuItems(MessageContextMenuInvocation<T> invocation);
	
	protected abstract T getMessage(int row);
	protected abstract boolean isPrincipalColumn(int col);
	protected abstract Principal getPrincipalByColIndex(int col);
	protected abstract boolean hasPrincipalMessage(Principal principal, int row);
	
	private MessageContextMenuInvocation<T> createInvocationContext()
	{
		T selectedMessage = null;
		List<T> selectedMessages = new LinkedList<T>();
		Principal selectedPrincipal = null;
		
		// Get selected message and/or principal message
		
		int selectedRow = this.table.getSelectedRow();
		int selectedCol = this.table.getSelectedColumn();

		// Add selected principal messages
		if(this.isPrincipalColumn(selectedCol))
		{
			selectedPrincipal = this.getPrincipalByColIndex(selectedCol);
			
			if(!this.hasPrincipalMessage(selectedPrincipal, selectedRow))
			{
				selectedPrincipal = null;
			}
		}
		
		selectedMessage = this.getMessage(selectedRow);
		
		if(selectedMessage.getMessage() == null)
		{
			selectedMessage = null;
			selectedPrincipal = null;
		}
		
		// Add selected messages
		for(int i = 0; i < this.table.getSelectedRowCount(); i++)
		{
			T curMessage = this.getMessage(this.table.getSelectedRows()[i]);
			
			if(curMessage.getMessage() != null)
			{
				selectedMessages.add(curMessage);
			}
			
		}
		
		return new MessageContextMenuInvocation<T>(selectedMessage, selectedMessages, selectedPrincipal);
	}

	@Override
	public void popupMenuWillBecomeVisible(PopupMenuEvent e)
	{
		JPopupMenu popupMenu = (JPopupMenu)e.getSource();
				
		popupMenu.removeAll();
		
		Point mousePoint = this.table.getMousePosition();
		
		if(mousePoint != null && this.table.rowAtPoint(mousePoint) >= 0 && this.table.columnAtPoint(mousePoint) >= 0 && this.table.getSelectedRow() >= 0 && this.table.getSelectedColumn() >= 0)
		{
			// Add menu items
			for(JMenuItem menuItem: this.createMenuItems(this.createInvocationContext()))
			{
				popupMenu.add(menuItem);
			}
		}
	}

	@Override
	public void popupMenuWillBecomeInvisible(PopupMenuEvent e){}

	@Override
	public void popupMenuCanceled(PopupMenuEvent e){}
	
}
