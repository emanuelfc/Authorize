package gui.tabs.usersTab;

import java.awt.event.ActionEvent;
import java.util.List;
import javax.swing.JOptionPane;
import javax.swing.JTable;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;

import authorize.user.User;
import authorize.user.UsersManager;
import burp.BurpExtender;
import gui.UserPanel;
import gui.utils.MovableEntityTableController;

@SuppressWarnings("serial")
public class UsersController extends MovableEntityTableController<User>
{
	private UsersManager usersManager;
	
	public UsersController()
	{
		super(new UsersTableModel());
		
		this.usersManager = BurpExtender.instance.getAuthorize().getUserManager();
	}
	
	@Override
	public List<User> getEntries()
	{
		return this.usersManager.getOrderedUsers();
	}
	
	protected boolean addAction(ActionEvent e)
	{
		UserPanel userPanel = new UserPanel();
		
		int result = JOptionPane.showConfirmDialog(null, userPanel, "Add User", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
		
		if(result == JOptionPane.OK_OPTION)
		{
			this.usersManager.addUser(userPanel.getUsername());
			super.tableModel.fireTableDataChanged();
			
			return true;
		}
		
		return false;
	}
	
	protected boolean editAction(ActionEvent e)
	{
		if(this.selection != null)
		{
			UserPanel userPanel = new UserPanel(this.selection);
			
			int result = JOptionPane.showConfirmDialog(null, userPanel, "Edit User", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
			
			if(result == JOptionPane.OK_OPTION)
			{
				if(!userPanel.getUsername().equals(this.selection.getName()))
				{
					this.usersManager.editUserName(this.selection.getName(), userPanel.getUsername());
					return true;
				}
			}
		}
		else JOptionPane.showMessageDialog(null, "Please select a User to edit!");
		
		return false;
	}
	
	protected boolean removeAction(ActionEvent e)
	{
		if(this.selection != null)
		{
			if(this.usersManager.removeUser(this.selection.getName()) != null)
			{
				super.setSelectedEntry(null);
				super.tableModel.fireTableDataChanged();
				
				return true;
			}
		}
		else JOptionPane.showMessageDialog(null, "Please select a User to remove!");
		
		return false;
	}

	@Override
	protected void moveUpAction(ActionEvent e)
	{
		int oldIndex = this.usersManager.getOrderedUsers().indexOf(this.selection);
		this.usersManager.setUserOrder(this.selection, oldIndex - 1);
	}

	@Override
	protected void moveDownAction(ActionEvent e)
	{
		int oldIndex = this.usersManager.getOrderedUsers().indexOf(this.selection);
		this.usersManager.setUserOrder(this.selection, oldIndex + 1);
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
	}
}
