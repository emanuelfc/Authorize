package gui.tabs.usersTab;

import java.awt.event.ActionEvent;
import java.util.List;

import javax.swing.JOptionPane;
import javax.swing.JTable;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;

import authorize.user.PrivateInfo;
import authorize.user.User;
import burp.BurpExtender;
import gui.PrivateInfoPanel;
import gui.utils.MovableEntityTableController;
import gui.utils.SelectionListener;

@SuppressWarnings("serial")
public class PrivateInfoControllerPanel extends MovableEntityTableController<PrivateInfo> implements SelectionListener<User>
{
	private User user;
	
	public PrivateInfoControllerPanel()
	{
		super(new PrivateInfoTableModel());
	}
	
	@Override
	public List<PrivateInfo> getEntries()
	{
		return this.user.getPrivateInfo();
	}
	
	@Override
	public void onSelection(User selectedEntry)
	{
		if(selectedEntry != null)
		{
			this.user = selectedEntry;
			((PrivateInfoTableModel)super.tableModel).onSelection(selectedEntry);
		}
		else this.user = null;
		
		super.setSelectedEntry(null);
	}
	
	protected boolean addAction(ActionEvent e)
	{
		if(this.user != null)
		{
			PrivateInfoPanel  privateInfoPanel = new PrivateInfoPanel();
			BurpExtender.callbacks.customizeUiComponent(privateInfoPanel);
			
			int result = JOptionPane.showConfirmDialog(null, privateInfoPanel, "Add Private Info", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
			
			if(result == JOptionPane.OK_OPTION)
			{
				this.user.addPrivateInfo(privateInfoPanel.create());
				super.tableModel.fireTableDataChanged();
				
				return true;
			}
		}
		else JOptionPane.showMessageDialog(null, "Please select a User to add Private Information!");
		
		return true;
	}
	
	protected boolean editAction(ActionEvent e)
	{
		if(this.selection != null && this.user != null)
		{
			PrivateInfoPanel privateInfoPanel = new PrivateInfoPanel(this.selection);
			BurpExtender.callbacks.customizeUiComponent(privateInfoPanel);
			
			int result = JOptionPane.showConfirmDialog(null, privateInfoPanel, "Edit Private Information", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
			
			if(result == JOptionPane.OK_OPTION)
			{
				privateInfoPanel.edit(this.selection);
				super.tableModel.fireTableDataChanged();
				
				return true;
			}
		}
		else JOptionPane.showMessageDialog(null, "Please select Private Information to edit!");
		
		return false;
	}
	
	protected boolean removeAction(ActionEvent e)
	{
		if(this.selection != null && this.user != null)
		{
			if(this.user.removePrivateInfo(this.selection))
			{
				super.setSelectedEntry(null);
				super.tableModel.fireTableDataChanged();
				
				return true;
			}
		}
		else JOptionPane.showMessageDialog(null, "Please select Private Information to remove!");
		
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
