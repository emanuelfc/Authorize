package gui.controllerPanels;

import java.awt.event.ActionEvent;
import java.util.List;

import javax.swing.JOptionPane;
import javax.swing.JTable;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;

import authorize.principal.Principal;
import authorize.principal.PrivateInfo;
import burp.BurpExtender;
import gui.PrivateInfoPanel;
import gui.tableModels.PrivateInfoTableModel;
import gui.utils.MovableEntryControllerPanel;
import gui.utils.SelectionListener;

@SuppressWarnings("serial")
public class PrivateInfoControllerPanel extends MovableEntryControllerPanel<PrivateInfo> implements SelectionListener<Principal>
{
	public static final String PRIVATE_INFO_TABLE_NAME = "Private Information";
	
	private Principal principal;
	
	public PrivateInfoControllerPanel()
	{
		super(null, new PrivateInfoTableModel(), PRIVATE_INFO_TABLE_NAME);
		
		this.table.getSelectionModel().addListSelectionListener(new EntrySelectionListener()
		{

			@Override
			public List<PrivateInfo> getEntriesList()
			{
				return PrivateInfoControllerPanel.this.principal.getPrivateInfo();
			}
	
		});
	}
	
	// For principal modifiers
	@Override
	public void onSelection(Principal selectedEntry)
	{
		if(selectedEntry != null)
		{
			this.principal = selectedEntry;
			((PrivateInfoTableModel)super.tableModel).onSelection(selectedEntry);
		}
		else this.principal = null;
		
		super.setSelectedEntry(null);
	}
	
	protected void addAction(ActionEvent e)
	{
		if(this.principal != null)
		{
			PrivateInfoPanel  privateInfoPanel = new PrivateInfoPanel();
			BurpExtender.callbacks.customizeUiComponent(privateInfoPanel);
			
			int result = JOptionPane.showConfirmDialog(null, privateInfoPanel, "Add Private Info", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
			
			if(result == JOptionPane.OK_OPTION)
			{
				this.principal.addPrivateInfo(privateInfoPanel.create());
				this.elements = this.principal.getPrivateInfo();
				super.tableModel.fireTableDataChanged();
			}
		}
		else JOptionPane.showMessageDialog(null, "Please select a Principal to add Private Information!");
	}
	
	protected void editAction(ActionEvent e)
	{
		if(this.selection != null && this.principal != null)
		{
			PrivateInfoPanel privateInfoPanel = new PrivateInfoPanel(this.selection);
			BurpExtender.callbacks.customizeUiComponent(privateInfoPanel);
			
			int result = JOptionPane.showConfirmDialog(null, privateInfoPanel, "Edit Private Information", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
			
			if(result == JOptionPane.OK_OPTION)
			{
				privateInfoPanel.edit(this.selection);
				super.tableModel.fireTableDataChanged();
			}
		}
		else JOptionPane.showMessageDialog(null, "Please select Private Information to edit!");
	}
	
	protected void removeAction(ActionEvent e)
	{
		if(this.selection != null && this.principal != null)
		{
			if(this.principal.removePrivateInfo(this.selection))
			{
				super.setSelectedEntry(null);
				super.tableModel.fireTableDataChanged();
			}
		}
		else JOptionPane.showMessageDialog(null, "Please select Private Information to remove!");
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
