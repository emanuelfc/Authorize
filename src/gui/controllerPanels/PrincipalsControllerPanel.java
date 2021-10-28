package gui.controllerPanels;

import java.awt.event.ActionEvent;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.ConcurrentMap;

import javax.swing.JOptionPane;
import javax.swing.JTable;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;

import authorize.principal.Principal;
import burp.BurpExtender;
import gui.PrincipalPanel;
import gui.tableModels.PrincipalsTableModel;
import gui.utils.EntryControllerPanel;

@SuppressWarnings("serial")
public class PrincipalsControllerPanel extends EntryControllerPanel<Principal>
{
	public static final String PRINCIPALS_TABLE_NAME = "Principals";
	
	public PrincipalsControllerPanel()
	{
		super(new LinkedList<Principal>(BurpExtender.instance.getAuthorize().getPrincipals().values()), new PrincipalsTableModel(), PRINCIPALS_TABLE_NAME);
		
		this.table.getSelectionModel().addListSelectionListener(new EntrySelectionListener()
		{

			@Override
			public List<Principal> getEntriesList()
			{
				return new LinkedList<Principal>(BurpExtender.instance.getAuthorize().getPrincipals().values());
			}
	
		});
	}
	
	protected void addAction(ActionEvent e)
	{
		PrincipalPanel principalPanel = new PrincipalPanel();
		
		int result = JOptionPane.showConfirmDialog(null, principalPanel, "Add Principal", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
		
		if(result == JOptionPane.OK_OPTION)
		{
			BurpExtender.instance.getAuthorize().addPrincipal(principalPanel.getPrincipalName());
			super.tableModel.fireTableDataChanged();
		}
	}
	
	protected void editAction(ActionEvent e)
	{
		if(this.selection != null)
		{
			PrincipalPanel principalPanel = new PrincipalPanel(this.selection);
			
			int result = JOptionPane.showConfirmDialog(null, principalPanel, "Edit Principal", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
			
			if(result == JOptionPane.OK_OPTION)
			{
				ConcurrentMap<String, Principal> principals = BurpExtender.instance.getAuthorize().getPrincipals();
				
				String newPrincipalName = principalPanel.getPrincipalName();
				
				synchronized(principals)
				{
					if(!principals.containsKey(newPrincipalName))
					{
						principals.remove(this.selection.getName());
						this.selection.setName(newPrincipalName);
						principals.put(newPrincipalName, this.selection);
						super.tableModel.fireTableDataChanged();
					}
				}
			}
		}
		else JOptionPane.showMessageDialog(null, "Please select a Principal to edit!");
	}
	
	protected void removeAction(ActionEvent e)
	{
		if(this.selection != null)
		{
			if(BurpExtender.instance.getAuthorize().getPrincipals().remove(this.selection.getName()) != null)
			{
				super.setSelectedEntry(null);
				super.tableModel.fireTableDataChanged();
			}
		}
		else JOptionPane.showMessageDialog(null, "Please select a Principal to remove!");
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
