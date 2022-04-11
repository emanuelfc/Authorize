package gui.tabs;

import java.awt.event.ActionEvent;
import javax.swing.JOptionPane;
import javax.swing.JTable;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;

import authorize.interception.MatchRule;
import authorize.types.MatchType;
import burp.BurpExtender;
import gui.utils.MovableEntityTableController;

@SuppressWarnings("serial")
public abstract class MatchRuleControllerPanel extends MovableEntityTableController<MatchRule>
{
	private MatchType[] matchTypes;
	
	public MatchRuleControllerPanel(MatchTableModel matchTableModel, MatchType[] matchTypes)
	{
		super(matchTableModel);
		this.matchTypes = matchTypes;
	}
	
	protected abstract boolean addMatchRule(MatchRule matchRule);
	
	protected boolean addAction(ActionEvent e)
	{
		MatchRulePanel matchRulePanel = new MatchRulePanel(this.matchTypes);
		BurpExtender.callbacks.customizeUiComponent(matchRulePanel);
		
		int result = JOptionPane.showConfirmDialog(null, matchRulePanel, "Add Rule", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
		
		if(result == JOptionPane.OK_OPTION)
		{			
			MatchRule matchRule = matchRulePanel.create();
			if(this.addMatchRule(matchRule))
			{
				super.tableModel.fireTableDataChanged();
				return true;
			}
		}
		
		return false;
	}
	
	protected boolean editAction(ActionEvent e)
	{
		if(this.selection != null)
		{
			MatchRulePanel enforcementRulePanel = new MatchRulePanel(this.matchTypes, this.selection);
			BurpExtender.callbacks.customizeUiComponent(enforcementRulePanel);
			
			int result = JOptionPane.showConfirmDialog(null, enforcementRulePanel, "Edit Rule", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
			
			if(result == JOptionPane.OK_OPTION)
			{
				enforcementRulePanel.edit(this.selection);
				super.tableModel.fireTableDataChanged();
				
				return true;
			}
		}
		else JOptionPane.showMessageDialog(null, "Please select a Rule to edit!");
		
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
	}
}
