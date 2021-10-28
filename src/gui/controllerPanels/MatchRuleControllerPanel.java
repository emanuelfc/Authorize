package gui.controllerPanels;

import java.awt.event.ActionEvent;
import java.util.List;

import javax.swing.JOptionPane;
import javax.swing.JTable;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;

import authorize.matcher.MatchRule;
import authorize.types.MatchType;
import burp.BurpExtender;
import gui.tableModels.MatchTableModel;
import gui.utils.EntriesRetrievalFunction;
import gui.utils.MovableEntryControllerPanel;

@SuppressWarnings("serial")
public class MatchRuleControllerPanel extends MovableEntryControllerPanel<MatchRule> implements ChangeListener
{
	private MatchType[] matchTypes;
	private EntriesRetrievalFunction<MatchRule> getEntriesFunction;
	
	public MatchRuleControllerPanel(MatchType[] matchTypes, String panelName, List<MatchRule> matchRules, EntriesRetrievalFunction<MatchRule> getEntriesFunction)
	{
		super(matchRules, new MatchTableModel(matchRules), panelName);
		
		this.setAlignmentX(LEFT_ALIGNMENT);
		
		this.matchTypes = matchTypes;
		this.getEntriesFunction = getEntriesFunction;
		
		this.table.getSelectionModel().addListSelectionListener(new EntrySelectionListener()
		{

			@Override
			public List<MatchRule> getEntriesList()
			{
				return MatchRuleControllerPanel.this.getEntriesFunction.getEntries();
			}

		});
		
		this.setRulesFromAuthorize();
	}
	
	private void setRulesFromAuthorize()
	{
		((MatchTableModel)super.tableModel).setList(this.getEntriesFunction.getEntries());
	}
	
	public void stateChanged(ChangeEvent e)
	{
		this.setRulesFromAuthorize();
	}
	
	protected void addAction(ActionEvent e)
	{
		MatchRulePanel matchRulePanel = new MatchRulePanel(this.matchTypes);
		BurpExtender.callbacks.customizeUiComponent(matchRulePanel);
		
		int result = JOptionPane.showConfirmDialog(null, matchRulePanel, "Add Rule", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
		
		if(result == JOptionPane.OK_OPTION)
		{			
			MatchRule matchRule = matchRulePanel.create();
			this.elements.add(matchRule);
			super.tableModel.fireTableDataChanged();
		}
	}
	
	protected void editAction(ActionEvent e)
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
			}
		}
		else JOptionPane.showMessageDialog(null, "Please select a Rule to edit!");
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
