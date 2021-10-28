package gui.controllerPanels;

import java.awt.event.ActionEvent;
import java.util.List;

import javax.swing.JComboBox;
import javax.swing.JOptionPane;
import javax.swing.JTable;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;

import authorize.modifier.ModifierRule;
import authorize.types.ModifierType;
import burp.BurpExtender;
import gui.modifier.ModifierRulePanel;
import gui.tableModels.ModifierRuleTableModel;
import gui.utils.AdjustableConfirmDialog;
import gui.utils.MovableEntryControllerPanel;

@SuppressWarnings("serial")
public class ModifierRulesControllerPanel extends MovableEntryControllerPanel<ModifierRule>
{
	public static final String MODIFIERS_PANEL_NAME = "Modifiers";
	public static final JComboBox<ModifierType> modifierTypeComboBox = new JComboBox<ModifierType>(ModifierType.values());
	
	public ModifierRulesControllerPanel(List<ModifierRule> modifiers, ModifierRuleTableModel modifierRuleTableModel)
	{
		super(modifiers, modifierRuleTableModel, MODIFIERS_PANEL_NAME);
	}
	
	protected void addAction(ActionEvent e)
	{
		ModifierRulePanel modifierPanel = new ModifierRulePanel(null);
		BurpExtender.callbacks.customizeUiComponent(modifierPanel);
		
		int result = AdjustableConfirmDialog.showAdjustableConfirmDialog(null, modifierPanel, "Add a Modifier", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
		
		if(result == JOptionPane.OK_OPTION)
		{
			ModifierRule newModifierRule = modifierPanel.createModifierRule();
			this.elements.add(newModifierRule);
			super.tableModel.fireTableDataChanged();
		}
	}
	
	protected void editAction(ActionEvent e)
	{
		if(super.selection != null)
		{
			ModifierRulePanel modifierPanel = new ModifierRulePanel(super.selection);
			BurpExtender.callbacks.customizeUiComponent(modifierPanel);
			
			int result = AdjustableConfirmDialog.showAdjustableConfirmDialog(null, modifierPanel, "Edit a Modifier", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
			
			if(result == JOptionPane.OK_OPTION)
			{
				modifierPanel.editModifierRule(super.selection);
				super.tableModel.fireTableDataChanged();
			}
		}
		else JOptionPane.showMessageDialog(null, "Please select a Modifier to edit!");
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
