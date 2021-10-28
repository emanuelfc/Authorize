package gui.controllerPanels;

import java.awt.event.ActionEvent;
import java.util.List;

import javax.swing.JOptionPane;

import authorize.modifier.ModifierRule;
import authorize.principal.Principal;
import gui.tableModels.PrincipalModifierRuleTableModel;
import gui.utils.SelectionListener;

@SuppressWarnings("serial")
public class PrincipalModifierRulesControllerPanel extends ModifierRulesControllerPanel implements SelectionListener<Principal>
{	
	public PrincipalModifierRulesControllerPanel(List<ModifierRule> modifiers)
	{
		super(modifiers, new PrincipalModifierRuleTableModel());
		
		super.table.getSelectionModel().addListSelectionListener(new EntrySelectionListener()
		{

			@Override
			public List<ModifierRule> getEntriesList()
			{
				return PrincipalModifierRulesControllerPanel.this.elements;
			}
	
		});
	}
	
	public PrincipalModifierRulesControllerPanel()
	{
		this(null);
	}
	
	@Override
	public void onSelection(Principal selectedPrincipal)
	{
		if(selectedPrincipal != null)
		{
			this.elements = selectedPrincipal.getModifierRules();
			((PrincipalModifierRuleTableModel)super.tableModel).onSelection(selectedPrincipal);
		}
		else this.elements = null;
		
		super.setSelectedEntry(null);
	}
	
	@Override
	protected void addAction(ActionEvent e)
	{
		if(this.elements != null)
		{
			super.addAction(e);
		}
		else JOptionPane.showMessageDialog(null, "Please select a Principal to add Modifiers to!");
	}
}
