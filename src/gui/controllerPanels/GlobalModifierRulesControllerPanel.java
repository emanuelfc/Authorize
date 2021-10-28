package gui.controllerPanels;

import java.util.List;

import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import authorize.modifier.ModifierRule;
import burp.BurpExtender;
import gui.tableModels.GlobalModifierRuleTableModel;

@SuppressWarnings("serial")
public class GlobalModifierRulesControllerPanel extends ModifierRulesControllerPanel implements ChangeListener
{
	public GlobalModifierRulesControllerPanel(List<ModifierRule> modifiers)
	{
		super(modifiers, new GlobalModifierRuleTableModel(modifiers));
		
		super.table.getSelectionModel().addListSelectionListener(new EntrySelectionListener()
		{

			@Override
			public List<ModifierRule> getEntriesList()
			{
				return BurpExtender.instance.getAuthorize().getGlobalModifiers();
			}
	
		});
	}
	
	public void stateChanged(ChangeEvent e)
	{
		this.elements = BurpExtender.instance.getAuthorize().getGlobalModifiers();
		((GlobalModifierRuleTableModel)super.tableModel).setList(this.elements);
	}
}
