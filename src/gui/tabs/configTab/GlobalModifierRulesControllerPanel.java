package gui.tabs.configTab;

import java.awt.event.ActionEvent;
import java.util.List;

import authorize.modifier.ModifierRule;
import burp.BurpExtender;

@SuppressWarnings("serial")
public class GlobalModifierRulesControllerPanel extends ModifierRulesControllerPanel
{
	public GlobalModifierRulesControllerPanel()
	{
		super(new ModifierRuleTableModel()
				{

					@Override
					protected ModifierRule getEntry(int row, int col)
					{
						return BurpExtender.instance.getAuthorize().getGlobalModifiers().get(row);
					}

					@Override
					public int getRowCount()
					{
						return BurpExtender.instance.getAuthorize().getGlobalModifiers().size();
					}
			
				});
	}
	
	@Override
	public List<ModifierRule> getEntries()
	{
		return BurpExtender.instance.getAuthorize().getGlobalModifiers();
	}

	@Override
	protected boolean addModifierRule(ModifierRule newModifierRule)
	{
		return this.getEntries().add(newModifierRule);
	}

	@Override
	protected boolean removeAction(ActionEvent e)
	{
		if(this.getEntries().remove(this.selection))
		{
			this.tableModel.fireTableDataChanged();
			return true;
		}
		
		return false;
	}
}
