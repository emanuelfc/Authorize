package gui.tabs.usersTab;

import java.util.List;

import authorize.modifier.ModifierRule;
import authorize.user.User;
import gui.tabs.configTab.ModifierRuleTableModel;
import gui.utils.SelectionListener;

@SuppressWarnings("serial")
public class UserModifierRuleTableModel extends ModifierRuleTableModel implements SelectionListener<User>
{
	private List<ModifierRule> userModifierRules;
	
	public UserModifierRuleTableModel(List<ModifierRule> userModifierRules)
	{
		super();
		this.userModifierRules = null;
	}

	@Override
	protected ModifierRule getEntry(int row, int col)
	{
		return this.userModifierRules.get(row);
	}

	@Override
	public int getRowCount()
	{
		return this.userModifierRules != null ? this.userModifierRules.size() : 0;
	}

	@Override
	public void onSelection(User selection)
	{
		this.userModifierRules = selection != null ? selection.getModifierRules() : null;
		this.fireTableDataChanged();
	}
}
