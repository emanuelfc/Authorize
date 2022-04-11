package gui.tabs.usersTab;

import java.awt.event.ActionEvent;
import java.util.List;

import javax.swing.JOptionPane;

import authorize.modifier.ModifierRule;
import authorize.user.User;
import gui.tabs.configTab.ModifierRulesControllerPanel;
import gui.utils.SelectionListener;

@SuppressWarnings("serial")
public class UserModifierRulesControllerPanel extends ModifierRulesControllerPanel implements SelectionListener<User>
{	
	private List<ModifierRule> userModifierRules;
	
	public UserModifierRulesControllerPanel()
	{
		super(new UserModifierRuleTableModel(null));
		this.userModifierRules = null;
	}
	
	@Override
	protected List<ModifierRule> getEntries()
	{
		return this.userModifierRules;
	}
	
	@Override
	public void onSelection(User selectedUser)
	{
		if(selectedUser != null)
		{
			this.userModifierRules = selectedUser.getModifierRules();
			((UserModifierRuleTableModel)super.tableModel).onSelection(selectedUser);
		}
		else this.userModifierRules = null;
		
		super.setSelectedEntry(null);
	}
	
	@Override
	protected boolean addModifierRule(ModifierRule newModifierRule)
	{
		return this.userModifierRules.add(newModifierRule);
	}
	
	@Override
	protected boolean addAction(ActionEvent e)
	{
		if(this.userModifierRules != null)
		{
			return super.addAction(e);
		}
		else JOptionPane.showMessageDialog(null, "Please select a User to add Modifiers to!");
		
		return false;
	}

	@Override
	protected boolean removeAction(ActionEvent e)
	{
		if(this.userModifierRules != null && this.selection != null)
		{
			if(this.userModifierRules.remove(this.selection))
			{
				this.tableModel.fireTableDataChanged();
				return true;
			}
		}
		else JOptionPane.showMessageDialog(null, "Please select a Modifier to remove!");
		
		return false;
	}
}
