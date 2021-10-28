package gui.tableModels;

import java.util.List;

import authorize.modifier.ModifierRule;
import authorize.principal.Principal;
import gui.utils.SelectionListener;

@SuppressWarnings("serial")
public class PrincipalModifierRuleTableModel extends ModifierRuleTableModel implements SelectionListener<Principal>
{
	public PrincipalModifierRuleTableModel()
	{
		super();
	}
	
	@Override
	public void onSelection(Principal selectedPrincipal)
	{
		List<ModifierRule> newModifiersList = selectedPrincipal != null ? selectedPrincipal.getModifierRules() : null;
		super.setList(newModifiersList);
	}
	
}
