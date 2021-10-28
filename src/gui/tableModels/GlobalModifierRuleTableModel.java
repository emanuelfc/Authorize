package gui.tableModels;

import java.util.List;

import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import authorize.modifier.ModifierRule;
import burp.BurpExtender;

@SuppressWarnings("serial")
public class GlobalModifierRuleTableModel extends ModifierRuleTableModel implements ChangeListener
{
	public GlobalModifierRuleTableModel(List<ModifierRule> modifiers)
	{
		super(modifiers);
	}
	
	public GlobalModifierRuleTableModel()
	{
		this(null);
	}

	@Override
	// Used when importing config.
	public void stateChanged(ChangeEvent e)
	{
		super.setList(BurpExtender.instance.getAuthorize().getGlobalModifiers());
	}
	
}
