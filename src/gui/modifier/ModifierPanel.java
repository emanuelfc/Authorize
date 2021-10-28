package gui.modifier;

import authorize.modifier.Modifier;
import gui.utils.AbstractEntityPanel;

@SuppressWarnings("serial")
public abstract class ModifierPanel extends AbstractEntityPanel
{
	public abstract Modifier createModifier();
	public abstract void editModifier(Modifier modifier);
}
