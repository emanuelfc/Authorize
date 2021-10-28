package gui.utils;

@FunctionalInterface
public interface SelectionListener<E>
{
	public void onSelection(E selection);
}
