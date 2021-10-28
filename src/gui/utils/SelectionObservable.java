package gui.utils;

public interface SelectionObservable<E>
{
	public void addSelectionListener(SelectionListener<E> listener);
	public void triggerListeners(E selection);
}
