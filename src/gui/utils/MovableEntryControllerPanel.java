package gui.utils;

import java.awt.event.ActionEvent;
import java.util.List;

import javax.swing.table.AbstractTableModel;

@SuppressWarnings("serial")
public abstract class MovableEntryControllerPanel<E> extends EntryControllerPanel<E>
{
	protected MovableEntryControllerPanel(List<E> elements, AbstractTableModel tableModel, String title)
	{
		super(elements, tableModel, title);
		
		this.buttonsPanel.addMoveButtons(this::moveUpAction, this::moveDownAction);
	}
	
	private void swap(int index, E element)
	{
		int elementIndex = this.elements.indexOf(element);
		E tmp = this.elements.set(index, element);
		this.elements.set(elementIndex, tmp);
	}

	// Go -1 - to the direction of the beginning of the list
	protected void moveUpAction(ActionEvent e)
	{
		if(this.selection != null)
		{
			int index = this.elements.indexOf(this.selection);
			if(index > 0)
			{
				this.swap(index-1, this.selection);
				this.tableModel.fireTableDataChanged();
			}
		}
	}
	
	// Go +1 - to the direction of the end of the list
	protected void moveDownAction(ActionEvent e)
	{
		if(this.selection != null)
		{
			int index = this.elements.indexOf(this.selection);
			if(index < this.elements.size()-1)
			{
				this.swap(index+1, this.selection);
				this.tableModel.fireTableDataChanged();
			}
		}
	}
}
