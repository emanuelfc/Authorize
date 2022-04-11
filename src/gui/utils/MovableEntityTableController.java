package gui.utils;

import java.awt.event.ActionEvent;
import javax.swing.table.AbstractTableModel;

@SuppressWarnings("serial")
public abstract class MovableEntityTableController<E> extends EntityTableController<E>
{
	protected MovableEntityTableController(AbstractTableModel tableModel)
	{
		super(tableModel);
		
		this.buttonsPanel.addMoveButtons(this::moveUpAction, this::moveDownAction);
	}
	
	private void moveAction(int direction, E selection)
	{
		if(this.selection != null)
		{
			int oldIndex = this.getEntries().indexOf(this.selection);
			
			if(this.getEntries().remove(this.selection))
			{
				int newIndex = oldIndex + direction;
				this.getEntries().add(newIndex, this.selection);
				this.tableModel.fireTableDataChanged();
			}
		}
	}

	protected void moveUpAction(ActionEvent e)
	{
		this.moveAction(-1, this.selection);
	}

	protected void moveDownAction(ActionEvent e)
	{
		this.moveAction(+1, this.selection);
	}
}
