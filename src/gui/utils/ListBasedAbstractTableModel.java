package gui.utils;

import java.util.List;

@SuppressWarnings("serial")
public abstract class ListBasedAbstractTableModel<E> extends SimpleAbstractTableModel
{
	protected List<E> list;
	
	public ListBasedAbstractTableModel(String[] columnNames, Class<?>[] columnTypes, List<E> list)
	{
		super(columnNames, columnTypes);
		this.list = list;
	}
	
	public void setList(List<E> list)
	{
		this.list = list;
		this.fireTableDataChanged();
	}
	
	@Override
	public int getRowCount()
	{
		return (this.list != null) ? this.list.size() : 0;
	}

	@Override
	public abstract Object getValueAt(int row, int col);
}
