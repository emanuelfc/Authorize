package gui.utils;

import javax.swing.table.AbstractTableModel;

@SuppressWarnings("serial")
public abstract class SimpleAbstractTableModel extends AbstractTableModel
{
	protected String[] columnNames;
	protected Class<?>[] columnTypes;
	
	public SimpleAbstractTableModel(String[] columnNames, Class<?>[] columnTypes)
	{
		this.columnNames = columnNames;
		this.columnTypes = columnTypes;
	}
	
	public Class<?> getColumnClass(int col)
	{
		return this.columnTypes[col];
	}
	
	public String getColumnName(int col)
	{
		return this.columnNames[col];
	}
	
	@Override
	public int getColumnCount()
	{
		return columnNames.length;
	}

	@Override
	public abstract int getRowCount();

	@Override
	public abstract Object getValueAt(int row, int col);

	@Override
	public boolean isCellEditable(int row, int col)
	{
		return col == 0;
	}
}
