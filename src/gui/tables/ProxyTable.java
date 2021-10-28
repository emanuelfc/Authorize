package gui.tables;

import java.awt.Component;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Iterator;

import javax.swing.JLabel;
import javax.swing.JPopupMenu;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;

import authorize.messages.PrincipalMessage;
import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IMessageEditor;
import gui.controllerPanels.MessageEditorController;
import gui.menus.proxyMenus.ProxyPopupMenuListener;
import gui.renderers.PrincipalAuthorizationCellRenderer;
import gui.tableModels.ProxyTableModel;
import gui.windows.AuthorizeMessageWindowPopup;

@SuppressWarnings("serial")
public class ProxyTable extends JTable implements ChangeListener
{
	private MessageEditorController messageEditor;
	private IMessageEditor requestViewer;
	private IMessageEditor responseViewer;
	private ProxyTableModel proxyTableModel;
	
	public ProxyTable(MessageEditorController messageEditor, IMessageEditor requestViewer, IMessageEditor responseViewer)
	{
		super();
		
		this.autoCreateColumnsFromModel = true;
		
		this.proxyTableModel = new ProxyTableModel();
		this.setModel(this.proxyTableModel);
		
		this.proxyTableModel.addTableModelListener(new TableModelListener()
		{

			@Override
			public void tableChanged(TableModelEvent e)
			{
				if(e.getFirstRow() == TableModelEvent.HEADER_ROW)
				{
					ProxyTable.this.customizeTable();
				}
			}
			
		});
		
		this.customizeTable();

		this.messageEditor = messageEditor;
		
		this.requestViewer = requestViewer;
		this.responseViewer = responseViewer;
		
		this.addMouseListener(new AuthorizeMessageWindowPopup(this));
		
		JPopupMenu popupMenu = new JPopupMenu();
		popupMenu.addPopupMenuListener(new ProxyPopupMenuListener(this));
		this.setComponentPopupMenu(popupMenu);
	}
	
	private void customizeTable()
	{	
		this.setAutoCreateRowSorter(true);
		this.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		this.setRowSelectionAllowed(true);
		this.setColumnSelectionAllowed(false);
		this.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
		
		TableColumnModel columnModel = this.getColumnModel();
		
		// ID Column
		TableColumn idColumn = columnModel.getColumn(0);
		idColumn.setPreferredWidth(50);
		idColumn.setMinWidth(50);
		DefaultTableCellRenderer leftRenderer = new DefaultTableCellRenderer();
		leftRenderer.setHorizontalAlignment(JLabel.LEFT);
		idColumn.setCellRenderer(leftRenderer);
		
		DefaultTableCellRenderer defaultColumnsRenderer = new DefaultTableCellRenderer();
		
		// Host Column
		TableColumn hostColumn = columnModel.getColumn(1);
		hostColumn.setPreferredWidth(220);
		hostColumn.setCellRenderer(defaultColumnsRenderer);
		
		// Method Column
		TableColumn methodColumn = columnModel.getColumn(2);
		methodColumn.setPreferredWidth(60);
		methodColumn.setMinWidth(50);
		methodColumn.setCellRenderer(defaultColumnsRenderer);
		
		// URL - Path Column
		TableColumn pathColumn = columnModel.getColumn(3);
		pathColumn.setPreferredWidth(380);
		pathColumn.setCellRenderer(defaultColumnsRenderer);
		
		// Status Column
		TableColumn statusColumn = columnModel.getColumn(4);
		statusColumn.setPreferredWidth(55);
		statusColumn.setMinWidth(55);
		statusColumn.setCellRenderer(defaultColumnsRenderer);
		
		// Time Column
		TableColumn timeColumn = columnModel.getColumn(5);
		timeColumn.setPreferredWidth(140);
		timeColumn.setMinWidth(140);
		
		TableCellRenderer dateCellRenderer = new DefaultTableCellRenderer()
		{
			private SimpleDateFormat dateFormat = new SimpleDateFormat("HH:mm:ss dd/MM/YYYY");
			
			public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column)
			{
				if(value instanceof Date)
				{
					value = dateFormat.format(value);
				}
				return super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
			}
		};
		
		timeColumn.setCellRenderer(dateCellRenderer);
		
		PrincipalAuthorizationCellRenderer principalAuthCellRenderer = new PrincipalAuthorizationCellRenderer();
		this.setDefaultRenderer(String.class, principalAuthCellRenderer);
		
		Iterator<TableColumn> it = this.getColumnModel().getColumns().asIterator();
		for(int i = 0; i < 6; i++)
		{
			it.next();
		}
		
		while(it.hasNext())
		{
			it.next().setPreferredWidth(130);
		}
		
		this.tableHeader.setReorderingAllowed(true);
	}
	
	public int tableRowToMessageId(int row)
	{
		return this.proxyTableModel.modelRowToMessageId(this.convertRowIndexToModel(row));
	}
	
	private IHttpRequestResponse getSelectedMessage(int row, int col)
	{
		int messageId = this.tableRowToMessageId(row);
		int modelCol = this.convertColumnIndexToModel(col);
		
		if(ProxyTableModel.isPrincipalColumn(modelCol))
		{
			PrincipalMessage principalMessage = ProxyTableModel.getPrincipalByColIndex(modelCol).getMessage(messageId);
			if(principalMessage != null)
			{
				return principalMessage.getMessage();
			}
			else return null;
		}
		else
		{
			return BurpExtender.instance.getAuthorize().getMessages().get(messageId).getMessage();
		}
	}
	
	public void changeSelection(int row, int col, boolean toggle, boolean extend)
	{
		super.changeSelection(row, col, toggle, extend);
		
		IHttpRequestResponse selectedMessageInfo = this.getSelectedMessage(row, col);
		
		byte[] request, response;
		
		if(selectedMessageInfo != null)
		{
			request = selectedMessageInfo.getRequest();
			response = selectedMessageInfo.getResponse();
		}
		else
		{
			request = response = "Message Does Not Exist".getBytes();
		}
		
		this.requestViewer.setMessage(request, true);
		this.responseViewer.setMessage(response, false);
		
		this.messageEditor.onSelection(selectedMessageInfo);
	}
	
	public ProxyTableModel getModel()
	{
		return this.proxyTableModel;
	}

	@Override
	public void stateChanged(ChangeEvent e)
	{
		this.proxyTableModel.fireTableStructureChanged();
	}
}
