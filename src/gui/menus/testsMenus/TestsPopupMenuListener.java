package gui.menus.testsMenus;

import java.util.LinkedList;
import java.util.List;
import javax.swing.JMenuItem;

import authorize.messages.PrincipalMessage;
import authorize.messages.TestMessage;
import authorize.principal.Principal;
import burp.BurpExtender;
import gui.menus.commonMenus.MessageContextMenuInvocation;
import gui.menus.commonMenus.MessagePopupMenuListener;
import gui.menus.commonMenus.SendToComparerRequestMenu;
import gui.menus.commonMenus.SendToComparerResponseMenu;
import gui.menus.commonMenus.SendToIntruderMenu;
import gui.menus.commonMenus.SendToRepeaterMenu;
import gui.tableModels.TestsTableModel;
import gui.tables.TestsTable;

public class TestsPopupMenuListener extends MessagePopupMenuListener<TestMessage>
{
	public TestsPopupMenuListener(TestsTable table)
	{
		super(table);
	}

	@Override
	public List<JMenuItem> createMenuItems(MessageContextMenuInvocation<TestMessage> invocation)
	{
		List<JMenuItem> menuItems = new LinkedList<JMenuItem>();
		
		if(invocation.getSelectedMessages().size() == 1)
		{
			menuItems.add(new ExecuteTestMenu(invocation.getSelectedMessage()));
			
			if(invocation.getSelectedPrincipal() != null)
			{
				menuItems.add(new ExecuteTestForPrincipalMenu(invocation.getSelectedMessage(), invocation.getSelectedPrincipal()));
			}
			
			menuItems.add(new ExecuteEnforcementTestMenu(invocation.getSelectedMessage()));
			
			if(invocation.getSelectedPrincipal() != null)
			{
				menuItems.add(new ExecutePrincipalEnforcementTestMenu(invocation.getSelectedMessage(), invocation.getSelectedPrincipal()));
			}
			
			menuItems.add(new DeleteTestMenu(invocation.getSelectedMessage()));
		}

		if(invocation.getSelectedMessages().size() > 1)
		{
			menuItems.add(new ExecuteTestsMenu(invocation.getSelectedMessages()));
		}
		
		if(invocation.getSelectedMessages().size() == 1)
		{
			if(invocation.getSelectedPrincipal() != null)
			{
				menuItems.add(new DeletePrincipalTestMenu(invocation.getSelectedMessage(), invocation.getSelectedPrincipal()));
			}
			
			if(invocation.getSelectedMessages().size() == 1)
			{
				menuItems.add(new SendToIntruderMenu(invocation.getSelectedMessage().getMessage()));
				menuItems.add(new SendToRepeaterMenu(invocation.getSelectedMessage().getMessage()));
				menuItems.add(new SendToComparerRequestMenu(invocation.getSelectedMessage().getMessage()));
				menuItems.add(new SendToComparerResponseMenu(invocation.getSelectedMessage().getMessage()));
			}
		}
	
		return menuItems;
	}

	@Override
	protected TestMessage getMessage(int row)
	{
		int messageId = BurpExtender.instance.getView().getTestsTab().getTable().tableRowToMessageId(row);
		return BurpExtender.instance.getAuthorize().getTests().get(messageId);
	}

	@Override
	protected boolean isPrincipalColumn(int col)
	{
		return TestsTableModel.isPrincipalColumn(col);
	}

	@Override
	protected Principal getPrincipalByColIndex(int col)
	{
		return TestsTableModel.getPrincipalByColIndex(col);
	}
	
	@Override
	protected boolean hasPrincipalMessage(Principal principal, int row)
	{
		int messageId = BurpExtender.instance.getView().getTestsTab().getTable().tableRowToMessageId(row);
		PrincipalMessage principalMessage = BurpExtender.instance.getAuthorize().getTests().get(messageId).getPrincipalMessage(principal.getName());
		if(principalMessage != null)
		{
			return principalMessage.getMessage() != null;
		}
		
		return false;
	}
	
}
