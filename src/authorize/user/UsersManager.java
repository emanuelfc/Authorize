package authorize.user;

import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

public class UsersManager
{
	private Predicate<User> enabledUserPredicate = (user) -> (user.isEnabled());
	
	private ConcurrentMap<String, User> users;
	
	private List<User> orderedUsers;
	
	@JsonIgnore
	private User impersonatingUser;
	
	public UsersManager()
	{
		this.users = new ConcurrentHashMap<String, User>();
		this.orderedUsers = new LinkedList<User>();
		this.impersonatingUser = null;
	}
	
	@JsonCreator
	public UsersManager(@JsonProperty("users") Map<String, User> users)
	{
		this.users = new ConcurrentHashMap<String, User>(users);
		this.orderedUsers = new LinkedList<User>(users.values());
		this.impersonatingUser = null;
	}
	
	public ConcurrentMap<String, User> getUsers()
	{
		return this.users;
	}
	
	public boolean hasEnabledUsers()
	{
		return this.users.values().stream().anyMatch(this.enabledUserPredicate);
	}
	
	public List<User> getOrderedUsers()
	{
		return this.orderedUsers;
	}
	
	public List<User> getOrderedEnabledUsers()
	{
		return this.orderedUsers.stream().filter(this.enabledUserPredicate).collect(Collectors.toList());
	}
	
	public void addUser(User user)
	{
		if(this.users.putIfAbsent(user.getName(), user) == null)
		{
			this.orderedUsers.add(user);
		}
	}
	
	public void addUser(String name)
	{
		this.addUser(new User(name));
	}
	
	public void editUserName(String name, String newUsername)
	{
		User removedUser = this.removeUser(name);
		
		if(removedUser != null)
		{
			removedUser.setName(newUsername);
			this.addUser(removedUser);
		}
	}
	
	public User removeUser(String name)
	{
		User removedUser = this.users.remove(name);
		
		if(removedUser != null)
		{
			if(this.impersonatingUser != null && this.impersonatingUser.equals(removedUser)) this.resetImpersonatingUser();;
			
			this.orderedUsers.remove(removedUser);
			
			return removedUser;
		}
		
		return null;
	}
	
	public boolean setUserOrder(User user, int index)
	{
		if(this.orderedUsers.remove(user))
		{
			this.orderedUsers.add(index, user);
			
			return true;
		}
		
		return false;
	}
	
	@JsonIgnore
	public User getImpersonatingUser()
	{
		return this.impersonatingUser;
	}
	
	public void setImpersonatingUser(User newImpersonatingUser)
	{
		this.impersonatingUser = newImpersonatingUser;
	}
	
	public void resetImpersonatingUser()
	{
		this.impersonatingUser = null;
	}
}
