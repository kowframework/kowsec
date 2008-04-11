with Aw_Sec; 

package Aw_Sec.Authentication is


	function New_Authentication_Manager( Conn_Access: Connection_Access )
		return Authentication_Manager is
	
		Auth_Manager: Authentication_Manager;
	begin
		Auth_Manager.Connection := Conn_Access;
		
		return Auth_Manager;
	end New_Authentication_Manager;


	function Do_Login(	Manager:  in Authentication_Manager;
	                  	Username: in String;
	                  	Password: in String ) return User'Class is
		Required_User : User;
		Connection : Root_Connection_Type;
	
	begin
		Connection := Get_Connection(Manager);
		
		Set_User_Password(Connection, Username, Password);
		Connect(Connection);

		if Username = Connection.User_Name and then
			Password = Connection.User_Password then
			Required_User.Username.all := Username;
			return Required_User;
		else 
			raise INVALID_CREDENTIALS;
		end if;
		
	end Do_Login;


	function Get_Groups(    Manager:	in Authentication_Manager;
	                        User_Object:	in User'Class )
		return Authorization_Groups is
	end Get_Groups;
	
	function Get_Groups( User_object: in User'Class )
		return Authorization_Groups is
	
	end Get_Groups;


-- private
	
	function Get_Connection( Auth_Manager: in Authentication_Manager )
		return Root_Connection_Type'Class is
	begin
		if Auth_Manager.Connection /= NULL
			return Auth_Manger.connection.all;
		else if Auth_Manager.Connection_Driver /= null
			return Get_Connection( Auth_Manager.Connection_Driver );
		else
			raise NOT_CONNECTED;
		end if;
	end Get_Connection;

end Aw_Sec.Authentication;

