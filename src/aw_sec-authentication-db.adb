------------------------------------------------------------------------------
--                                                                          --
--                          Ada Works :: Security                           --
--                                                                          --
--                                Ada Works                                 --
--                                                                          --
--                                 B o d y                                  --
--                                                                          --
--        Copyright (C) 2007-2008, Ydea Desenv. de Softwares Ltda           --
--                                                                          --
--                                                                          --
-- AwSec is free software; you can redistribute it  and/or modify it under  --
-- terms of the  GNU General Public License as published  by the Free Soft- --
-- ware  Foundation;  either version 2,  or (at your option) any later ver- --
-- sion. AwSec is distributed in the hope that it will be useful, but WITH- --
-- OUT ANY WARRANTY;  without even the  implied warranty of MERCHANTABILITY --
-- or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License --
-- for  more details.  You should have  received  a copy of the GNU General --
-- Public License distributed with AwSec; see file COPYING.  If not, write  --
-- to  the Free Software Foundation,  59 Temple Place - Suite 330,  Boston, --
-- MA 02111-1307, USA.                                                      --
--                                                                          --
-- As a special exception,  if other files  instantiate  generics from this --
-- unit, or you link  this unit with other files  to produce an executable, --
-- this  unit  does not  by itself cause  the resulting  executable  to  be --
-- covered  by the  GNU  General  Public  License.  This exception does not --
-- however invalidate  any other reasons why  the executable file  might be --
-- covered by the  GNU Public License.                                      --
--                                                                          --
------------------------------------------------------------------------------

-------------------------------------------------------------------------------
-- This is the Aw_Sec.Authentication package.                                --
-------------------------------------------------------------------------------

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

