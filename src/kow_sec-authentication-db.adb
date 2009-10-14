------------------------------------------------------------------------------
--                                                                          --
--                          Ada Works :: Security                           --
--                                                                          --
--                                Ada Works                                 --
--                                                                          --
--                                 B o d y                                  --
--                                                                          --
--               Copyright (C) 2007-2009, Ada Works Project                 --
--                                                                          --
--                                                                          --
-- KOWSec is free software; you can redistribute it  and/or modify it under  --
-- terms of the  GNU General Public License as published  by the Free Soft- --
-- ware  Foundation;  either version 2,  or (at your option) any later ver- --
-- sion. KOWSec is distributed in the hope that it will be useful, but WITH- --
-- OUT ANY WARRANTY;  without even the  implied warranty of MERCHANTABILITY --
-- or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License --
-- for  more details.  You should have  received  a copy of the GNU General --
-- Public License distributed with KOWSec; see file COPYING.  If not, write  --
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
-- This is the KOW_Sec.Authentication.DB package.                             --
-------------------------------------------------------------------------------
with Ada.Exceptions;
with Ada.Unchecked_Conversion;
with Ada.Strings.Unbounded;	 use Ada.Strings.Unbounded;

package body KOW_Sec.Authentication.DB is


	function New_Authentication_Manager( Conn_Access: Connection_Access )
		return Authentication_Manager is
	
		Auth_Manager: Authentication_Manager;
		
	begin
		Auth_Manager.Connection := Conn_Access;
		
		return Auth_Manager;
	end New_Authentication_Manager;

	procedure Set_Connection( Manager: in out Authentication_Manager; Conn_Access: Connection_Access ) is
	begin
		Manager.Connection := Conn_Access;
	end Set_Connection;
 
	-- User Table Name
	procedure Set_Users_Table(	Manager:  in out Authentication_Manager;
					Users_Table_Name : in String	) is
	begin
		Manager.Users_Table := To_Unbounded_String( Users_Table_Name );	
	end Set_Users_Table;

	function Get_Users_Table ( Manager:  in Authentication_Manager ) return String is
	begin
		return To_String( Manager.Users_Table );
	end Get_Users_Table;


	-- Id Field of the Users Tables 
	procedure Set_User_Id_Field( 	Manager:  in out Authentication_Manager;
					User_Id_Field_Name : in String ) is
	begin
		Manager.User_Id_Field := To_Unbounded_String(User_Id_Field_Name);
	end Set_User_Id_Field;

	function Get_User_Id_Field( Manager:  in Authentication_Manager )  return String is
	begin
		return To_String( Manager.User_Id_Field);
	end Get_User_Id_Field;


	-- Username Field Name
	procedure Set_Username_Field( 	Manager:  in out Authentication_Manager;
					Name : in String ) is
	begin
		Manager.Username_Field := To_Unbounded_String(Name);
	end Set_Username_Field;

	function Get_Username_Field( Manager:  in Authentication_Manager )  return String is
	begin
		return To_String( Manager.Username_Field );
	end Get_Username_Field;


	-- Password Field Name
	procedure Set_Password_Field( 	Manager:  in out Authentication_Manager;
					Pwd : in String ) is
	begin
		Manager.Password_Field := To_Unbounded_String(Pwd);	
	end Set_Password_Field;

	function Get_Password_Field( Manager:  in Authentication_Manager )  return String is
	begin
		return To_String ( Manager.Password_Field );
	end Get_Password_Field;


	-- First_Name Field Name
	procedure Set_First_Name_Field( 	Manager:  in out Authentication_Manager;
						Name : in String ) is
	begin
		Manager.First_Name_Field := To_Unbounded_String(Name);
	end Set_First_Name_Field;

	function Get_First_Name_Field( Manager:  in Authentication_Manager )  return String is
	begin
		return To_String( Manager.First_Name_Field );
	end Get_First_Name_Field;


	-- Last_Name Field Name
	procedure Set_Last_Name_Field( 	Manager:  in out Authentication_Manager;
					Name : in String ) is
	begin
		Manager.Last_Name_Field := To_Unbounded_String(Name);
	end Set_Last_Name_Field;

	function Get_Last_Name_Field( Manager:  in Authentication_Manager )  return String is
	begin
		return To_String( Manager.Last_Name_Field );
	end Get_Last_Name_Field;


	-- Email Field Name
	procedure Set_Email_Field(	Manager:  in out Authentication_Manager;
					Name : in String ) is
	begin
		Manager.Email_Field := To_Unbounded_String( Name );
	end Set_Email_Field;

	function Get_Email_Field  (	Manager:  in Authentication_Manager ) return String is
	begin
		return To_String( Manager.Email_Field );
	end Get_Email_Field;


	-- Groups Table Name
	procedure Set_Groups_Table( 	Manager:  in out Authentication_Manager;
					Groups_Table_Name : in String ) is
	begin
		Manager.Groups_Table := To_Unbounded_String(Groups_Table_Name);
	end Set_Groups_Table;

	function Get_Groups_Table( Manager:  in Authentication_Manager )  return String is
	begin
		return To_String( Manager.Groups_Table );
	end Get_Groups_Table;
	
	
	-- Username Field of the Groups Tables 
	procedure Set_Groups_Username_Field( 	Manager:  in out Authentication_Manager;
						Name : in String ) is
	begin	
		Manager.Groups_Username_Field := To_Unbounded_String(Name);
	end Set_Groups_Username_Field;

	function Get_Groups_Username_Field( Manager:  in Authentication_Manager )  return String is
	begin
		return To_String( Manager.Groups_Username_Field );
	end Get_Groups_Username_Field;

	-- Group_Name Field Name
	procedure Set_Group_Name_Field(	Manager:  in out Authentication_Manager;
					Name : in String ) is
	begin
		Manager.Group_Name_Field := To_Unbounded_String(Name);		
	end Set_Group_Name_Field;

	function Get_Group_Name_Field( Manager:  in Authentication_Manager )  return String is
	begin
		return To_String( Manager.Group_Name_Field ); 
	end Get_Group_Name_Field;
	

	-- helper function to get the Query's Value at Column Column_Name
	function Value(	Query : in  Root_Query_Type'Class; 
			Column_Name : in String ) return Unbounded_String is
	begin
		return To_Unbounded_String("" & Value( Query, Column_Index( Query, Column_Name) ) );
	end Value;
	

	-- verify if exists the Username with corresponding Password
	-- at the Users Table.
	function Do_Login(	Manager:  in Authentication_Manager;
	                  	Username: in String;
	                  	Password: in String ) return User'Class is
	
		Required_User : User;

		Connection: Connection_Access := Get_Connection(Manager);
	
		Query: Root_Query_Type'Class := New_Query( Connection.all );
	begin
		--Set_Case( Query, Preserve_Case );

 		Prepare( Query, "SELECT * from " );
		Append( Query, Get_Users_Table(Manager) );
		Append( Query, " WHERE " );
		Append( Query, Get_Username_Field(Manager) );
		Append( Query, " = " );
		Append_Quoted( Query, Connection.all , Username);
		Append( Query, " AND " );
		Append( Query, Get_Password_Field( Manager ) );
		Append( Query, " = " );
		Append_Quoted( Query, Connection.all, Password );

		Execute( Query, Connection.all );


		begin
			Fetch( Query );
			-- if the result is empty, an exception is throwed now.
			-- so, there is no need to count the tuples.

			Required_User.Username :=
				Value(Query, Get_Username_Field(Manager));
			Required_User.First_Name := 
				Value(Query, Get_First_Name_Field(Manager));
			Required_User.Last_Name :=
				Value(Query, Get_Last_Name_Field(Manager));
			Required_user.Email :=
				Value( Query, Get_Email_Field(Manager));
		
			Required_User.Groups_Cache := new Groups_Cache_Type;

			return Required_User;

		exception
			when others =>
				raise INVALID_CREDENTIALS with "Empty Result Set";
		end;
	exception
		when APQ.SQL_Error =>
			raise INVALID_CONFIGURATION with Error_Message( Query );
		
	end Do_Login;

	
	function Get_Groups(    Manager:	in Authentication_Manager;
	                        User_Object:	in User'Class )
		return Authorization_Groups is


        	function To_Authorization_Group is
         		new Ada.Unchecked_Conversion (	Source => Unbounded_String,
                					Target => Authorization_Group	);

		Connection : Connection_Access := Get_Connection(Manager);
		Query: Root_Query_Type'Class := New_Query( Connection.all ); 
		Groups : Authorization_Groups;
	begin	
 		Prepare( Query,  "SELECT * from " );
		Append( Query, Get_Groups_Table(Manager) );
		Append( Query, " WHERE " );
		Append( Query, Get_Groups_Username_Field(Manager) & "=");
		Append_Quoted( Query, Connection.all, Identity( User_Object ));
		-- we should use Identity here because not aways the identity is the username
		--
		-- Even thought it might seen odd, try to picture the following:
		-- User "B" logged at computer "client" tries to fetch some information at the 
		-- compuer "server", which has it's own user base.
		--
		-- So, there might be another user "B" at the "server". In order to make sure this user
		-- is unique at "server", inside there the user could be called "B@client" instead of 
		-- only "B".
 


		Execute( Query, Connection.all );

		loop
			begin
				Fetch(Query); 
			exception
				when No_Tuple => exit;
			end;
		
			if Value( Query, Get_Group_Name_Field( Manager ) ) /= Null_Unbounded_String then
				Authorization_Group_Vectors.Append(
					Groups,
					To_Authorization_Group(
						Value(
							Query,
							Get_Group_Name_Field(Manager)
						) 
					) );
			end if;
		end loop;

		return Groups;

	exception
		when E: APQ.SQL_Error =>
			raise INVALID_CONFIGURATION with Error_Message( Query );

	end Get_Groups;
	
	
-- private
	
	function Get_Connection( Auth_Manager: in Authentication_Manager )
		return Connection_Access is
	begin
		if Auth_Manager.Connection /= null then 
			return Auth_Manager.Connection;
	--	elsif Auth_Manager.Connection_Driver /= null then
	--		return Get_Connection( Auth_Manager.Connection_Driver );
		else 
			raise NOT_CONNECTED;
		end if;

	end Get_Connection;

end KOW_Sec.Authentication.DB;

