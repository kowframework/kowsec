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
-- This is the Aw_Sec.Authentication.DB package.                                --
-------------------------------------------------------------------------------



package body Aw_Sec.Authentication.DB is


	function New_Authentication_Manager( Conn_Access: Connection_Access )
		return Authentication_Manager is
	
		Auth_Manager: Authentication_Manager;
	begin
		Auth_Manager.Connection := Conn_Access;
		
		return Auth_Manager;
	end New_Authentication_Manager;



	-- User Table Name
	procedure Set_User_Table(	Manager:  in Authentication_Manager;
					User_Table_Name : in String 		) is
	begin
		Manager.User_Table := To_Unbounded_String( User_Table_Name );	
	end Set_User_Table;

	function Get_User_Table ( Manager:  in Authentication_Manager ) return String is
	begin
		return To_String( Manager.User_Table );
	end Get_User_Table;


	-- Id Field of the Users Tables 
	procedure Set_User_Id_Field( 	Manager:  in Authentication_Manager;
					User_Id_Field_Name : in String ) is
	begin
		Manager.User_Id_Field := User_Id_Field_Name;
	end Set_User_Id_Field;

	function Get_User_Id_Field( Manager:  in Authentication_Manager )  return String is
	begin
		return To_String( Manager.User_Id_Field);
	end Get_User_Id_Field;


	-- Username Field Name
	procedure Set_Username_Field( 	Manager:  in Authentication_Manager;
					Name : in String ) is
	begin
		Manager.Username := Name;
	end Set_Username_Field;

	function Get_Username_Field( Manager:  in Authentication_Manager )  return String is
	begin
		return To_String( Manager.Username );
	end Get_Username_Field;


	-- Password Field Name
	procedure Set_Password_Field( 	Manager:  in Authentication_Manager;
					Pwd : in String ) is
	begin
		Manager.Password := Pwd;	
	end Set_Password_Field;

	function Get_Password_Field( Manager:  in Authentication_Manager )  return String is
	begin
		return To_String ( Manager.Password );
	end Get_Password_Field;


	-- First_Name Field Name
	procedure Set_First_Name_Field( 	Manager:  in Authentication_Manager;
						Name : in String ) is
	begin
		Manager.First_Name := Name;
	end Set_First_Name_Field;

	function Get_First_Name_Field( Manager:  in Authentication_Manager )  return String is
	begin
		return To_String( Manager.First_Name );
	end Get_First_Name_Field;


	-- Last_Name Field Name
	procedure Set_Last_Name_Field( 	Manager:  in Authentication_Manager;
					Name : in String ) is
	begin
		Manager.Last_Name := Name;
	end Set_Last_Name_Field;

	function Get_Last_Name_Field( Manager:  in Authentication_Manager )  return String is
	begin
		return To_String( Manager.Last_Name );
	end Get_Last_Name_Field;


	-- Groups Table Name
	procedure Set_Groups_Table( 	Manager:  in Authentication_Manager;
					Groups_Table_Name : in String ) is
	begin
		Manager.Groups_Table := Groups_Table_Name;
	end Set_Groups_Table;

	function Get_Groups_Table( Manager:  in Authentication_Manager )  return String is
	begin
		return To_String( Manager.Groups_Table );
	end Get_Groups_Table;
	
	
	-- Username Field of the Groups Tables 
	procedure Set_Groups_Username_Field( 	Manager:  in Authentication_Manager;
						Name : in String ) is
	begin	
		Manager.Groups_Username := Name;
	end Set_Groups_Username_Field;

	function Get_Groups_Username_Field( Manager:  in Authentication_Manager )  return String is
	begin
		return To_String( Manager.Groups_Username );
	end Get_Groups_Username_Field;

	-- Group_Name Field Name
	procedure Set_Group_Name_Field( 	Manager:  in Authentication_Manager;
						Name : in String ) is
	begin
		Manager.Group_Name_Field := Name;		
	end Set_Group_Name_Field;

	function Get_Group_Name_Field( Manager:  in Authentication_Manager )  return String is
	begin
		return To_String( Manager.Group_Name_Field ); 
	end Get_Group_Name_Field;
	

	-- helper function to get the Query's Value at Column Column_Name
	function Value(	Query : in  Root_Query_Type; 
			Column_Name : in String ) return String is
	begin
		return Value( Query, Column_Index( Query, Column_Name) );
	end Value;
	

	-- verify if exists the Username with corresponding Password
	-- at the Users Table.
	function Do_Login(	Manager:  in Authentication_Manager;
	                  	Username: in String;
	                  	Password: in String ) return User'Class is
		
		Query: Root_Query_Type'Class;
		Required_User : User;
		Connection : Root_Connection_Type;
	
	begin
		Connection := Get_Connection(Manager);
		Query := New_Query( Connection );

 		Prepare( Query,  "SELECT * from " & Get_Users_Table &
			" where " &  Get_Username_Field & "=");
		Append_Quoted( Query, Connection, Username);
 	
		Execute( Query, Connection );

		if Username = Value(Query, Get_Username_Field) and then
			Password = Value(Query, Get_Password_Field) then
			
			Required_User.Username.all := Value(Query, Get_Username_Field);
			Required_User.First_Name.all := Value(Query, Get_First_Name_Field);
			Required_User.Last_Name.all := Value(Query, Get_Last_Name_Field);
			
			return Required_User;
		else 
			raise INVALID_CREDENTIALS;
		end if;
		
	end Do_Login;

	
	function Get_Groups(    Manager:	in Authentication_Manager;
	                        User_Object:	in User'Class )
		return Authorization_Groups is


        	function To_Authorization_Group is
         		new Ada.Unchecked_Conversion (Source => Unbounded_String,
                	Target => Authorization_Group);

		Query: Root_Query_Type'Class;
		Connection : Root_Connection_Type;
		Groups : Authorization_Groups;
	begin	
		Connection := Get_Connection(Manager);
		Query := New_Query( Connection );

 		Prepare( Query,  "SELECT * from " & Get_Groups_Table &
			" where " &  Get_Groups_Username_Field & "=");
		Append_Quoted( Query, Connection, User_Object.Username);
 	
		Execute( Query, Connection );

		if Value(Query, Get_Group_Name_Field) /= Null_Unbounded_String then
			loop
				begin
					Fetch(Query); 
				exception
					when No_Tuple => exit;
				end;
	
				Append( Groups,
					To_Authorization_Group(	To_Unbounded_String(
						Value( Query, Get_Group_Name ) ) ) ) ;
			end loop;

		end if;

		return Groups;

	end Get_Groups;
	
	
-- private
	
	function Get_Connection( Auth_Manager: in Authentication_Manager )
		return Root_Connection_Type'Class is
	begin
		if Auth_Manager.Connection /= null then 
			return Auth_Manger.connection.all;
		elsif Auth_Manager.Connection_Driver /= null then
			return Get_Connection( Auth_Manager.Connection_Driver );
		else 
			raise NOT_CONNECTED;
		end if;

	end Get_Connection;

end Aw_Sec.Authentication.DB;

