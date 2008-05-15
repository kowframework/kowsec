------------------------------------------------------------------------------
--                                                                          --
--                          Ada Works :: Security                           --
--                                                                          --
--                                Ada Works                                 --
--                                                                          --
--                                 S p e c                                  --
--                                                                          --
--        Copyright (C) 2007-2008, Ydea Desenv. de Softwares Ltda           --
--                                                                          --
--                                                                          --
-- AwSec; free software; you can redistribute it  and/or modify it under  --
-- terms of the  GNU General Public License as published  by the Free Soft- --
-- ware  Foundation;  either version 2,  or (at your option) any later ver- --
-- sion. AwSec; distributed in the hope that it will be useful, but WITH- --
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
-- This; the Aw_Sec.Authentication.DB package                              --
-------------------------------------------------------------------------------


with APQ;	use APQ;

package Aw_Sec.Authentication.DB is



	INVALID_CONFIGURATION: Exception;


	type Connection_Access is access all Root_Connection_Type'Class;
	
	type Authentication_Manager is new Aw_Sec.Authentication_Manager
		with private;
	
	function New_Authentication_Manager( Conn_Access: Connection_Access )
		return Authentication_Manager;


	procedure Set_Connection( Manager: in out Authentication_Manager; Conn_Access: Connection_Access );

	-- User Table Name
	procedure Set_Users_Table(	Manager:  in out Authentication_Manager;
					Users_Table_Name : in String );
	function Get_Users_Table ( Manager:  in Authentication_Manager ) return String;

	-- Id Field of the Users Tables 
	procedure Set_User_Id_Field(	Manager:  in out Authentication_Manager;
					User_Id_Field_Name : in String );
	function Get_User_Id_Field ( Manager:  in Authentication_Manager ) return String;

	-- Username Field Name
	procedure Set_Username_Field(	Manager:  in out Authentication_Manager;
					Name : in String );
	function Get_Username_Field ( Manager:  in Authentication_Manager ) return String;

	-- Password Field Name
	procedure Set_Password_Field(	Manager:  in out Authentication_Manager;
					Pwd : in String );
	function Get_Password_Field ( Manager:  in Authentication_Manager ) return String;

	-- First_Name Field Name
	procedure Set_First_Name_Field( Manager:  in out Authentication_Manager;
					Name : in String );
	function Get_First_Name_Field  ( Manager:  in Authentication_Manager ) return String;

	-- Last_Name Field Name
	procedure Set_Last_Name_Field(	Manager:  in out Authentication_Manager;
					Name : in String );
	function Get_Last_Name_Field  (	Manager:  in Authentication_Manager ) return String;

	-- Groups Table Name
	procedure Set_Groups_Table(	Manager:  in out Authentication_Manager;
					Groups_Table_Name : in String );
	function Get_Groups_Table  ( Manager:  in Authentication_Manager ) return String;
	
	-- User_Id Field of the Groups Tables 
	procedure Set_Groups_Username_Field(	Manager:  in out Authentication_Manager;
						Name : in String );
	function Get_Groups_Username_Field ( Manager:  in Authentication_Manager ) return String;

	-- Group_Name Field Name
	procedure Set_Group_Name_Field(	Manager:  in out Authentication_Manager;
					Name : in String );
	function Get_Group_Name_Field (	Manager:  in Authentication_Manager ) return String;

	
	
	function Do_Login(	Manager:  in Authentication_Manager;
	                  	Username: in String;
	                  	Password: in String ) return User'Class;
	-- Login the user, returning a object representing it.
        -- This object might be a direct instance of User or a subclass.
        -- It's this way so the authentication method might have
        -- a user with extended properties.
	 
	 
	function Get_Groups(    Manager:        in Authentication_Manager;
	                        User_Object:    in User'Class )
		return Authorization_Groups;
	-- Return all the groups for this user
	-- It's implemented in the manager for 2 reasons:
	--      1. this way we can store the users and the groups in
	--         different managers.
	--      2. the information on how to obtain the groups information
	--         doesn't belong to the user itself.
	 

	


private

	function Get_Connection( Auth_Manager: in Authentication_Manager )
		return Connection_Access;

	type Authentication_Manager is new Aw_Sec.Authentication_Manager with
	record
		Connection		: Connection_access;
	--	Connection_Driver	: APQ.Connection_Driver;
		
		-- Configuration File Properties
		Users_Table		: Unbounded_String;
		User_Id_Field 		: Unbounded_String;
		Username_Field 		: Unbounded_String;
		Password_Field 		: Unbounded_String;
		First_Name_Field 	: Unbounded_String;
		Last_Name_Field		: Unbounded_String;
		
		Groups_Table	 	: Unbounded_String;
		Groups_Username_Field 	: Unbounded_String;
		Group_Name_Field 	: Unbounded_String;
	
	end record;

end Aw_Sec.Authentication.DB;
