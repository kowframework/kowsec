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
-- This is the Aw_Sec.Authentication.DB package                              --
-------------------------------------------------------------------------------


with Aw_Sec; 

with APQ;	use APQ;

package Aw_Sec.Authentication.DB is
	
	type Connection_Access is access all Root_Connection_Type'Class;
	
	type Authentication_Manager is new Aw_Sec.Authentication_Manager
		with private;
	
	function New_Authentication_Manager( Conn_Access: Connection_Access )
		return Authentication_Manager;


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
	 
	function Get_Groups( User_object: in User'Class )
		return Authorization_Groups;

	
	INVALID_CREDENTIALS: Exception;
	-- should be raised when login fails.

	ANONYMOUS_ACCESS: Exception;
	-- should be raised when trying to get information from 
	-- an anonymous user.


private

	function Get_Connection( Auth_Manager: in Authentication_Manager )
		return Root_Connection_Type'Class;

	type Authentication_Manager is new Aw_Sec.Authentication_Manager with
	record
		Connection: Connection_access;
		Connection_Driver : APQ.Connection_Driver;
	end record;

end Aw_Sec.Authentication.DB;
