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
-- This is the base package for AwSec.                                       --
-------------------------------------------------------------------------------

package body Aw_Sec is

	procedure Check_Anonymous_Access( User_Object: in User; Where: in String ) is
	begin
		if Is_Anonymous( User_Object ) then
			raise ANONYMOUS_ACCESS
				with 
					"Can't get information from anonymous user [" &
					Where &
					"]";
		end if;
	end Check_Anonymous_Access;


	procedure Set_Groups_Timeout( User_Object: in out User; New_Timeout: in Duration ) is
	        -- set the timeout of the groups cache for this user
	begin
		User_Object.Groups.Set_timeout( New_Timeout );
	end Set_Groups_Timeout;

	procedure Update_Groups( User_Object: in out User ) is
		-- Tells the user that his groups should be updated in the
		-- next request to Get_Groups.
	begin
		User_Object.Groups_Cache.Set_Update;
	end Update_Groups;


	function Identity( User_Object: in User ) return String is
		-- Return a string identifying the current user. Usually it's the username
		-- but one could implement other methods, such as a numeric id for this user
	begin
		return To_String( User_Object.Username );
	end Identity;


	function Full_Name(	User_Object	: in User;
				Locale		: Aw_Lib.Locales.Locale
					:= Aw_Lib.Locales.Default_Locale
		) return String is
		-- return the full name for this user, respecting the locale's conventions
	begin
		Check_Anonymous_Access( User_Object, "Full_Name" );
		return Aw_Lib.Locales.Format_Full_Name(
			Locale		=> Locale,
			First_Name	=> To_String( First_Name ),
			Last_Name	=> To_String( Last_Name )
			);
	end Full_Name;

	
	procedure Get_Groups( User_object: in User'Class; Groups: in out Authorization_Groups ) is
	-- Get the groups for this user.
	-- There are two things to notice here:
	-- 	1. This method is task safe. It means it will never return something
	--	 while the user's group list is being generated.
	--	2. The user's group is auto-updated by using the methods:
	--		. Set_Groups_Timeout( User, Duration);
	--		. Update_Groups( User );


	begin
		Check_Anonymous_Access( User_Object, "Get_Groups" );

		-- Notice:
		-- According Ada2005 RM the Vector needs finalization.
		-- For this reason we don't deallocate the memory here.

		Groups := User_Object.Groups_Cache.Get_Groups;
	end Get_Groups;

	function Is_Anonymous(	User_Object: in User ) return Boolean is
	-- Return true if this user isn't logged in.
	-- 
	-- Even though this isn't an abstract method, one can overwrite it
	-- in order to log hits from anonymuos users when using determined Manager.
		Username: String := To_String( User_Object.Username );
	begin
		if Username'Length = 0  OR Username = Anonymous_Username then
			return true;
		else
			return false;
		end if;
	end Is_Anonymous;

	procedure Do_Logout( User_Object: in out User ) is
	-- Not only make sure the user is logged out but also
	-- Make sure Is_Anonymous returns true for now on for this user.
		Null_String := To_Unbounded_String( "" );
	begin
		User.Username := Anonymous_Username;
		User.First_Name := Null_Unbounded_String;
		User.Last_Name := Null_Unbounded_String;

		-- there is no need to clear the user's cache
		-- as Get_Groups always checks if it's an anonymous user or not.
		--
		--
		-- TODO: implement something to clear this cache in order to
		-- recycle the memory
	end Do_Logout;



	procedure Require(	User_Object	: in out User'Class;
				Name		: in Criteria_Name;
				Pattern		: in Criteria_Descriptor) is
		My_Criteria: Criteria_Manager.Create_Criteria( Name, Pattern );
	begin
		Require( User_Object, My_Criteria );
	end Require;




	protected body Criteria_Manager is
		use Criteria_Maps;
		--  we created a protected type here so our code is task-safe.
		procedure Register( Name: in String; Factory: in Criteria_Factory ) is
			-- We do not check if the factory is null as it has been checked before
			-- in the public register method.
			-- Register the factory in this registry.
		begin
			if Contains( Map, Name ) then
				raise DUPICATED_CRITERIA with "Name: " & Name;
			end if;

			Insert( Map, Name, Factory );

		end Register;

		procedure Unload( Name: in Criteria_name ) is
			-- remove this criteria from the registry.
		begin
			if Contains( Map, Name ) then
				delete( Map, Name );
			end if;

			raise INVALID_CRITERIA with "Can't unload " & Name;
		end Unload;


		procedure Empty_Criteria_Registry is
			-- used to unload all the criterias from the registry.

		begin
			while not Is_Empty( Map )
			loop
				Delete_First( Map );
			end loop;
		end Emtpy_Criteria_Registry;

		function Create_Criteria( Name, Pattern: in String ) return Criteria'Class is
			-- create a new criteria object from an already registered criteria type
			-- based on it's name and the given pattern.
			Factory: Criteria_Factory;
		begin
			if not Contains( Map, Name ) then
				raise INVALID_CRITERIA with "Can't create " & Name;
			end if;

			Factory :=  Element( Name );

			return Factory.all( Pattern );
		end Create_Criteria;
	end Criteria_Manager;



	-- PRIVATE --

	protected body Groups_Cache_Type is 
		function Should_Update return Boolean is
		begin
			if
				Authorization_Groups = NULL	OR
				Need_Update = true		OR
				(
					Timeout /= 0.0 AND THEN 
					Last_Update < (Now - Timeout)
				)
			then
				return true;
		 	else 
		 		return_code := false;
		 	end if;
		
		end Should_Update;
		
		procedure Update( User_Object: in User'Class; Managers: in Authorization_Manager_Vectors.Vector ) is
			-- update the groups and then set:
			-- 	need_update := false
			-- 	last_update := now

			Empty: Authorization_Groups(1 .. 0);
			-- it's used when there is nothing to be returned from Groups.
			
			procedure Free is new Unchecked_Deallocation(
				Object	=> Authorization_Groups
				);


			function Iterate( i: in Integer ) return Authorization_Groups is
				My_Groups := Get_Groups( Managers(i).all, User_Object );
				Next: Integer := I + 1;
			begin
				if Next <= Managers'Last then
					declare
						Next_Groups: Authorization_Groups := Iterate( Next );
					begin
						if Next_Groups'Length > 0 then
							if My_Groups'Length > 0 then
								return My_Groups & Next_Groups;
							else
								return Next_Groups;
							end if;
						end if;
					end;
				end if;

				return My_Groups;
				-- If it hasn't fetched anything from the next groups
				-- return the current groups list.
			end Iterate;
		begin

			Check_Anonymous_Access( User_Object, "Groups_Cache_Type.Update" );

			Free( Groups );

			-- notice we don't check if the user is anonymous
			-- it's due the check if

			if Managers'Length = 0 then
				return; -- there is nothing to be feched if manager is null
			end if;


			-- now we try to fetch the groups information for
			-- the current user:
			declare
				My_Groups : Authorization_Groups := Iterate ( Managers'First );
			begin
				if My_Groups'Length /= 0 then
					Groups := new Authorization_Groups( 1 .. My_Groups'Length );
					Groups.all := My_Groups;
				end if;
			end;

			-- if the update has been a success, then..
			Need_Update := False;
			Last_Update := Now;
		end Update;

		function Get_Groups return Authorization_Groups is
			-- checks if the groups should be update
			-- 	if true, do the update
			-- 	if false, don't update.
			-- return the current groups list
			Empty: Authorization_Groups( 1 .. 0 );
		begin
		end Get_Groups;

		procedure Set_Update is
			-- tell this cache it should be updated in the next call
			-- of Get_Groups.
		begin
			Need_Update := True;
		end Set_Update;
		
		procedure Set_Timeout( New_Timeout: in Duration ) is
		begin
			Timeout := New_Timeout;
		end Set_Timeout;
	end Groups_Cache_Type;





end Aw_Sec;
