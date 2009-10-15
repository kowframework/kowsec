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

------------------------------------------------------------------------------
-- This is the base package for KOWSec.                                      --
------------------------------------------------------------------------------



--------------
-- Ada 2005 --
--------------
with Ada.Exceptions;	use Ada.Exceptions;
with Ada.Strings.Unbounded;
with Ada.Text_IO;	use Ada.Text_IO;


-------------
-- Contrib --
-------------
with MD5;

package body KOW_Sec is

	use Criteria_Maps;


	function To_Criteria_Name ( Name : String ) return Criteria_Name is
	begin
		return To_Unbounded_String(Name);
	end To_Criteria_Name;

	function To_Criteria_Descriptor ( Descriptor : String ) return Criteria_Descriptor is
	begin
		return To_Unbounded_String(Descriptor);
	end To_Criteria_Descriptor;


	-- AUXILIAR PROCEDURES AND FUNCTIONS --
	procedure Check_Anonymous_Access( User_Object: in User'Class; Where: in String ) is
		-- This procedure is called by all the procedures and functions that
		-- require the user is logged in.
		--
		-- If the user is anonymous raise an exception with a clear message.
	begin
		if Is_Anonymous( User_Object ) then
			raise ANONYMOUS_ACCESS
				with 
					"Can't get information from anonymous user [" &
					Where &
					"]";
		end if;
	end Check_Anonymous_Access;



	-- SPEC IMPLEMENTATION --



	function To_Access( User_Object: in User ) return User_Access is
	begin
		return new User'( User_Object );
	end To_Access;

	procedure Set_Groups_Timeout( User_Object: in out User; New_Timeout: in Duration ) is
	        -- set the timeout of the groups cache for this user
	begin
		User_Object.Groups_Cache.Set_timeout( New_Timeout );
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
				Locale		: KOW_Lib.Locales.Locale
					:= KOW_Lib.Locales.Default_Locale
		) return String is
		-- return the full name for this user, respecting the locale's conventions
	begin
		Check_Anonymous_Access( User_Object, "Full_Name" );
		return KOW_Lib.Locales.Get_Formated_Full_Name(
			L		=> Locale,
			First_Name	=> To_String( User_Object.First_Name ),
			Last_Name	=> To_String( User_Object.Last_Name )
			);
	end Full_Name;


	function Email( User_Object : in User ) return String is
		-- Return a string with the email address for this user or an empty string
	begin
		return To_String( User_Object.Email );
	end Email;


	function Gravatar_URL( User_Object : in User ) return String is
	begin
		return "http://www.gravatar.com/avatar/" & MD5.Calculate( Email( User_Object ) ) & ".jpg";
	end Gravatar_URL;
	
	procedure Get_Groups( User_object: in out User'Class; Groups: in out Authorization_Groups ) is
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

		User_Object.Groups_Cache.Get_Groups( User_Object, Groups );
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
		Null_String : Unbounded_String := To_Unbounded_String( "" );
	begin
		User_Object.Username := To_Unbounded_String( Anonymous_Username );
		User_Object.First_Name := Null_Unbounded_String;
		User_Object.Last_Name := Null_Unbounded_String;

		-- there is no need to clear the user's cache
		-- as Get_Groups always checks if it's an anonymous user or not.
		--
		--
		-- TODO: implement something to clear this cache in order to
		-- recycle the memory
	end Do_Logout;


	procedure Set_Username( User_Object: in out User; Username: in String ) is
	begin
		User_Object.Username := To_Unbounded_String( Username );
	end Set_Username;
	function Get_Username( User_Object: in User ) return String is
	begin
		return To_String( User_Object.Username );
	end Get_Username;

	procedure Set_First_Name( User_Object: in out User; First_Name: in String ) is
	begin
		User_Object.First_Name := To_Unbounded_String( First_Name );
	end Set_First_Name;
	function Get_First_Name( User_Object: in User ) return String is
	begin
		return To_String( User_Object.First_Name );
	end Get_First_Name;

	procedure Set_Last_Name( User_Object: in out User; Last_Name: in String ) is
	begin
		User_Object.Last_Name := To_Unbounded_String( Last_Name );
	end Set_Last_Name;
	function Get_Last_Name( User_Object: in User ) return String is
	begin
		return To_String( User_Object.Last_Name );
	end Get_Last_Name;

	procedure Set_Email( User_Object : in out User; Email : in String ) is
	begin
		User_Object.Email := To_Unbounded_String( Email );
	end Set_Email;
	function Get_Email( User_Object : in User ) return String is
	begin
		return Email( User_Object );
	end Get_Email;












	----------------
	-- State Vars --
	----------------
	procedure Set_State(	User_Object	: in out User;
				State		: in KOW_Lib.UString_Ordered_Maps.Map) is
		-- set the complete state map
		pragma Inline( Set_State );
	begin
		User_Object.State := State;
	end Set_State;


	procedure Set_State_Variable(	User_Object	: in out User;
					Name		: in String;
					Value		: in String ) is
		-- Set a Session variable for this user
		Pragma Inline( Set_State_Variable );
	begin
		Set_State_Variable( User_Object, To_Unbounded_String( Name ), To_Unbounded_String( Value ) );
	end Set_State_Variable;

	procedure Set_State_Variable(	User_Object	: in out User;
					Name		: in String;
					Value		: in Unbounded_String ) is
		-- Set a Session variable for this user
		Pragma Inline( Set_State_Variable );
	begin
		Set_State_Variable( User_Object, To_Unbounded_String( Name ), Value  );
	end Set_State_Variable;

	procedure Set_State_Variable(	User_Object	: in out User;
					Name		: in Unbounded_String;
					Value		: in Unbounded_String ) is
		-- Set a Session variable for this user
		Pragma Inline( Set_State_Variable );
	begin
		KOW_Lib.UString_Ordered_Maps.Include( User_Object.State, Name, Value );
	end Set_State_Variable;



	function Get_State( User_Object	: in User ) return KOW_Lib.UString_Ordered_Maps.Map is
	begin
		return User_Object.State;
	end Get_State;


	function Get_State_Variable(	User_Object	: in User;
					Name		: in String ) return String is
		-- get the state variable Name
		-- if not set, raise UNOWN_STATE_VARIABLE exception
		Pragma Inline( Get_State_Variable );
	begin
		return To_String( Get_State_Variable( User_Object, To_Unbounded_String( Name ) ) );
	end Get_State_Variable;


	function Get_State_Variable(	User_Object	: in User;
					Name		: in String ) return Unbounded_String is
		-- get the state variable Name
		-- if not set, raise UNOWN_STATE_VARIABLE exception
		Pragma Inline( Get_State_Variable );
	begin
		return Get_State_Variable( User_Object, To_Unbounded_String( Name ) );
	end Get_State_Variable;

	function Get_State_Variable(	User_Object	: in User;
					Name		: in Unbounded_String ) return Unbounded_String is
		-- get the state variable Name
		-- if not set, raise UNOWN_STATE_VARIABLE exception
		Pragma Inline( Get_State_Variable );
	begin
		return KOW_Lib.UString_Ordered_Maps.Element( User_Object.State, Name );
	exception
		when CONSTRAINT_ERROR =>
			raise UNKNOWN_STATE_VARIABLE with To_String( Name );
	end Get_State_Variable;



	procedure Register_Manager( Manager: in out Authentication_Manager_Access ) is
		-- Register a manager so it's usable by KOW_Sec.
	begin
		Append( Managers_Registry, Manager );
	end Register_Manager;


	function Do_Login(	Username: in String;
				Password: in String ) return User'Class is
		--  tries to login the user using the registered managers.
		
		use Authentication_Manager_Vectors;

		C: Authentication_Manager_Vectors.Cursor := First( Managers_Registry );
	begin
		while Has_Element( C )
		loop
			begin
				return Do_Login(	Element( C ).all,
							Username,
							Password);
			exception
				when INVALID_CREDENTIALS => null;
			end;
			C := Next( C );
		end loop;

		raise INVALID_CREDENTIALS with "for username """ & Username & """";
	end Do_Login;





	procedure Internal_Require( User_Object: in out User'Class; Criteria_Object: in out Criteria'Class ) is
	begin
		Require( User(User_object), Criteria_Object );
	end Internal_Require;

	procedure Require(	User_Object	: in out User'Class;
				Name		: in Criteria_Name;
				Descriptor	: in Criteria_Descriptor) is

		My_Criteria: Criteria'Class := Criterias.Create_Criteria( Name, Descriptor );
	begin
		Require( User_Object, My_Criteria );
--		Internal_Require( User_Object, Criteria_Manager.Create_Criteria( Name, Descriptor ) );
	end Require;



	protected body Criteria_Manager is
	
		--  we created a protected type here so our code is task-safe.
		procedure Register( Name: in String; Factory: in Criteria_Factory ) is
			-- We do not check if the factory is null as it has been checked before
			-- in the public register method.
			-- Register the factory in this registry.
		begin
			if Contains( Map, To_Unbounded_String(Name) ) then
				raise DUPLICATED_CRITERIA with "Name: " & Name;
			end if;

			Insert( Map, To_Unbounded_String(Name), Factory );

		end Register;

		procedure Unload( Name: in Criteria_name ) is
			-- remove this criteria from the registry.
		begin
			if Contains( Map, Name ) then
				delete( Map, Name );
			end if;

			raise INVALID_CRITERIA with "Can't unload " & To_String(Name);
		end Unload;


		procedure Empty_Criteria_Registry is
			-- used to unload all the criterias from the registry.

		begin
			Clear( Map );
		end Empty_Criteria_Registry;

		function Create_Criteria( Name : in Criteria_Name; Descriptor: in Criteria_Descriptor ) return Criteria'Class is
			-- create a new criteria object from an already registered criteria type
			-- based on it's name and the given Descriptor.
			Factory: Criteria_Factory;
		begin
			if not Contains( Map, Name ) then
				raise INVALID_CRITERIA with "Can't create " & To_String(Name);
			end if;

			Factory := Element( Map, Name );

			return Factory.all( Descriptor );
		end Create_Criteria;
	end Criteria_Manager;



	-------------
	-- ACTIONS --
	-------------

	procedure Set_Exit_Status(	Action_Object	: in out Base_Action;
					Status		: in Exit_Status;
					Message		: in String ) is
		-- Set the exit status and a message describing what hapenned.
		-- Raise STATUS_CONFLICT when the status has been already defined 
		-- or EXIT_NULL is passed as parameter
		-- If the status is EXIT_FATAL, then FATAL_ERROR exception is raised.
		-- As the action is Limited_Controlled, when deallocated it will log the error.

	begin

		if Action_Object.Status /= EXIT_NULL then
			raise STATUS_CONFLICT with 
				"Exit status already defined as " & 
				Exit_Status'Image( Action_Object.Status );
		elsif Status = EXIT_NULL then
			raise STATUS_CONFLICT with
				"Can't define exit status to null in runtime";
		end if;

		-- if we got to here, all we've got to do is set the status and the message
		Action_Object.Status := Status;
		Action_Object.Message := To_Unbounded_String( Message );
	end Set_Exit_Status;

	
	function Name( Action_Object: in Base_Action ) return String is
	begin
		return Ada.Strings.Unbounded.To_String( Action_Object.Name );
	end Name;
	
	-- the basic action implementation provided:
	

	function New_Action(	Name		: in String;
				Root_Accountant	: in Accountant_Access;
				User_Object	: in User_Access ) return Action is
	begin
		return ( Ada.Finalization.Limited_Controlled with
			Name		=> Ada.Strings.Unbounded.To_Unbounded_String( Name ),
			Creation_Time	=> Ada.Calendar.Clock,
			User_Object	=> User_Object,
			Status		=> EXIT_NULL,
			Root_Accountant => Root_Accountant,
			Message		=> Null_Unbounded_String );

	end New_Action;



	---------------------------
	-- Accounting Management --
	---------------------------

	function New_Accountant(	Service	: in String;
					Root	: Accountant_Access := Root_Acc)
		return Accountant is
		-- This is the constructor for accountants.
		-- It's far preferable to use constructors instead
		-- of simply instantiate the type.
	begin
		return (
			Ada.Finalization.Limited_Controlled with 
				Creation_Time	=> Ada.Calendar.Clock,
				Service		=> To_Unbounded_String( Service ),
				Root		=> Root );

	end New_Accountant;


	function Service( Accountant_Object: in Accountant ) return Unbounded_String is
		-- Gets the current service name
		-- The service name is a string representing the accountant.
		Pragma Inline( Service );
	begin
		return Accountant_Object.Service;
	end Service;
	
	function Service( Accountant_Object: in Accountant ) return String is
		-- same as the Service() return unbounded_string
		Pragma Inline( Service );
	begin
		return To_String( Service( Accountant_Object ) );
	end Service;


	procedure Flush( Accountant_Object: in out Accountant ) is
		-- Flushes the current acountant.
	begin
		null;
		-- there is no need to flush the default implementation of accountant
		-- as it logs in realtime to stdout and errout.
	end Flush;


	procedure Log( Status, Path, Message: in String; Output: in File_Type ) is
		Pragma Inline( Log );
	begin
		Put(	Output, 
			"["	&
			Status	&
			" @ "	&
			Path	&
			"] "	&
			Message );
		New_Line( Output );
	end Log;


	procedure Log( Child : Action'Class; Path: in String; Output: in File_Type ) is
		Pragma Inline( Log );

		Status: Exit_Status := Child.Status;
	begin
		if Status = Exit_Null then
			Status := Exit_Success;
		end if;
		Log(	Status	=> Exit_Status'Image( Status ),
			Message	=> To_String( Child.Message ),
			Path	=> Path & Name( Child ),
			Output	=> Output );
	end Log;


	procedure Log( Child: in Action'Class; Path: in String ) is
	begin
		if Child.Status = EXIT_SUCCESS OR Child.Status = EXIT_NULL then
			Log( Child => Child, Path => Path, Output => Standard_Output );
		else
			Log( Child => Child, Path => Path, Output => Standard_Error );
		end if;
	end Log;


	procedure Delegate(	To_Accountant	: in out Accountant;
				Child		: in Action'Class ) is
		-- Called to log a child action

		function p_array( Serv: in Unbounded_String ) return Path_Array is
			Pragma Inline( P_Array );
			P: Path_Array( 1 .. 1 ) := (1 => Serv );
		begin
			return P;
		end P_array;
		

	begin
		if To_Accountant.Root = NULL then
			Log(	Child	=> Child, 
				Path	=> Service( To_Accountant ));
		else
			Delegate(	To_Accountant	=> To_Accountant.Root.all,
					Relative_Path	=> P_Array( Service( To_Accountant ) ),
					Child		=> Child );
		end if;
	end Delegate;
	
	procedure Delegate(	To_Accountant	: in out Accountant;
				Relative_Path	: in Path_Array;
				Child		: in Action'Class ) is
		-- delegates the action to from the child accountant to the to_accountant.
		-- Relative_path is the relative path from the to_accountant to it's child.
		-- For instance:
		-- 	Acc1->Acc2->Action1
		-- If Acc2 delegates Action1 to Acc2, it'll call:
		-- 	Delegate(	To_Accountant	=> Acc1,
		-- 			Relative_Path	=> ( Service( Acc2 ) ),
		-- 			Child		=> Action1 );

		function Build_Path_Arr( Arr: in Path_Array ) return String is
		begin
			if Arr'Length = 0 then
				return "";
			else
				return	To_String( Arr(Arr'First) )	&
					"/"				&
					Build_Path_Arr( Arr(Arr'First + 1 .. Arr'Last ) );
			end if;
		end Build_Path_Arr;


		function Build_Path( Arr: in Path_Array ) return String is
		begin
			return Service( To_Accountant ) & Build_Path_Arr( Arr );
		end Build_Path;

	begin
		if To_Accountant.Root = NULL then
			Log(	Child	=> Child,
				Path	=> Build_Path( Relative_Path ) );
		else
			declare
				function Get_Path_Array return Path_Array is
					P: Path_Array( 1 .. Relative_Path'Length + 1 );
				begin
					P(1) := Service( To_Accountant );
					P(2 .. P'Last) := Relative_Path;
					return P;
				end Get_Path_Array;
			begin
				Delegate(	To_Accountant	=> To_Accountant.Root.all,
						Relative_Path	=> Get_Path_Array,
						Child		=> Child );
			end;
		end if;
	end Delegate;


	

	-----------------------------------
	-- CLASSWIDE METHODS DECLARATION --
	-----------------------------------

	----------------------------------------
	-- User Management - accounting aware --
	----------------------------------------
	function Do_Login(	Manager:	 in Authentication_Manager'Class;
				Username:	 in String;
				Password:	 in String;
				Root_Accountant: in Accountant_Access ) return User'Class is
		-- This function logs any error returned by Do_Login method
		-- As it's a class wide function, it dynamic dispatching is enabled
		-- for both Authentication_Manager and Accountant types

		My_Action: Base_Action'Class := New_Action(
			Name		=> "Do_Login",
			Root_Accountant	=> Root_Accountant,
			User_Object	=> Null );
	begin
		declare
			Usr: User'Class := Do_Login( Manager, Username, Password );
		begin
			-- if I got here I managed to login! woot!
			Set_Exit_Status(
				My_Action,
				Exit_Success,
				"Logged in as [" & Identity( Usr ) & "]"
				);
			return Usr;
		end;
	exception
		when E: INVALID_CREDENTIALS =>
			Set_Exit_Status(
				My_Action,
				Exit_Error,
				"INVALID_CREDENTIALS :: " & Exception_Message( E )
				);
			Reraise_Occurrence( E );
		when E: Others =>
			Set_Exit_Status(
				My_action,
				Exit_Warning,
				Exception_Name( E ) & " :: " & Exception_Message( E )
				);
			Reraise_Occurrence( E );
	end Do_Login;



	function Do_Login(	Username	: in String;
				Password	: in String;
				Root_Accountant	: in Accountant_Access ) return User'Class is
		My_Acc: Accountant_Access := new Accountant'(New_Accountant( "Login_Service", Root_Accountant ));

		use Authentication_Manager_Vectors;

		C: Authentication_Manager_Vectors.Cursor := First( Managers_Registry );
	begin
		while Has_Element( C )
		loop
			begin
				return Do_Login(	Element( C ).all,
							Username,
							Password,
							My_Acc);
			exception
				when INVALID_CREDENTIALS => null;
			end;
			C := Next( C );
		end loop;

		raise INVALID_CREDENTIALS;

	end Do_Login;



	procedure Do_Logout(	User_Object:	 in out User_Access;
				Root_Accountant: in Accountant_Access ) is
		-- This function logs any error returned by Do_Logout method
		-- As it's a class wide function, it dynamic dispatching is enabled
		-- for both Authentication_Manager and Accountant types
		My_Action: Base_Action'Class := New_Action(
				Name		=> "Do_Logout",
				Root_Accountant	=> Root_Accountant,
				User_Object	=> User_Object );
	begin
		Do_Logout( User_Object.all );
	exception
		when E: Others =>
			Set_Exit_Status(
				My_action,
				Exit_Warning,
				Exception_Name( E ) & " :: " & Exception_Message( E )
				);
			Reraise_Occurrence( E );

	end Do_Logout;

	-------------------------------------------------
	-- Authorization Management - accounting aware --
	-------------------------------------------------


	procedure Require(	User_Object:	 in User_Access;
				Criteria_Object: in Criteria'Class; 
				Root_Accountant: in out Accountant_Access) is
		-- matches the user against some criteria.
		-- raise ACCESS_DENIED if the user fails this criteria.
		-- logs any error that might occur using the root_accountant
		My_Action: Base_Action'Class := New_Action(
				Name		=> "Require",
				Root_Accountant	=> Root_Accountant,
				User_Object	=> User_Object );
	begin
		Require(	User_Object	=> User_Object.all,
				Criteria_Object	=> Criteria_Object );

		-- if it got here, the user has been accepted.
		Set_Exit_Status(
			My_Action,
			Exit_Success,
			"[" & Get_Type( Criteria_Object ) & "] " & Describe( Criteria_Object )
			);
	exception
		when E: Others =>
			Set_Exit_Status(
				My_action,
				Exit_Warning,
				Exception_Name( E ) & " :: " & Exception_Message( E )
				);
			Reraise_Occurrence( E );

	end Require;

	procedure Require(	User_Object	: in out User_Access;
				Name		: in Criteria_Name;
				Descriptor	: in Criteria_Descriptor;
				Root_Accountant	: in out Accountant_Access) is
		-- matches the user against some criteria that's created at run time.
		-- raises 
		-- 	ACCESS_DENIED if the user fails this criteria.
		-- 	INVALID_CRITERIA if trying to create a criteria that isn't registered
		-- 	INVALID_CRITERIA_DESCRIPTOR if the descriptor is invalid for this criteria
		-- logs any erro that might occur using the root_accountant
		My_Action: Base_Action'Class := New_Action(
				Name		=> "Require",
				Root_Accountant	=> Root_Accountant,
				User_Object	=> User_Object );
	begin
		Require(	User_Object	=> User_Object.all,
				Name		=> Name,
				Descriptor	=> Descriptor );

		Set_Exit_Status(
			My_Action,
			Exit_Success,
			"[" & To_String( Name ) & "] " & To_String( Descriptor ) );
	exception
		when E: INVALID_CRITERIA => 
			Set_Exit_Status(
				My_action,
				Exit_Error,
				Exception_Name( E ) & " :: " & Exception_Message( E )
				);
			Reraise_Occurrence( E );

		when E: INVALID_CRITERIA_DESCRIPTOR =>
			Set_Exit_Status(
				My_action,
				Exit_Error,
				Exception_Name( E ) & " :: " & Exception_Message( E )
				);
			Reraise_Occurrence( E );

		when E: Others =>
			Set_Exit_Status(
				My_action,
				Exit_Warning,
				Exception_Name( E ) & " :: " & Exception_Message( E )
				);
			Reraise_Occurrence( E );
	end Require;




	
	-- PRIVATE --

	protected body Groups_Cache_Type is 
		function Should_Update return Boolean is
		begin
			if
				Authorization_Group_Vectors.Is_Empty( Groups )	OR
				Need_Update	= true OR
				(
					Timeout /= 0.0 AND THEN 
					Last_Update < (Clock - Timeout)
				)
			then
				return true;
		 	else 
		 		return false;
		 	end if;
		
		end Should_Update;
		
		procedure Update( User_Object: in User'Class; Managers: in Authentication_Managers ) is
			-- update the groups and then set:
			-- 	need_update := false
			-- 	last_update := now

			Empty: Authorization_Groups;
			-- it's used when there is nothing to be returned from Groups.
			


			function Iterate( C: in Authentication_Manager_Vectors.Cursor ) return Authorization_Groups is
				My_Groups	: Authorization_Groups;
				-- Groups I'll get in this iteration, using the current Manager (if any)
				Next_Groups	: Authorization_Groups;
				-- Groups I'll get in the next manager + the other manager + ...
			begin

				if Authentication_Manager_Vectors.Has_Element( C ) then
					Next_Groups := Iterate( Authentication_Manager_Vectors.Next( C ) );

					My_Groups := Get_Groups(
						Authentication_Manager_Vectors.Element( C ).all,
						User_Object );

					Authorization_Group_Vectors.Append(
						Container => My_Groups,
						New_Item => Next_Groups
						);
				end if;
			
				return My_Groups;
			end Iterate;
		begin

			Check_Anonymous_Access( User_Object, "Groups_Cache_Type.Update" );

			Authorization_Group_Vectors.Clear( Groups );

			if Is_Empty( Managers ) then
				return; -- there is nothing to be feched if manager is null
			end if;


			Groups := Iterate ( First( Managers ) );

			-- if the update has been a success, then..
			Need_Update := False;
			Last_Update := Clock;
		end Update;

		procedure Get_Groups( User_Object: in User'Class; Auth_Groups: out Authorization_Groups ) is
			-- checks if the groups should be update
			-- 	if true, do the update
			-- 	if false, don't update.
			-- return the current groups list
		begin
			if Should_Update then
				Update( User_Object, Managers_Registry);
			end if;

			Auth_Groups := Groups;
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


	overriding
	procedure Finalize( A: in out Action ) is
		-- used to flush the action.
	begin
		Delegate( A.Root_Accountant.all, A );
	end Finalize;

begin
	Root_Acc := new Accountant'( New_Accountant( Service => "/", Root => null ) );

end KOW_Sec;
