------------------------------------------------------------------------------
--                                                                          --
--                          KOW Framework Security                          --
--                                                                          --
--                              KOW Framework                               --
--                                                                          --
--                                 B o d y                                  --
--                                                                          --
--             Copyright (C) 2007-2009, KOW Framework Project               --
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




--------------
-- Ada 2005 --
--------------
with Ada.Exceptions;
with Ada.Text_IO;		use Ada.Text_IO;


package body KOW_Sec.Accounting is
	-------------
	-- ACTIONS --
	-------------

	procedure Set_Exit_Status(
					Action	: in out Base_Action_Type;
					Status	: in     Exit_Status;
					Message	: in     String
				) is
		-- Set the exit status and a message describing what hapenned.
		-- Raise STATUS_CONFLICT when the status has been already defined 
		-- or EXIT_NULL is passed as parameter
		-- If the status is EXIT_FATAL, then FATAL_ERROR exception is raised.
		-- As the action is Limited_Controlled, when deallocated it will log the error.

	begin

		if Action.Status /= EXIT_NULL then
			raise STATUS_CONFLICT with 
				"Exit status already defined as " & 
				Exit_Status'Image( Action.Status );
		elsif Status = EXIT_NULL then
			raise STATUS_CONFLICT with
				"Can't define exit status to null in runtime";
		end if;

		-- if we got to here, all we've got to do is set the status and the message
		Action.Status := Status;
		Action.Message := To_Unbounded_String( Message );
	end Set_Exit_Status;

	
	function Name( Action : in Base_Action_Type ) return String is
	begin
		return Ada.Strings.Unbounded.To_String( Action.Name );
	end Name;
	
	-- the basic action implementation provided:
	

	function New_Action(
				Name		: in String;
				Root_Accountant	: in Accountant_Access;
				User		: in User_Data_Type := KOW_Sec.Anonymous_User
			) return Action_Type is
	begin
		return ( Ada.Finalization.Limited_Controlled with
					Name		=> Ada.Strings.Unbounded.To_Unbounded_String( Name ),
					Creation_Time	=> Ada.Calendar.Clock,
					User		=> User,
					Status		=> EXIT_NULL,
					Root_Accountant => Root_Accountant,
					Message		=> Null_Unbounded_String
				);

	end New_Action;



	---------------------------
	-- Accounting Management --
	---------------------------

	function New_Accountant(
				Service	: in String;
				Root	: in Accountant_Access := Root_Acc
			) return Accountant_Type is
		-- This is the constructor for accountants.
		-- It's far preferable to use constructors instead
		-- of simply instantiate the type.
	begin
		return ( Ada.Finalization.Limited_Controlled with 
				Creation_Time	=> Ada.Calendar.Clock,
				Service		=> To_Unbounded_String( Service ),
				Root		=> Root
			);

	end New_Accountant;


	function Service( Accountant: in Accountant_Type ) return Unbounded_String is
		-- Gets the current service name
		-- The service name is a string representing the accountant.
		Pragma Inline( Service );
	begin
		return Accountant.Service;
	end Service;
	
	function Service( Accountant: in Accountant_Type ) return String is
		-- same as the Service() return unbounded_string
		Pragma Inline( Service );
	begin
		return To_String( Service( Accountant ) );
	end Service;


	procedure Flush( Accountant: in out Accountant_Type ) is
		-- Flushes the current acountant.
	begin
		Ada.Text_IO.Flush( Ada.Text_IO.Standard_Output );
		Ada.Text_IO.Flush( Ada.Text_IO.Standard_Error );
	end Flush;


	procedure Log( Status, Path, Message: in String; Output: in File_Type ) is
		Pragma Inline( Log );
	begin
		Put( Output, "[" & Status & " @ " & Path & "] " & Message );
		New_Line( Output );
	end Log;


	procedure Log( Child : Base_Action_Type'Class; Path: in String; Output: in File_Type ) is
		Pragma Inline( Log );
		Status: Exit_Status := Child.Status;
	begin
		if Status = Exit_Null then
			Status := Exit_Success;
		end if;
		Log(	
				Status	=> Exit_Status'Image( Status ),
				Message	=> To_String( Child.Message ),
				Path	=> Path & Name( Child ),
				Output	=> Output
			);
	end Log;


	procedure Log( Child: in Base_Action_Type'Class; Path: in String ) is
	begin
		if Child.Status = EXIT_SUCCESS OR Child.Status = EXIT_NULL then
			null;
			--Log( Child => Child, Path => Path, Output => Standard_Output );
		else
			Log( Child => Child, Path => Path, Output => Standard_Error );
		end if;
	end Log;


	procedure Delegate(
				To_Accountant	: in out Accountant_Type;
				Child		: in     Base_Action_Type'Class
			) is
		-- Called to log a child action

		function p_array( Serv: in Unbounded_String ) return Path_Array is
			Pragma Inline( P_Array );
			P: Path_Array( 1 .. 1 ) := (1 => Serv );
		begin
			return P;
		end P_array;

	begin
		if To_Accountant.Root = NULL then
			Log(
					Child	=> Child, 
					Path	=> Service( To_Accountant )
				);
		else
			Delegate(
					To_Accountant	=> To_Accountant.Root.all,
					Relative_Path	=> P_Array( Service( To_Accountant ) ),
					Child		=> Child
				);
		end if;
	end Delegate;
	
	procedure Delegate(	To_Accountant	: in out Accountant_Type;
				Relative_Path	: in Path_Array;
				Child		: in Base_Action_Type'Class ) is
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
	function Do_Login(	Manager:	 in Authentication_Manager_Interface'Class;
				Username:	 in String;
				Password:	 in String;
				Root_Accountant: in Accountant_Access
			) return User_Identity_Type is
		-- This function logs any error returned by Do_Login method
		-- As it's a class wide function, it dynamic dispatching is enabled
		-- for both Authentication_Manager and Accountant types

		use Ada.Exceptions;


		My_Action: Base_Action_Type'Class := New_Action(
								Name		=> "Do_Login",
								Root_Accountant	=> Root_Accountant,
								User		=> Anonymous_User
							);
	begin
		declare
			Usr: User_Identity_Type:= Do_Login( Manager, Username, Password );
		begin
			-- if I got here I managed to login! woot!
			Set_Exit_Status(
				My_Action,
				Exit_Success,
				"Logged in as [" & String( Usr ) & "]"
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



	function Do_Login(
				Username	: in String;
				Password	: in String;
				Root_Accountant	: in Accountant_Access
			) return User_Identity_Type is
		My_Acc: Accountant_Access := new Accountant_Type'(New_Accountant( "Login_Service", Root_Accountant ));

		use Authentication_Manager_Maps;

		C: Authentication_Manager_Maps.Cursor := First( Managers_Registry );
	begin
		while Has_Element( C )
		loop
			begin
				return Do_Login(
							Element( C ).all,
							Username,
							Password,
							My_Acc
						);
			exception
				when INVALID_CREDENTIALS => null;
			end;
			C := Next( C );
		end loop;

		raise INVALID_CREDENTIALS;

	end Do_Login;



	-------------------------------------------------
	-- Authorization Management - accounting aware --
	-------------------------------------------------


	procedure Require(
				Criteria	: in out Criteria_Interface'Class; 
				User		: in     User_Type;
				Root_Accountant	: in     Accountant_Access
			) is
		-- matches the user against some criteria.
		-- raise ACCESS_DENIED if the user fails this criteria.
		-- logs any error that might occur using the root_accountant
		use Ada.Exceptions;
		My_Action : Base_Action_Type'Class := New_Action(
					Name		=> "Require",
					Root_Accountant	=> Root_Accountant,
					User		=> User.Data
				);
	begin
		Require(
				Criteria	=> Criteria,
				User		=> User
			);

		-- if it got here, the user has been accepted.
		Set_Exit_Status(
				My_Action,
				Exit_Success,
				"[" & Get_Name( Criteria ) & "] " & Describe( Criteria )
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

	procedure Require(
				Name		: in     Criteria_Name;
				Descriptor	: in     Criteria_Descriptor;
				User		: in     User_Type;
				Root_Accountant	: in     Accountant_Access
			) is
		-- matches the user against some criteria that's created at run time.
		-- raises 
		-- 	ACCESS_DENIED if the user fails this criteria.
		-- 	INVALID_CRITERIA if trying to create a criteria that isn't registered
		-- 	INVALID_CRITERIA_DESCRIPTOR if the descriptor is invalid for this criteria
		-- logs any erro that might occur using the root_accountant
		use Ada.Exceptions;

		My_Action : Base_Action_Type'Class := New_Action(
						Name		=> "Require",
						Root_Accountant	=> Root_Accountant,
						User		=> User.Data
					);
	begin
		Require(
				Name		=> Name,
				Descriptor	=> Descriptor,
				User		=> User
			);

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
	overriding
	procedure Finalize( A: in out Action_Type ) is
		-- used to flush the action.
	begin
		Delegate( A.Root_Accountant.all, A );
	end Finalize;

begin
	Root_Acc := new Accountant_Type'( New_Accountant( Service => "/", Root => null ) );
end KOW_Sec.Accounting;
