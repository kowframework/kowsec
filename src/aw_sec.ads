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
-- This is the base package for AwSec.                                       --
--                                                                           --
-------------------------------------------------------------------------------

with Ada.Finalization;

package Aw_Sec is



	------------------------------------
	-- TYPE AND CONSTANT DECLARATIONS --
	------------------------------------

	---------------------
	-- User Management --
	---------------------

	type User is tagged private;
	-- A user can be extended, even though it's not how Aw_Sec should be 
	-- extended
	-- Instead, try extending the Authentication_Manager type.
	
	type Authorization_Group is tagged private;
	-- Represents an authorization group for this user.
	-- Even though the main concept of groups is the unix meaning of groups
	-- this group can represent some ACL assigned to the user.
	--
	-- That's the reason why we call it Authorization_Group and not only Group.

	type Authorization_Group_Access is access all Authorization_Group'Class;

	type Authorization_Groups is Array(<>) of Authorization_Group_Access;
	-- an array containing access types for authorization groups.

	
	
	
	type Authentication_Manager is abstract bew Ada.Finalization.Controlled with private;
	-- This is where the magic happens!
	--
	-- The Authentication_Manager type is the type that should be extended
	-- when a new authentication method is implemented.
	--
	-- It's a controlled type only for the pleasure of the type implementor.


	INVALID_CREDENTIALS: Exception;
	-- should be raised when login fails.
	
	ANONYMOUS_ACCESS: Exception;
	-- should be raised when trying to get information from an anonymous user.

	------------------------------
	-- Authorization Management --
	------------------------------
	
	type Criteria is abstract tagged private;
	-- The criteria type should be implemented by different
	-- authorization schemas.
	-- This is the type that should be implemented by whoever wants to
	-- extend the authorization type avaliable.
	
	type Criteria_Name is new String( Integer range <> );
	-- A name representing the criteria
	-- It's used to identify the criteria in use.
	
	type Criteria_Descriptor is new Wide_String( Integer range <> );
	-- the criteria descriptor is a Wide_String representing that the
	-- criteria is.
	-- It's a Wide_String and not a String because one could use
	-- username in a descriptor pattern and the username is
	-- Wide_String.

	type Criteria_Factory is access function ( Descriptor: in Criteria_Descriptor ) return Criteria'Class;
	-- When the package containing the criteria is loaded, it should register itself with the main
	-- criteria registry (available in this package here) so it can be referenced later on by
	-- it's name.

	INVALID_CRITERIA_DESCRIPTOR: Exception;
	-- should be raised when the Criteria_Descriptor used can't be parsed.

	INVALID_CRITERIA: Exception;
	-- raised when trying to create or unload an unknown criteria.
	DUPLICATED_CRITERIA: Exception;
	-- raised when trying to register another criteria with the same name.

	ACCESS_DENIED: Exception;
	-- I think the name is clear enough...

	
	---------------------------
	-- Accounting Management --
	---------------------------


	type Accountant is new Ada.Finalization.Controlled with private;
	-- The Accountant should be overwritten by anyone willing to extend the
	-- Accounting Management schema of Aw_Sec.
	--
	-- There is a basic implementation avaliable in this package that outputs
	-- the messages to stdout and stderr.


	type Accountant_Access is access all Accountant'Class;
	
	type Action is new Ada.Finalization.Limited_Controlled with private;
	-- An action is any small and localized task that can be performed by the system.
	-- The action controlls:
	-- 	* when the task has been started
	-- 	* which user, if any, is responsible for triggering this action
	--	* when the task has been compleeted
	--	* the exit status and message of the task.
	--
	-- This information is then delegated for logging by the Action's root accountant.
	-- This accountant then decides where and how to send it.
	--
	-- The accountant can then delegate the logging for it's root accountant and so on...
	-- till it reaches the root accountant of all accountants.
	--
	-- You must specify what's the root accountant for every action, even when you
	-- already have your own root accountant.
	--
	-- Now, for the accountant, if you don't specify any root it understands you meant
	-- to use the Root_Acc instance avaliable in the next line:
	Root_Acc: constant Accountant( Service => "ROOT", Root => Null );


	type Exit_Status is (
		EXIT_SUCCESS,	-- no error at all in the exit status	
		EXIT_WARNING,	-- the action has exited with some minor warning
		EXIT_ERROR, 	-- the action has exited with error
		EXIT_FATAL,	-- the action has ended in a fatal error!
		EXIT_NULL	-- there is no exit status defined yet.
		);


	for Exit_Status use (
		EXIT_SUCESS	=> 2#000#, -- just to pretend I'm a smart guy. :D
		EXIT_WARNING	=> 2#001#,
		EXIT_ERROR	=> 2#010#,
		EXIT_FATAL	=> 2#011#,
		EXIT_NULL	=> 2#100#
		);

	STATUS_CONFLICT: Exception;
	-- Raised when one try to change the exit status while it has already been defined
	-- this is so in order to force the developer to use Actions to represent only
	-- small pieces of the code...
	--
	-- Usualy, if you need to set more than one exit status you can split your
	-- action in two other tasks.


	


	-------------------------
	-- METHODS DECLARATION --
	-------------------------


	--------------------------------------------
	-- User Management - not accounting aware --
	--------------------------------------------

	function Do_Login(	Manager:  in Authentication_Manager;
				Username: in Wide_String;
				Password: in Wide_string ) return User is abstract;
	-- Login the user, returning a object representing it.
	-- This object might be a direct instance of User or a subclas.
	-- It's this way so the authentication method might have
	-- a user with extended properties.


	procedure Do_Logout(	Manager:	in Authentication_Manager;
				User_Object:	in out User ) is abstract;
	-- not only make sure the user is logged out but also
	-- make sure Is_Anonymous returns true for now on for this user.


	function Is_Anonymous(	Manager:	in Authentication_Manager;
				User_Object:	in User ) return Boolean;
	-- Return true if this user isn't logged in.
	-- 
	-- Even though this isn't an abstract method, one can overwrite it
	-- in order to log hits from anonymuos users when using determined Manager.


	function Get_Groups( User_Object: in User ) return Authorization_Groups;

	----------------------------------------
	-- User Management - accounting aware --
	----------------------------------------
	

	function Do_Login(	Manager:	 in Authentication_Manager'Class;
				Username:	 in Wide_String;
				Password:	 in Wide_String;
				Root_Accountant: in Accountant'Class ) return User'Class;
	-- This function logs any error returned by Do_Login method
	-- As it's a class wide function, it dynamic dispatching is enabled
	-- for both Authentication_Manager and Accountant types
	
	procedure Do_Logout(	Manager:	 in Authentication_Manager'Class;
				User_Object:	 in User'Class;
				Root_Accountant: in Accountant'Class );
	-- This function logs any error returned by Do_Logout method
	-- As it's a class wide function, it dynamic dispatching is enabled
	-- for both Authentication_Manager and Accountant types
	


	-----------------------------------------------------
	-- Authorization Management - not accounting aware --
	-----------------------------------------------------
	
	function Create_Criteria( Descriptor: in Criteria_Descriptor ) return Criteria is abstract;
	-- Function that should be implemented by the authorization method in use.
	
	function Create_Criteria(	Name:		in Criteria_Name;
					Descriptor:	in Criteria_Descriptor ) return Criteria'Class;
	-- This function tries to create a criteria by it's name.
	-- This will only work if the criteria has been registered by
	-- the following method:
	
	procedure Register(	Name:	 in Criteria_Name;
				Factory: in Criteria_Factory );
	-- This procedure should be called by the package that implements
	-- a criteria in load time (the static part of the body).
	-- If the implementor fails to do so, the criteria won't be avaliable
	-- later on by it's name.

	procedure Unload( Name: in Criteria_name );
	-- remove this criteria from the registry.
	

	procedure Empty_Criteria_Registry;
	-- used to unload all the criterias from the registry.
	

	procedure Require(	User_Object:	in out User'Class;
				Criteria:	in Criteria ) is abstract;
	-- matches the user against some criteria.
	-- raises ACCESS_DENIED if the user fails this criteria.
	

	procedure Require(	User_Object:	in out User'Class;
				Name:		in Criteria_Name;
				Descriptor:	in Criteria_Descriptor);
	-- matches the user against some criteria that's created at run time.
	-- raises 
	-- 	ACCESS_DENIED if the user fails this criteria.
	-- 	INVALID_CRITERIA if trying to create a criteria that isn't registered
	-- 	INVALID_CRITERIA_DESCRIPTOR if the descriptor is invalid for this criteria



	-------------------------------------------------
	-- Authorization Management - accounting aware --
	-------------------------------------------------


	procedure Require(	User_Object:	 in out User'Class;
				Criteria:	 in Criteria'Class 
				Root_Accountant: in out Accountant'Class);
	-- matches the user against some criteria.
	-- raise ACCESS_DENIED if the user fails this criteria.
	-- logs any error that might occur using the root_accountant


	-- TODO: adotar agora esse estilo de identação ou não?
	procedure Require(	User_Object	: in out User'Class;
				Name		: in Criteria_Name;
				Descriptor	: in Criteria_Descriptor;
				Root_Accountant	: in out Accountant'Class);
	-- matches the user against some criteria that's created at run time.
	-- raises 
	-- 	ACCESS_DENIED if the user fails this criteria.
	-- 	INVALID_CRITERIA if trying to create a criteria that isn't registered
	-- 	INVALID_CRITERIA_DESCRIPTOR if the descriptor is invalid for this criteria
	-- logs any erro that might occur using the root_accountant



	---------------------------
	-- Accounting Management --
	---------------------------


	function New_Action(	Root_Accountant : in Accountant'Class;
				User_Object	: in User'Class ) return Action;
	-- Used to create a new action which's root is Root_Accountant
	-- Should be used as a constructor.
	-- 
	-- Even thouth it's preffered to use this method to create your
	-- actions, it's also possible to count on the Initialize method
	-- to setup the automatic settings

	procedure Set_Exit_Status(	Current_Action	=> Action;
					Status		=> Exit_Status;
					Message		=> Wide_String );
	-- Set the exit status and a message describing what hapenned.
	-- Raise STATUS_CONFLICT when the status has been already defined


	procedure Finalize_Action(	Current_Countant	: in Accountant;
					Current_Action		: in Action'Class );
	-- Called by the action when it's going to be deallocated.
	--
	-- This method should be overwriten when extending the Aw_Sec accountin
	-- schema.

	procedure New_Accountant(	Service			: in Wide_String,
					Root_Accountant		: in Accountant'Class := Root_Acc );
	-- Accountant constructor.
	--
	-- This method should be overwriten when extending the Aw_Sec accountin
	-- schema.
	
	procedure Finalize_Accountant(	Current_Accountant	: in Accountant;
					Child_Accountant	: in Accountant'Class );
	-- Called by the child accountant when it's going to be deallocated.
	--
	-- This method should be overwriten when extending the Aw_Sec accountin
	-- schema.

private


	type User is tagged record
		Username : access Wide_String;
		Groups	 : access Authorization_Groups;
	end record;

	-- TODO: from here and package body!
	type Authentication_Manager is abstract bew Ada.Finalization.Controlled with record
	end record;

	type Accountant is new Ada.Finalization.Controlled with record
	end record;

	type Action is new Ada.Finalization.Limited_Controlled with record
	end record;
	
	procedure Adjust( U : in out User );

end Aw_Sec;
