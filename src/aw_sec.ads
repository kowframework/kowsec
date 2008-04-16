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

-- TODO:
-- 	. accounting
--
-- Notice:
-- 	I decided to finish the user and authentication schema before continuing
-- 	the rest of Aw_Sec design as it's a critical area.
-- 		OgRo.


with Ada.Containers.Vectors;
with Ada.Finalization;
with Ada.Strings.Unbounded;	use Ada.Strings.Unbounded;

package Aw_Sec is



	------------------------------------
	-- TYPE AND CONSTANT DECLARATIONS --
	------------------------------------


	-----------------------
	-- Groups Management --
	-----------------------
	
	type Authorization_Group is new Unbounded_String; 
	-- Represents an authorization group for this user.
	-- Even though the main concept of groups is the unix meaning of groups
	-- this group can represent some ACL assigned to the user.
	--
	-- That's the reason why we call it Authorization_Group and not only Group.
	--
	-- It's an Unbounded_String type because there is no way to predict the
	-- string size in a Authorization_Manager and the groups can be retrieved
	-- from different managers for the same user (see the rest of the file)


	package Authorization_Group_Vectors is new Ada.Containers.Vectors(
			Index_Type	=> Natural;
			Element_Type	=> Authorization_Group );

	type Authorization_Groups is new Authorization_Group_Vectors.Vectors;
	-- this will make all the vector's methods avaliable here
	-- in Aw_Sec package.


	-- there is no special method for the Authorization_Group type.

	---------------------
	-- User Management --
	---------------------

	type User is tagged private;
	-- A user can be extended, even though it's not how Aw_Sec should be 
	-- extended
	--
	-- Instead, try extending the Authentication_Manager type.
	--
	-- Here, the user is a read-only type, meaning there is no implementation
	-- of methods for changing user's properties.
	--
	-- This should be handler somewhere else.

	procedure Set_Groups_Timeout( User_Object: in out User; New_Timeout: in Duration );
	-- set the timeout of the groups cache for this user
	
	procedure Update_Groups( User_Object: in out User );
	-- Tells the user that his groups should be updated in the
	-- next request to Get_Groups.


	function Identity( User_Object: in User ) return String;
	-- Return a string identifying the current user. Usually it's the username
	-- but one could implement other methods, such as a numeric id for this user


	function Full_Name(	User_Object	: in User;
				Locale		: Aw_Lib.Locales.Locale
					:= Aw_Lib.Locales.Default_Locale
		) return String;
	-- return the full name for this user, respecting the locale's conventions

	
	procedure Get_Groups( User_object: in out User'Class; Groups: in out Authorization_Groups);
	-- Get the groups for this user.
	-- There are two things to notice here:
	-- 	1. This method is task safe. It means it will never return something
	--	 while the user's group list is being generated.
	--	2. The user's group is auto-updated by using the methods:
	--		. Set_Groups_Timeout( User, Duration);
	--		. Update_Groups( User );



	function Is_Anonymous(	User_Object: in User ) return Boolean;
	-- Return true if this user isn't logged in.
	-- 
	-- Even though this isn't an abstract method, one can overwrite it
	-- in order to log hits from anonymuos users when using determined Manager.


	procedure Do_Logout( User_Object: in out User );
	-- Not only make sure the user is logged out but also
	-- Make sure Is_Anonymous returns true for now on for this user.


	-------------------------------
	-- AUTHENTICATION MANAGEMENT --
	-------------------------------

	type Authentication_Manager is abstract new Ada.Finalization.Controlled with private;
	-- This is where the magic happens!
	--
	-- The Authentication_Manager type is the type that should be extended
	-- when a new authentication method is implemented.
	--
	-- It's a controlled type only for the pleasure of the type implementor.


	function Do_Login(	Manager:  in Authentication_Manager;
				Username: in String;
				Password: in String ) return User'Class is abstract;
	-- Login the user, returning a object representing it.
	-- This object might be a direct instance of User or a subclass.
	-- It's this way so the authentication method might have
	-- a user with extended properties.



	----------------------------------------
	-- USER AND AUTHENTICATION EXCEPTIONS --
	----------------------------------------


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


	function Create_Criteria( Pattern: in String ) return Criteria is abstract;
	-- create a criteria to be matched based on the given pattern.

	function Get_Type( Criteria_Object: in Criteria ) return String is abstract;
	-- return a String representing the criteria
	-- it's the same string that will be used by the methods:
	-- 	Register( Name, Factory )
	-- 	Create_Criteria( Name, Patern ) return Criteria'Class;
	
	function Describe( Criteria_Object: in Criteria ) return String is abstract;
	-- return a string describing the current criteria


	------------------------------------------------
	-- Plugin Loading in Authorization Management --
	------------------------------------------------

	type Criteria_Factory is access function ( Descriptor: in Criteria_Descriptor ) return Criteria'Class;
	-- When the package containing the criteria is loaded, it should register itself with the main
	-- criteria registry (available in this package here) so it can be referenced later on by
	-- it's name.
	
	package Criteria_Maps is new 
		Ada.Containers.Hashed_Maps(
				Key_Type	=> Unbounded_String,
				Element_Type	=> Criteria_Factory );
	
	protected type Criteria_Manager is
		--  we created a protected type here so our code is task-safe.
		procedure Register( Str: in String; Factory: in Criteria_Factory );
		-- Register a criteria based on it's name.
		-- We do not check if the factory is null as it has been checked before
		-- in the public register method.
		-- If there is another criteria with the same name, raises Duplicated_Criteria
	
		procedure Unload( Name: in Criteria_name );
		-- remove this criteria from the registry.
		-- if there is no such criteria, raises INVALID_CRITERIA
	
		procedure Empty_Criteria_Registry;
		-- used to unload all the criterias from the registry.


		function Create_Criteria( Name, Pattern: in String ) return Criteria'Class;
		-- create a new criteria object from an already registered criteria type
		-- based on it's name and the given pattern.
		-- if there is no such criteria, raises INVALID_CRITERIA

	private
		Map: Criteria_Maps.Map;
	end Criteria_Manager;

	Criterias: Criteria_Manager;
	-- It's a public object.
	-- The Criteria implementor should call
	-- 	Criteria_Registry.Register( "name", factory'access );
	-- in the static part of his package.


	INVALID_CRITERIA_DESCRIPTOR: Exception;
	-- should be raised when the Criteria_Descriptor used can't be parsed.

	INVALID_CRITERIA: Exception;
	-- raised when trying to create or unload an unknown criteria.

	DUPLICATED_CRITERIA: Exception;
	-- raised when trying to register another criteria with the same name.

	ACCESS_DENIED: Exception;
	-- I think the name is clear enough...


	-- TODO: from here
	
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
	
	type Base_Action is abstract new Ada.Finalization.Limited_Controlled with private;

	type Action is new Base_Action with private;
	-- An action is any small and localized task that can be performed by the system.
	-- The action controlls:
	-- 	* when the task (not as in paralel computing!) has been started
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


	


	-----------------------------------
	-- CLASSWIDE METHODS DECLARATION --
	-----------------------------------


	----------------------------------------
	-- User Management - accounting aware --
	----------------------------------------
	

	function Do_Login(	Manager:	 in Authentication_Manager'Class;
				Username:	 in String;
				Password:	 in String;
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


	function Make_Action(	Root_Accountant	: in Accountant'Class;
				User_Object	: in User'Class ) return Action;

	procedure Set_Exit_Status(	Current_Action	=> Action;
					Status		=> Exit_Status;
					Message		=> String );
	-- Set the exit status and a message describing what hapenned.
	-- Raise STATUS_CONFLICT when the status has been already defined


	procedure Finalize_Action(	Current_Countant	: in Accountant;
					Current_Action		: in Action'Class );
	-- Called by the action when it's going to be deallocated.
	--
	-- This method should be overwriten when extending the Aw_Sec accountin
	-- schema.

	procedure New_Accountant(	Service			: in String,
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


	protected type Groups_Cache_Type is 
		function Should_Update return Boolean;
		-- Determines if the this cache should be update.
		-- The criteria for this is:
		-- 	if Empty(Authorization_Groups) then
		-- 		return_code := true;
		-- 	else if Need_Update = True then 
		-- 		return_code := true;
		-- 	else if Timeout /= 0.0 and then Last_Update < Now - Timeout then
		-- 		return_code := true;
		-- 	else 
		-- 		return_code := false;
		-- 	end if;
		--
		-- 	return return_code;
		
		
		procedure Update( User_Object: in User'Class; Managers: in Authorization_Managers );
		-- update the groups and then set:
		-- 	need_update := false
		-- 	last_update := now

		function Get_Groups return Authorization_Groups;
		-- checks if the groups should be update
		-- 	if true, do the update
		-- 	if false, don't update.
		-- return the current groups list

		procedure Set_Update;
		-- tell this cache it should be updated in the next call
		-- of Get_Groups.
		

		procedure Set_Timeout( New_Timeout: Duration );
	private
		Groups		: Authorization_Groups;
		Timeout		: Duration := 600.0;		-- the duration of this cache in secconds
		Need_Update	: Boolean := True;		-- should update the cache in the next Get_Groups call?
		Last_Update	: Time;				-- when was the last access to this information.
	end Groups_Cache_Type;


	Anonymous_Username : String := "anonymous";

	type User is tagged record
		Username	: Unbounded_String := To_Unbounded_String( Anonymous_Username );
		-- as default, in Aw_Sec, anonymous user has this username
		First_Name	: Unbounded_String;
		Last_Name	: Unbounded_String;
		-- this one is optional, depending on the Authorization_Manager
		Groups_Cache	: Groups_Cache_Type;
		Managers	: Authorization_Manager_Vectors.Vector;
	end record;

	type Authentication_Manager is abstract new Ada.Finalization.Controlled with null record;

	function Get_Groups(	Manager:	in Authentication_Manager;
				User_Object:	in User'Class )
				return Authorization_Groups is abstract;
	-- Return all the groups for this user
	-- It's implemented in the manager for 2 reasons:
	-- 	1. this way we can store the users and the groups in
	-- 	  different managers.
	-- 	2. the information on how to obtain the groups information
	-- 	  doesn't belong to the user itself.
	-- When implementor of this method should assume:
	-- 	1. the user is valid and so is the results of Identity( User_Object );
	-- 	2. it's meant to work with any authentication manager vs user combination.
	-- This is a private method so the user won't call it directly.
	-- Instead, it's called by the Get_Groups (User'Class) method implemented here.



	type Criteria is abstract tagged null record;

	procedure Match(	Criteria_Object	: in Criteria;
				User_Object	: in out User'Class;
				Results		: out Boolean ) is abstract;
	-- Match the user permissions against the given criteria
	-- some criterias might require the user to be loged in
	-- (as when it's required to get user's groups).
	--
	-- User_Object is an "in out" so it can have it's groups
	-- updated automatically by Aw_Sec when required.






	-- TODO: FROM HERE AGAIN


	type Accountant is new Ada.Finalization.Controlled with record
		Creation_Time	: Time := Now;
		Calls_Count
	end record;

	type Action is new Ada.Finalization.Limited_Controlled with record
		Initialized: Boolean := False;
		-- flag used internally to indicate when the method has been initialized.
	end record;
	procedure Initialize(A: in out Action);
	-- overrides the initialization so it'll raise an exception
	-- anytime the user tries to initialize an object without
	-- using a constructor.
	
	procedure Finalize( A: in out Action );
	-- used to 

end Aw_Sec;
