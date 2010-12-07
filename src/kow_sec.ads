------------------------------------------------------------------------------
--                                                                          --
--                       KOW Framework :: Security                          --
--                                                                          --
--                              KOW Framework                               --
--                                                                          --
--                                 S p e c                                  --
--                                                                          --
--               Copyright (C) 2007-2011, KOW Framework Project             --
--                                                                          --
--                                                                          --
-- KOWSec is free software; you can redistribute it  and/or modify it under --
-- terms of the  GNU General Public License as published  by the Free Soft- --
-- ware  Foundation;  either version 2,  or (at your option) any later ver- --
-- sion. KOWSec is distributed in the hope that it will be useful, but WITH---
-- OUT ANY WARRANTY;  without even the  implied warranty of MERCHANTABILITY --
-- or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License --
-- for  more details.  You should have  received  a copy of the GNU General --
-- Public License distributed with KOWSec; see file COPYING.  If not, write --
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
-- This is the base package for KOWSec.                                      --
-------------------------------------------------------------------------------


--------------
-- Ada 2005 --
--------------
with Ada.Calendar;			use Ada.Calendar;
with Ada.Containers.Vectors;
with Ada.Containers.Ordered_Maps;
with Ada.Finalization;
with Ada.Strings.Unbounded;		use Ada.Strings.Unbounded;
with Ada.Containers.Hashed_Maps;
with Ada.Strings.Unbounded.Hash;

-------------------
-- KOW Framework --
-------------------
with KOW_Lib.Locales;
with KOW_Lib.File_System;		use KOW_Lib.File_System;
with KOW_Lib.UString_Ordered_Maps;



package KOW_Sec is

	--------------------------
	-- Constant Deffinition --
	--------------------------
	Storage_Root : constant String := Get_Working_Dir / "appdata" / "kow_sec";
	-- where the KOW_Sec.Data will store their files
	
	----------------------------
	-- The User Identity Type --
	----------------------------
	
	type User_Identity_Type is new String( 1 .. 32 );
	-- the user identity is a MD5 hash

	function To_Identity( Str : in String ) return User_Identity_Type;
	-- calculates the hash of this identity


	function New_User_Identity return User_Identity_Type;
	-- this will generate a brand new user identity


	Anonymous_User_Identity : User_Identity_Type := ( others => ' ' );
	-- it is initialized in the elaboration


	-------------------------------
	-- AUTHENTICATION MANAGEMENT --
	-------------------------------

	type Authentication_Manager_Interface is interface;
	-- This is where the magic happens!
	--
	-- The Authentication_Manager type is the type that should be extended
	-- when a new authentication method is implemented.
	--
	-- It's a controlled type only for the pleasure of the type implementor.


	type Authentication_Manager_Access is access all Authentication_Manager_Interface'Class;

	function Do_Login(
				Manager	: in Authentication_Manager_Interface;
				Username: in String;
				Password: in String
			) return User_Identity_Type is abstract;
	-- Login the user, returning a object representing it.
	-- This object might be a direct instance of User or a subclass.
	-- It's this way so the authentication method might have
	-- a user with extended properties.


	function Has_User(
				Manager		: in Authentication_Manager_Interface;
				User_Identity	: in User_Identity_Type
			) return Boolean is abstract;
	-- check if a given user can be authenticated by the given manager


	package Authentication_Manager_Vectors is new Ada.Containers.Vectors(
					Index_Type	=> Natural,
					Element_Type	=> Authentication_Manager_Access
				);


	type Authentication_Managers is new Authentication_Manager_Vectors.Vector with null record;

	Managers_Registry: Authentication_Managers;
	-- a registry of the current managers.

	procedure Register_Manager( Manager: in out Authentication_Manager_Access );
	-- Register a manager so it's usable by KOW_Sec.
	

	function Do_Login(
				Username : in String;
				Password : in String
			) return User_Identity_Type;
	-- tries to login the user using the registered managers.
	-- the pair username vs password here is quite abstract.. the manager can implement
	-- this function giving different meanings to the data received


	----------------------
	-- Roles Management --
	----------------------

	type Role_Identity_Type is new String( 1 .. 102 );

	function To_Identity( Str : in String ) return Role_Identity_Type;

	type Role_Type is record
		-- represent some sort of action a user can perform.
		--
		-- each available role must be registered by the application declaring it
		-- so it can become available for testing.
		
		Application	: String( 1 .. 50 );
		Role		: String( 1 .. 50 );
	end record;


	function Identity( Role : in Role_type ) return Role_Identity_Type;
	-- returns Application::Role
	
	package Role_Maps is new Ada.Containers.Ordered_Maps(
				Key_Type	=> Role_Identity_Type,
				Element_Type	=> Role_Type
			);
	-- maps identity => role

	package Role_Vectors is new Ada.Containers.Vectors(
				Index_Type	=> Positive,
				Element_Type	=> Role_Type
			);

	protected Roles_Registry is
		procedure Register( Application, Role : in String );
		procedure Register( Role : in Role_Type );
		

		function Get_Roles return Role_Maps.Map;
	private
		My_Roles : Role_Maps.Map;
	end Roles_Registry;



	-----------------------
	-- Groups Management --
	-----------------------
	

	type Group_Type is new String( 1 .. 50 );

	function To_String( Group : Group_Type ) return String;
	-- get the trimmed version of group_type


	function Get_Roles( Group : in Group_Type ) return Role_Vectors.Vector;
	-- return the roles assigned to a given group

	package Group_Vectors is new Ada.Containers.Vectors (
				Index_Type	=> Positive,
				Element_Type	=> Group_Type
			);
	





	---------------------
	-- User Management --
	---------------------


	type Info_Kind_Type is ( Email_Contact, Phone_Contact );

	type Contact_Info_Type is record
		Kind	: Info_Kind_Type;
		Value	: String( 1 .. 100 );
	end record;


	type Contact_Info_Array is array ( Positive range <> ) of Contact_Info_Type;

	type User_Type is record
		Identity	: User_Identity_Type := Anonymous_User_Identity;


		-- formal first and last names:
		First_Name	: String( 1 .. 50 );
		Last_Name	: String( 1 .. 150 );


		Nickname	: String( 1 .. 50 );
		-- how the user would like to be called

		Primary_Email	: String( 1 .. 100 );

		Contact_Info	: Contact_Info_Array( 1 .. 10 );
	end record;

	type Logged_User_Type is record
		User		: User_Type;

		Current_Manager	: Authentication_Manager_Access;
		-- the authentication manager used to authenticate this instance
		-- if null, the user hasn't been logged in
	end record;


	package User_Vectors is new Ada.Containers.Vectors(
				Index_Type	=> Positive,
				Element_Type	=> User_Type
			);


	Anonymous_User : constant User_Type := (
					Identity	=> Anonymous_User_Identity,
					others	=> <>
				);
	Logged_Anonymous_User : constant Logged_User_Type := (
					User		=> Anonymous_User,
					Current_Manager	=> null
				);

	function Identity( User : in User_Type ) return String;
	-- Return a string identifying the current user. Usually it's the username
	-- but one could implement other methods, such as a numeric id for this user


	function Full_Name(
				User	: in User_Type;
				Locale	: in KOW_Lib.Locales.Locale := KOW_Lib.Locales.Default_Locale
		) return String;
	-- return the full name for this user, respecting the locale's conventions

	function Gravatar_URL( User : in User_Type; Size : Positive := 69 ) return String;
	-- return the gravatar URL for the given user
	
	function Get_Groups( User : in User_Type ) return Group_Vectors.Vector;
	-- Get the groups for this user.

	procedure Set_Groups( User : in User_Type; Groups : in Group_Vectors.Vector );

	function Get_Roles(
				User			: in User_Type;
				Combine_Group_Roles	: in Boolean := False
			) return Role_Vectors.Vector;
	-- get all roles by a given user
	-- if combine group roles is true, does exactly that given that only one instance of each role is returned

	function Is_Anonymous( User : in User_type ) return Boolean;
	-- Return true if this user isn't logged in.

	function Is_Anonymous( User : in Logged_User_type ) return Boolean;
	-- Return true if this user isn't logged in.

	function Get_User( User_Identity: in String ) return User_Type;
	-- get the user using the data backend

	function Get_User( User_Identity: in User_Identity_Type ) return User_Type;
	-- get the user using the data backend

	procedure Store_User( User : in User_Type );
	-- store the user using the backend


	function Do_Login(
				Username : in String;
				Password : in String
			) return Logged_User_Type;
	-- do login and initialize the logged_user_type variable


	----------------------------------------
	-- USER AND AUTHENTICATION EXCEPTIONS --
	----------------------------------------


	INVALID_CREDENTIALS: Exception;
	-- should be raised when login fails.
	
	ANONYMOUS_ACCESS: Exception;
	-- should be raised when trying to get information from an anonymous user.

	UNKNOWN_USER : Exception;
	-- when get_user fails or in case you want your do_login function more precise on error reporting

	------------------------------
	-- Authorization Management --
	------------------------------
	

	subtype Criteria_Name is Unbounded_String;
	subtype Criteria_Descriptor is Unbounded_String;

	function To_Criteria_Name( Name : String ) return Criteria_Name renames To_Unbounded_String;
	
	function To_Criteria_Descriptor( Descriptor : String ) return Criteria_Descriptor renames To_Unbounded_String;





	type Criteria_Interface is interface;
	-- The criteria type should be implemented by different
	-- authorization schemas.
	-- This is the type that should be implemented by whoever wants to
	-- extend the authorization type avaliable.


	function Get_Name( Criteria: in Criteria_Interface ) return String is abstract;
	-- return a String representing the criteria
	-- it's the same string that will be used when creating it dynamically
	
	function Describe( Criteria: in Criteria_Interface ) return String is abstract;
	-- return a string describing the current criteria


	procedure Require(	
				User		:	 in out User_Type;
				Criteria	:	 in     Criteria_Interface
			) is abstract;
	-- matches the user against some criteria.
	-- raise ACCESS_DENIED if the user fails this criteria.


	procedure Require(	
				User		: in out User_Type;
				Name		: in     Criteria_Name;
				Descriptor	: in     Criteria_Descriptor
			);
	-- Create and matches against a criteria using the criteria registry
	

	-----------------------
	-- Criteria Registry --
	-----------------------

	type Criteria_Factory_Type is access function ( Descriptor: in Criteria_Descriptor ) return Criteria_Interface'Class;
	-- When the package containing the criteria is loaded,
	-- it should register itself with the main
	-- criteria registry (available in this package here)
	-- so it can be referenced later on by it's name.
	--
	-- when using it and the descriptor is empty, no error should be raised
	
	package Criteria_Maps is new Ada.Containers.Hashed_Maps(
						Key_Type	=> Criteria_Name,
						Element_Type	=> Criteria_Factory_Type, 
						Hash 		=> Ada.Strings.Unbounded.Hash,
						Equivalent_Keys => "="
				);

	protected Criteria_Registry is
		--  we created a protected type here so our code is task-safe.
		procedure Register( Factory : in Criteria_Factory_Type );
		-- Register a criteria based on it's name.
		-- If there is another criteria with the same name,
		-- raises Duplicated_Criteria
	
		procedure Unload( Name : in Criteria_name );
		-- remove this criteria from the registry.
		-- if there is no such criteria, raises INVALID_CRITERIA
	
		procedure Empty_Criteria_Registry;
		-- used to unload all the criterias from the registry.


		function Create_Criteria(
					Name		: in Criteria_Name; 
					Descriptor	: in Criteria_Descriptor
			) return Criteria_Interface'Class;
		-- create a new criteria object from an already registered criteria type
		-- based on it's name and the given Descriptor.
		-- if there is no such criteria, raises INVALID_CRITERIA

	private
		Map: Criteria_Maps.Map;
	end Criteria_Registry;


	INVALID_CRITERIA_DESCRIPTOR: Exception;
	-- should be raised when the Descriptor used in the criteria can't be parsed.

	INVALID_CRITERIA: Exception;
	-- raised when trying to create or unload an unknown criteria.

	DUPLICATED_CRITERIA: Exception;
	-- raised when trying to register another criteria with the same name.

	ACCESS_DENIED: Exception;
	-- I think the name is clear enough...

end KOW_Sec;
