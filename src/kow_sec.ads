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
with Ada.Sequential_IO;
with Ada.Strings.Unbounded;		use Ada.Strings.Unbounded;
with Ada.Containers.Hashed_Maps;
with Ada.Strings.Unbounded.Hash;

-------------------
-- KOW Framework --
-------------------
with KOW_Lib.Json;
with KOW_Lib.Locales;
with KOW_Lib.File_System;		use KOW_Lib.File_System;
with KOW_Lib.UString_Ordered_Maps;



package KOW_Sec is
pragma Elaborate_Body( KOW_Sec );

	--------------------------
	-- Constant Deffinition --
	--------------------------
	Storage_Root : constant String := Get_Working_Dir / "appdata" / "kow_sec";
	-- where the KOW_Sec.Data will store their files
	


	------------------
	-- Data Storage --
	------------------

	generic
		Storage_Name : String;
		type Key_Type is private;
		with function To_String( Key : in Key_Type ) return String;
		with function "<"( L,R : in Key_Type ) return Boolean;
		type Element_Type is private;
		with package Element_Vectors is new Ada.Containers.Vectors(
						Index_Type	=> Positive,
						Element_Type	=> Element_Type
					);
		--Cache_Size	: Natural;	-- elements in cache
		--Index_Data	: Boolean;	-- should the data be indexed?
	package Data is


		------------------
		-- Storage Path --
		------------------
		Storage_Root : constant String := KOW_Sec.Storage_Root / Storage_Name;


		function Storage_Path( Key : in Key_Type ) return String;


		---------------------
		-- In-memory cache --
		---------------------

		package Cache_Maps is new Ada.Containers.Ordered_Maps(
					Key_type	=> Key_Type,
					Element_Type	=> Element_Vectors.Vector,
					"="		=> Element_Vectors."="
				);

		protected Cache is
			-- it's a infinite cache for every element loaded so far...
			-- to avoid colisions we are using ordered maps.. the ideal is to use an
			-- ordered map with a hash function with no colisions at all tough

			function Exists( Key : in Key_type ) return Boolean;
			-- checks if the file exists - both in cache and in disk

			procedure Read(
						Key		: in     Key_Type;
						Item		:    out Element_Vectors.Vector;
						From_Disk	: in     Boolean := False
					);
			-- tries reading from cache.. if not cache, read file...
			-- if from_disk = true reads from the file anyway

			procedure Write(
						Key	: in     Key_Type;
						Item	: in     Element_Vectors.Vector
					);
			-- update cache with new value
			-- if on_disk = true then update the disk file also

			procedure Append(
						Key	: in     Key_Type;
						Item	: in     Element_Type
					);
			-- append a new item into the storage
			-- if on_disk = true then update the disk also

			procedure Delete(
						Key		: in     Key_Type;
						From_Disk	: in     Boolean := False
					);
			-- delete from map and, if required, from disk also
		private
			Cache_Map : Cache_Maps.Map;
		end Cache;


		-------------
		-- Aliases --
		-------------

		procedure Append(
					Key	: in Key_Type;
					Element	: in Element_Type
				) renames Cache.Append;


		procedure Store(
					Key	: in Key_Type;
					Elements: in Element_Vectors.Vector 
				) renames Cache.Write;
		
		procedure Delete(
					Key		: in Key_type;
					From_Disk	: in Boolean := False
				) renames Cache.Delete;

		---------------------
		-- Other functions --
		---------------------

		function Exists( Key : in Key_Type ) return Boolean renames Cache.Exists;

		function Get_First(
					Key	: in Key_Type;
					Unique	: in Boolean := False
				) return Element_Type;
		-- get only the first element..
		-- if unique and it's not the only element then raise constraint_error
		-- if there is no element raise constraint_error also
		
		function Get_All( Key : in Key_Type ) return Element_Vectors.Vector;
		-- get all elements


		procedure Store(
					Key	: in Key_Type;
					Element	: in Element_Type
				);
		-- store the element making it the only one in the file

	private
		package Element_IO is new Ada.Sequential_IO( Element_Type );

	end Data;






	----------------------------
	-- The User Identity Type --
	----------------------------
	
	type User_Identity_Type is new String( 1 .. 32 );
	-- the user identity is a MD5 hash

	function MD5_Sign( Str : in String ) return User_Identity_Type;
	-- calculates the has for a string returning it as user_identity_type

	function To_Identity( Str : in String ) return User_Identity_Type;
	-- converts the string into the user_identity_type (cast)

	function To_String( Identity : in User_Identity_Type ) return String;

	function New_User_Identity return User_Identity_Type;
	-- this will generate a brand new user identity


	Anonymous_User_Identity : User_Identity_Type := ( others => ' ' );
	-- it is initialized in the elaboration

	type User_Identity_Array is array( Positive range <> ) of User_Identity_Type;

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


	function Get_Name( Manager : in Authentication_Manager_Interface ) return String is abstract;
	-- return a string representing the given authentication manager

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


	package Authentication_Manager_Maps is new Ada.Containers.Ordered_Maps(
					Key_Type	=> Unbounded_String,
					Element_Type	=> Authentication_Manager_Access
				);



	Managers_Registry: Authentication_Manager_Maps.Map;
	-- a registry of the current managers.

	procedure Register_Manager( Manager : in out Authentication_Manager_Access );
	-- Register a manager so it's usable by KOW_Sec.
	
	function Get_Manager( Manager_Name : in String ) return Authentication_Manager_Access;
	function Get_Manager( Manager_Name : in Unbounded_String ) return Authentication_Manager_Access;

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
	
	function To_Role( Identity : in Role_Identity_Type ) return Role_Type;
	-- parse the role identity into a role

	
	function New_Role(
				Application	: in String;
				Role		: in String
			) return Role_Type;
	-- builds up a new role object

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
		procedure Register( Role : in Role_Type );
		

		function Get_Roles return Role_Maps.Map;
	private
		My_Roles : Role_Maps.Map;
	end Roles_Registry;



	-----------------------
	-- Groups Management --
	-----------------------
	
	type Group_Name_Type is new String( 1 .. 50 );

	type Context_Type is new String( 1 .. 150 );

	function To_Context( Context_Str : in String ) return Context_Type;

	type Context_Array is array( positive range <> ) of Context_Type;

	Empty_Context_Array : Context_Array( 1 .. 0 );

	type Group_Type is record
		Name	: Group_Name_Type;
		Context	: Context_Type;

		-- a user can be in a group in a given context (say it's the admin in a project and a regular user in other).
		-- when context is empty (all spaces)
	end record;


	function Get_Name( Group : in Group_Type ) return String;
	-- get the trimmed version of the group name

	function Get_Context( Group : in Group_Type ) return String;
	-- get the trimmed version of the group context
	

	function To_String( Group : Group_Type ) return String;
	-- Return Get_Name & "::" & Get_Context

	function To_Group( Name : in String; Context : in Context_Type := ( others => ' ' ) ) return Group_Type;

	function Get_Roles( Group : in Group_Type ) return Role_Vectors.Vector;
	-- return the roles assigned to a given group

	procedure Set_Roles( Group : in Group_Type; Roles : in Role_Vectors.Vector );
	-- set the roles for the given group


	procedure Add_Role( Group : in Group_Type; Role : in Role_Type );

	function "<"( L, R : in Group_Type ) return Boolean;
	-- compares both group names

	package Group_Vectors is new Ada.Containers.Vectors (
				Index_Type	=> Positive,
				Element_Type	=> Group_Type
			);
	





	---------------------
	-- User Management --
	---------------------


	type Account_Status_Type is (
					Account_Pending,
					Account_Enabled,
					Account_Disabled,
					Account_Suspended
				);

	type Gender_Type is(
			Male_Gender,
			Female_Gender,
			Unknown_Gender
		);



	type Contact_Info_Kind_Type is ( Email_Contact, Phone_Contact, Address_Contact );

	type Contact_Info_Type is record
		Kind	: Contact_Info_Kind_Type;
		Value	: String( 1 .. 150 );
	end record;

	No_Info : constant Contact_Info_Type := ( Kind => Email_Contact, Value => ( others => ' ' ) );


	type Contact_Info_Array is array ( Positive range <> ) of Contact_Info_Type;

	type User_Data_Type is record
		Identity	: User_Identity_Type := Anonymous_User_Identity;

		Account_Status	: Account_Status_Type := Account_Pending;
		Account_Status_Message : String ( 1 .. 200 ) := ( others => ' ' );
		-- an aditional message to the user status; usefull when suspended, disabled or pending

		-- formal first and last names:
		First_Name	: String( 1 .. 50 ) := ( others => ' ' );
		Last_Name	: String( 1 .. 150 ) := ( others => ' ' );

		Gender		: Gender_Type	:= Unknown_Gender;


		Nickname	: String( 1 .. 50 ) := ( others => ' ' );
		-- how the user would like to be called

		Primary_Email	: String( 1 .. 100 ) := ( others => ' ' );

		Contact_Info	: Contact_Info_Array( 1 .. 10 ) := ( others => No_Info );
	end record;

	type User_Type is record
		Data		: User_Data_Type;

		Current_Manager	: Authentication_Manager_Access;
		-- the authentication manager used to authenticate this instance
		-- if null, the user hasn't been logged in
	end record;


	package User_Vectors is new Ada.Containers.Vectors(
				Index_Type	=> Positive,
				Element_Type	=> User_Data_Type
			);


	Anonymous_User : constant User_Data_Type := (
					Identity	=> Anonymous_User_Identity,
					others	=> <>
				);
	Logged_Anonymous_User : constant User_Type := (
					Data		=> Anonymous_User,
					Current_Manager	=> null
				);


	function Full_Name(
				User	: in User_Data_Type;
				Locale	: in KOW_Lib.Locales.Locale := KOW_Lib.Locales.Default_Locale
		) return String;
	-- return the full name for this user, respecting the locale's conventions

	function Gravatar_URL( User : in User_Data_Type; Size : Positive := 69 ) return String;
	-- return the gravatar URL for the given user
	
	function Get_All_Groups( User : in User_Data_Type ) return Group_Vectors.Vector;
	-- Get all the groups for this user, in every context
	
	function Get_Groups(
				User	: in User_Data_Type;
				Contexts: in Context_Array
			) return Group_Vectors.Vector;
	-- Get contextualized groups for this user.


	function Get_All_Groups( User : in User_Type ) return Group_Vectors.Vector;

	function Get_Groups(
				User 	: in User_Type;
				Contexts: in Context_Array
			) return Group_Vectors.Vector;

	procedure Set_Groups( User : in User_Data_Type; Groups : in Group_Vectors.Vector );


	procedure Add_Group( User : in User_Data_Type; Group : in Group_Type );
	-- add a group to the user;
	-- this procedure doesn't perform any kind of check!
	-- and it uses get_all_groups + set_groups;


	procedure Remove_Group( User : in User_Data_Type; Group : in Group_Type );
	-- remove the given group, taking into account the context.
	-- raises constraint_error if no group is found

	function Get_Roles(
				User			: in User_Data_Type;
				Combine_Group_Roles	: in Boolean := False;
				Contexts		: in Context_Array := Empty_Context_Array
			) return Role_Vectors.Vector;
	-- get all roles by a given user
	-- if combine group roles is true, does exactly that given that only one instance of each role is returned
	-- context is only used when combine_group_roles is true

	function Get_Roles(
				User			: in User_Type;
				Combine_Group_Roles	: in Boolean := False;
				Contexts		: in Context_Array := Empty_Context_Array
			) return Role_Vectors.Vector;
	

	function Get_All_Roles(
				User			: in User_Data_Type;
				Combine_Group_Roles	: in Boolean := False
			) return Role_Vectors.Vector;
	-- get every single role of this user, no mather in what context


	function Get_All_Roles(
				User			: in User_Type;
				Combine_Group_Roles	: in Boolean := False
			) return Role_Vectors.Vector;
	-- get every single role of this user, no mather in what context


	procedure Set_Roles( User : in User_Data_Type; Roles : in Role_Vectors.Vector );

	procedure Add_Global_Role( User : in User_Data_Type; Role : in Role_Type );

	function Is_Anonymous( User : in User_Data_Type ) return Boolean;
	-- Return true if this user isn't logged in.

	function Is_Anonymous( User : in User_Type ) return Boolean;
	-- Return true if this user isn't logged in.

	function Get_User( User_Identity: in String ) return User_Data_Type;
	-- get the user using the data backend

	function Get_User( User_Identity: in User_Identity_Type ) return User_Data_Type;
	-- get the user using the data backend

	procedure Store_User( User : in User_Data_Type );
	-- store the user using the backend


	function Do_Login(
				Username : in String;
				Password : in String
			) return User_Type;
	-- do login and initialize the User_Type variable


	function To_Json( User : in User_Data_Type ) return KOW_Lib.Json.Object_Type;
	-- return a JSON object representing the user

	function To_Json_Array( Users : in User_Vectors.Vector ) return KOW_Lib.Json.Array_Type;
	-- return a JSON array representing the users

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





	type Criteria_Type is abstract tagged null record;
	-- The criteria type should be implemented by different
	-- authorization schemas.
	-- This is the type that should be implemented by whoever wants to
	-- extend the authorization type avaliable.


	function Get_Name( Criteria: in Criteria_Type ) return String is abstract;
	-- return a String representing the criteria
	-- it's the same string that will be used when creating it dynamically
	
	function Describe( Criteria: in Criteria_Type ) return String is abstract;
	-- return a string describing the current criteria

	procedure Add_Context(
				Criteria	: in out Criteria_Type;
				Context		: in     Context_Type
			) is abstract;

	procedure Is_Allowed(
				Criteria	: in out Criteria_Type;
				User		: in     User_Type;
				Response	:    out Boolean
			) is abstract;

	procedure Require(	
				Criteria	: in out Criteria_Type;
				User		: in     User_Type 
			);
	-- matches the user against some criteria.
	-- raise ACCESS_DENIED if the user fails this criteria.


	procedure Require(	
				Name		: in     Criteria_Name;
				Descriptor	: in     Criteria_Descriptor;
				User		: in     User_Type;
				Contexts	: in     Context_Array
			);
	-- Create and matches against a criteria using the criteria registry
	

	-----------------------
	-- Criteria Registry --
	-----------------------

	type Criteria_Factory_Type is access function ( Descriptor: in Criteria_Descriptor ) return Criteria_Type'Class;
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
			) return Criteria_Type'Class;
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

	LOGIN_REQUIRED: EXCEPTION;
	-- it's raised by the procedure required when ACCESS_DENIED is raised AND the user is anonymouys
	-- AND the user is not logged in...
	--
	-- can be also used by your own criterias

	ACCOUNT_DISABLED_ERROR : Exception;
	-- used whenever the account can't be used in the login process
end KOW_Sec;
