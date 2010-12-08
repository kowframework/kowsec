------------------------------------------------------------------------------
--                                                                          --
--                       KOW Framework :: Security                          --
--                                                                          --
--                              KOW Framework                               --
--                                                                          --
--                                 B o d y                                  --
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
with Ada.Calendar;		use Ada.Calendar;
with Ada.Containers.Vectors;
with Ada.Containers.Hashed_Maps;
with Ada.Containers.Ordered_Maps;
with Ada.Finalization;
with Ada.Strings;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded;	use Ada.Strings.Unbounded;
with Ada.Strings.Unbounded.Hash;
with Ada.Numerics.Discrete_Random;

----------
-- GNAT --
----------
with GNAT.MD5;


-------------------
-- KOW Framework --
-------------------
with KOW_Lib.Locales;
with KOW_Lib.UString_Ordered_Maps;


with KOW_Sec.Authorization_Criterias;
pragma Elaborate( KOW_Sec.Authorization_Criterias );
with KOW_Sec.Data;

-------------
-- Contrib --
-------------




package body KOW_Sec is

	
	----------------------------
	-- The User Identity Type --
	----------------------------
	
	----------------------------
	-- The User Identity Type --
	----------------------------
	

	function MD5_Sign( Str : in String ) return String is

		-- calculates the hash of this identity
		use GNAT.MD5;
		C : Context;
	begin
		Update( C, Str );
		return Digest( C );
	end MD5_Sign;

	function To_Identity( Str : in String ) return User_Identity_Type is
	begin
		return User_Identity_Type( MD5_Sign( Str ) );
	end To_Identity;

	function New_User_Identity return User_Identity_Type is
		-- this will generate a brand new user identity
		

		function The_Timestamp return String is
			T	: Time := Clock;
			Y	: Year_Number;
			M	: Month_Number;
			D	: Day_Number;
			S	: Day_Duration;
		begin
			Split( T, Y, M, D, S );
			return Year_Number'Image( Y ) & Month_Number'Image( M ) & Day_Number'Image( D ) & Day_Duration'Image( S );
		end The_Timestamp;


		function The_Random_Part return String is
			Str : String( 1 .. 20 );


			package Char_Rand is new Ada.Numerics.Discrete_Random( Result_Subtype => Character );
			use Char_Rand;

			G : Generator;
		begin
			Reset( G );
			for i in Str'Range loop
				Str( I ) := Random( G );
			end loop;
			return Str;
		end The_Random_Part;


		function The_Key return String is
			-- the timestamp + 20 random leters
		begin
			return The_Timestamp & The_Random_Part;
		end The_Key;

	begin
		return To_Identity( The_Key );
	end New_User_Identity;


	-------------------------------
	-- AUTHENTICATION MANAGEMENT --
	-------------------------------


	procedure Register_Manager( Manager: in out Authentication_Manager_Access ) is
	-- Register a manager so it's usable by KOW_Sec.
	begin
		Authentication_Manager_Maps.Insert(
						Container	=>Managers_Registry,
						Key		=> To_Unbounded_String( Get_Name( Manager.all ) ),
						New_Item	=> Manager
					);
	end Register_Manager;
	
	function Get_Manager( Manager_Name : in String ) return Authentication_Manager_Access is
	begin
		return Get_Manager( To_Unbounded_String( Manager_Name ) );
	end Get_Manager;

	function Get_Manager( Manager_Name : in Unbounded_String ) return Authentication_Manager_Access is
	begin
		return Authentication_Manager_Maps.Element( Managers_Registry, Manager_Name );
	exception
		when CONSTRAINT_ERROR =>
			raise CONSTRAINT_ERROR with "no such authentication manager :: " & To_String( Manager_Name );
	end Get_Manager;

	function Do_Login(
				Username : in String;
				Password : in String
			) return User_Identity_Type is
		-- tries to login the user using the registered managers.
		-- the pair username vs password here is quite abstract.. the manager can implement
		-- this function giving different meanings to the data received
		use Authentication_Manager_Maps;

		C: Authentication_Manager_Maps.Cursor := First( Managers_Registry );

		User_Identity	: User_Identity_Type;
		User		: User_Type;
	begin
		while Has_Element( C )
		loop
			begin
				User_Identity :=  Do_Login(
							Element( C ).all,
							Username,
							Password
						);
				-- now we check the user status... we only allow enabled users..
				User := Get_User( User_Identity );

				if User.Account_Status /= Account_Enabled then
					raise ACCESS_DENIED with "The user is not enabled right now. The current status is: " & Account_Status_Type'Image( User.Account_Status );
				end if;

				return User_Identity;
			exception
				when INVALID_CREDENTIALS | UNKNOWN_USER => null;
			end;
			C := Next( C );
		end loop;

		raise INVALID_CREDENTIALS with "for username """ & Username & """";

	end Do_Login;




	----------------------
	-- Roles Management --
	----------------------

	function To_Identity( Str : in String ) return Role_Identity_Type is
		Id : Role_Identity_Type;
	begin
		Id( 1 .. Str'Length ) :=  Role_Identity_Type( Str );
		Id( Str'Length + 1 .. Id'Last ) := ( others => ' ' );
		return Id;
	end To_Identity;

	function Identity( Role : in Role_type ) return Role_Identity_Type is
		use Ada.Strings;
		-- returns Application::Role
	begin
		return To_Identity( Fixed.Trim( Role.Application, Both ) & "::" & Fixed.Trim( Role.Role, Both ) );
	end Identity;


	function To_Role( Identity : in Role_Identity_Type ) return Role_Type is
		-- parse the role identity into a role

		Id_Str	: String := Ada.Strings.Fixed.Trim( String( Identity ), Ada.Strings.Both );
		Index	: Natural := Ada.Strings.Fixed.Index( Id_Str, "::" );
		Role	: Role_Type;
		Role_Len: Positive;
	begin
		if Index <= 1 OR ELSE Index >= 101 then
			raise CONSTRAINT_ERROR with "Not a valid role identity: " & Id_Str;
		end if;

		Role.Application( 1 .. Index - 1 ) := Id_Str( 1 .. Index - 1 );
		Role.Application( Index .. Role.Application'Last ) := ( others => ' ' );

		Role_Len := Id_Str'Last - Index - 2;

		Role.Role( 1 .. Role_Len ) := Id_Str( Index + 2 .. Id_Str'Last );
		Role.Role( Role_Len + 1 .. Role.Role'Last ) := ( others => ' ' );


		return Role;

	end To_Role;

	protected body Roles_Registry is
		procedure Register( Application, Role : in String ) is
		begin
			Register( Role_Type'( Application => Application, Role => Role ) );
		end Register;

		procedure Register( Role : in Role_Type ) is
		begin
			Role_Maps.Include( My_Roles, Identity( Role ), Role );
		end Register;
		

		function Get_Roles return Role_Maps.Map is
		begin
			return My_Roles;
		end Get_Roles;
	end Roles_Registry;



	-----------------------
	-- Groups Management --
	-----------------------


	function To_String( Group : Group_Type ) return String is
		-- get the trimmed version of group_type
	begin
		return Ada.Strings.Fixed.Trim( String( Group ), Ada.Strings.Both );
	end To_String;

	package Group_Roles_Data is new KOW_Sec.Data(
				Storage_Name	=> "group_roles",
				Key_Type	=> Group_type,
				To_String	=> To_String,
				Element_Type	=> Role_Type,
				Element_Vectors	=> Role_Vectors
			);


	function Get_Roles( Group : in Group_Type ) return Role_Vectors.Vector is
	begin
		return Group_Roles_Data.Get_All( Group );
	end Get_Roles;

	procedure Set_Roles( Group : in Group_Type; Roles : in Role_Vectors.Vector ) is
	begin
		Group_Roles_Data.Store( Group, Roles );
	end Set_Roles;


	---------------------
	-- User Management --
	---------------------

	function To_String( Identity : in User_IDentity_Type ) return String is
	begin
		return String( Identity );
	end to_String;

	package User_Groups_Data is new KOW_Sec.Data(
				Storage_Name	=> "user_groups",
				Key_Type	=> User_Identity_Type,
				To_String	=> To_String,
				Element_Type	=> Group_Type,
				Element_Vectors	=> Group_Vectors
			);

	package User_Roles_Data is new KOW_Sec.Data(
				Storage_Name	=> "user_roles",
				Key_Type	=> User_Identity_Type,
				To_String	=> To_String,
				Element_Type	=> Role_Type,
				Element_Vectors	=> Role_Vectors
			);
	package User_Data is new KOW_Sec.Data(
				Storage_Name	=> "users",
				Key_Type	=> User_Identity_type,
				To_String	=> To_String,
				Element_Type	=> User_Type,
				Element_Vectors	=> User_Vectors
			);

	function Identity( User : in User_Type ) return String is
		-- Return a string identifying the current user. Usually it's the username
		-- but one could implement other methods, such as a numeric id for this user
	begin
		return To_String( User.Identity );
	end Identity;

	function Full_Name(
				User	: in User_Type;
				Locale	: in KOW_Lib.Locales.Locale := KOW_Lib.Locales.Default_Locale
		) return String is
	-- return the full name for this user, respecting the locale's conventions

	begin
		if Is_Anonymous( User ) then
			return KOW_Lib.Locales.Get_Formated_Full_Name(
					L		=> Locale,
					First_Name	=> "Anonymous",
					Last_Name	=> "User"
				);
		else
			return KOW_Lib.Locales.Get_Formated_Full_Name(
					L		=> Locale,
					First_Name	=> Ada.Strings.Fixed.Trim( User.First_Name, Ada.Strings.Both ),
					Last_Name	=> Ada.Strings.Fixed.Trim( User.Last_Name, Ada.Strings.Both )
				);
		end if;
	end Full_Name;


	function Gravatar_URL( User : in User_Type; Size : Positive := 69 ) return String is
		-- return the gravatar URL for the given user
		S : constant String := Ada.Strings.Fixed.Trim( Positive'Image( Size ), Ada.Strings.Both );
	begin
		return "http://www.gravatar.com/avatar/" & MD5_Sign( Ada.Strings.Fixed.Trim( User.Primary_Email, Ada.Strings.Both ) ) & ".jpg?s=" & S;
	end Gravatar_URL;

	function Get_Groups( User : in User_Type ) return Group_Vectors.Vector is
	begin
		return User_Groups_Data.Get_All( User.Identity );
	end Get_Groups;

	function Get_Groups( User : in Logged_User_Type ) return Group_Vectors.Vector is
		pragma Inline( Get_Groups );
	begin
		return Get_Groups( User.User );
	end Get_Groups;

	procedure Set_Groups( User : in User_Type; Groups : in Group_Vectors.Vector ) is
	begin
		User_Groups_Data.Store( User.Identity, Groups );
	end Set_Groups;


	function Get_Roles(
				User			: in User_Type;
				Combine_Group_Roles	: in Boolean := False
			) return Role_Vectors.Vector is
		-- if combine group roles is true, does exactly that given that only one instance of each role is returned

		use Role_Vectors;

		V : Vector;


		procedure Append_Once( Role : Role_Type ) is
		begin
			if not Contains( V, Role ) then
				Append( V, Role );
			end if;
		end Append_Once;

		procedure Append( From_Vector : in Vector ) is
			procedure Iterator( C: in Cursor ) is
			begin
				Append_once( Element( C ) );
			end Iterator;
		begin
			Iterate( From_Vector, Iterator'Access );
		end Append;

		procedure Groups_Iterator( C : Group_Vectors.Cursor ) is
		begin
			Append( Group_Roles_Data.Get_All( Group_Vectors.Element( C ) ) );
		end Groups_Iterator;

	begin
		V := User_Roles_Data.Get_All( User.Identity );
		if Combine_Group_Roles then
			Group_Vectors.Iterate( User_Groups_Data.Get_all( User.Identity ), Groups_Iterator'Access );
		end if;

		return V;
	end Get_Roles;


	function Get_Roles(
				User			: in Logged_User_Type;
				Combine_Group_Roles	: in Boolean := False
			) return Role_Vectors.Vector is
		pragma Inline( Get_Roles );
	begin
		return Get_Roles( User.User, Combine_Group_Roles );
	end Get_Roles;



	procedure Set_Roles( User : in User_Type; Roles : in Role_Vectors.Vector ) is
	begin
		User_Roles_Data.Store( User.Identity, Roles );
	end Set_Roles;

	function Is_Anonymous( User : in User_type ) return Boolean is
		-- Return true if this user isn't logged in.
	begin
		return User.Identity = ( 1 .. 32 => ' ' ) or else User.Identity = Anonymous_User_Identity;
	end Is_Anonymous;



	function Is_Anonymous( User : in Logged_User_type ) return Boolean is
		-- Return true if this user isn't logged in.
	begin
		return Is_Anonymous( User.User );
	end Is_Anonymous;

	function Get_User( User_Identity: in String ) return User_Type is
	begin
		return Get_User( To_Identity( User_Identity ) );
	end Get_User;

	function Get_User( User_Identity: in User_Identity_Type ) return User_Type is
	begin
		return User_Data.Get_First( User_Identity, True );
	end Get_User;



	procedure Store_User( User : in User_Type ) is
		-- store the user using the backend
	begin
		User_Data.Store( User.Identity, User );
	end Store_User;



	function Do_Login(
				Username : in String;
				Password : in String
			) return Logged_User_Type is
		-- do login and initialize the logged_user_type variable
		use Authentication_Manager_Maps;

		C: Authentication_Manager_Maps.Cursor := First( Managers_Registry );
	begin
		while Has_Element( C )
		loop
			begin
				declare
					Identity : User_Identity_Type := Do_Login(
										Element( C ).all,
										Username,
										Password
									);
					User 	: Logged_User_Type := (
									User		=> Get_User( Identity ),
									Current_Manager => Element( C )
								);
				begin


					if User.User.Account_Status /= Account_Enabled then
						raise ACCESS_DENIED with "The user is not enabled right now. The current status is: " & Account_Status_Type'Image( User.User.Account_Status );
					end if;
					return User;
				end;

			exception
				when INVALID_CREDENTIALS | UNKNOWN_USER => null;
			end;
			C := Next( C );
		end loop;

		raise INVALID_CREDENTIALS with "for username """ & Username & """";

	end Do_Login;






	------------------------------
	-- Authorization Management --
	------------------------------
	

	procedure Require(	
				Name		: in     Criteria_Name;
				Descriptor	: in     Criteria_Descriptor;
				User		: in     Logged_User_Type
			) is
		-- Create and matches against a criteria using the criteria registry
		Criteria : Criteria_Interface'Class := Criteria_Registry.Create_Criteria( Name, Descriptor );
	begin
		Require( Criteria, User );
	end Require;

	-----------------------
	-- Criteria Registry --
	-----------------------


	protected body Criteria_Registry is
		--  we created a protected type here so our code is task-safe.
		procedure Register( Factory : in Criteria_Factory_Type ) is
			-- Register a criteria based on it's name.
			-- If there is another criteria with the same name,
			-- raises Duplicated_Criteria
		

			D	: Criteria_Descriptor;
			Name	: Criteria_Name := To_Unbounded_String( Get_Name( Factory.all( D ) ) );
		begin
			if Criteria_Maps.Contains( Map, Name ) then
				raise DUPLICATED_CRITERIA with "Name: " & To_String( Name );
			end if;

			Criteria_Maps.Insert( Map, Name, Factory );
		end Register;

		procedure Unload( Name : in Criteria_name ) is
			-- remove this criteria from the registry.
		begin
			if Criteria_Maps.Contains( Map, Name ) then
				Criteria_Maps.Delete( Map, Name );
			end if;

			raise INVALID_CRITERIA with "Can't unload " & To_String(Name);
		end Unload;


		procedure Empty_Criteria_Registry is
			-- used to unload all the criterias from the registry.
		begin
			Criteria_Maps.Clear( Map );
		end Empty_Criteria_Registry;


		function Create_Criteria(
					Name		: in Criteria_Name; 
					Descriptor	: in Criteria_Descriptor
			) return Criteria_Interface'Class is
		-- create a new criteria object from an already registered criteria type
		-- based on it's name and the given Descriptor.
		-- if there is no such criteria, raises INVALID_CRITERIA
			Factory: Criteria_Factory_Type;
		begin
			if not Criteria_Maps.Contains( Map, Name ) then
				raise INVALID_CRITERIA with "Can't create " & To_String(Name);
			end if;

			Factory := Criteria_Maps.Element( Map, Name );

			return Factory.all( Descriptor );
		end Create_Criteria;

	end Criteria_Registry;

begin

	Anonymous_User_Identity := To_Identity( "anonymous" );
end KOW_Sec;
