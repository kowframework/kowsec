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
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded;	use Ada.Strings.Unbounded;
with Ada.Strings.Unbounded.Hash;
with Ada.Numerics.Discrete_Random;

-------------------
-- KOW Framework --
-------------------
with KOW_Lib.Locales;
with KOW_Lib.UString_Ordered_Maps;


with KOW_Sec.Authorization_Criterias;
pragma Elaborate( KOW_Sec.Authorization_Criterias );

-------------
-- Contrib --
-------------
with MD5;




package body KOW_Sec is

	
	----------------------------
	-- The User Identity Type --
	----------------------------
	
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
		return To_Identity( MD5.Calculate( The_Key ) );
	end New_User_Identity;


	-------------------------------
	-- AUTHENTICATION MANAGEMENT --
	-------------------------------


	procedure Register_Manager( Manager: in out Authentication_Manager_Access ) is
	-- Register a manager so it's usable by KOW_Sec.
	begin
		Append( Managers_Registry, Manager );
	end Register_Manager;
	

	function Do_Login(
				Username : in String;
				Password : in String
			) return User_Identity_Type is
		-- tries to login the user using the registered managers.
		-- the pair username vs password here is quite abstract.. the manager can implement
		-- this function giving different meanings to the data received
		use Authentication_Manager_Vectors;

		C: Authentication_Manager_Vectors.Cursor := First( Managers_Registry );
	begin
		while Has_Element( C )
		loop
			begin
				return Do_Login(
						Element( C ).all,
						Username,
						Password
					);
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

	function Identity( Role : in Role_type ) return Role_Identity_Type is
		-- returns Application::Role
	begin
		return Role_Identity_Type( Role.Application ) & "::" & Role_IDentity_Type( Role.Role );
	end Identity;


	protected body Roles_Registry is
		procedure Register( Application, Role : in String ) is
		begin
			Register( To_Unbounded_String( Application ), To_Unbounded_String( Role ) );
		end Register;

		procedure Register( Application, Role : in Unbounded_String ) is
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
	

	function Get_Roles( Group : in Group_Type ) return Role_Vectors.Vector is
		-- TODO return the roles assigned to a given group
		V : Role_Vectors.Vector;
	begin
		raise CONSTRAINT_ERROR with "not implemented yet";
		return V;
	end Get_Roles;


	---------------------
	-- User Management --
	---------------------


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
					First_Name	=> To_String( User.First_Name ),
					Last_Name	=> To_String( User.Last_Name )
				);
		end if;
	end Full_Name;


	function Gravatar_URL( User : in User_Type; Size : Positive := 69 ) return String is
		-- return the gravatar URL for the given user
		S : constant String := Ada.Strings.Fixed.Trim( Positive'Image( Size ), Ada.Strings.Both );
	begin
		return "http://www.gravatar.com/avatar/" & MD5.Calculate( To_String( User.Primary_Email ) ) & ".jpg?s=" & S;
	end Gravatar_URL;

	function Get_Groups( User : in User_Type ) return Group_Vectors.Vector is
		-- TODO Get the groups for this user.
		V : Group_Vectors.Vector;
	begin
		raise CONSTRAINT_ERROR with "not implemented yet";
		return V;
	end Get_Groups;


	function Get_Roles( User : in User_Type; Combine_Group_Roles : in Boolean := False) return Role_Vectors.Vector is
		-- TODO get all roles by a given user
		-- if combine group roles is true, does exactly that given that only one instance of each role is returned
		V : Role_Vectors.Vector;
	begin
		raise CONSTRAINT_ERROR with "not implemented yet";
		return V;
	end Get_Roles;

	function Is_Anonymous( User : in User_type ) return Boolean is
		-- Return true if this user isn't logged in.
	begin
		return Length( User.Identity ) = 0 or else User.Identity = Anonymous_User_Identity;
	end Is_Anonymous;

	function Get_User( User_Identity: in String ) return User_Type is
		-- get the user using the data backend
		U : User_Type;
	begin
		raise CONSTRAINT_ERROR with "not implemented yet";
		return U;
	end Get_User;
















	------------------------------
	-- Authorization Management --
	------------------------------
	

	procedure Require(	
				User		: in out User_Type;
				Name		: in     Criteria_Name;
				Descriptor	: in     Criteria_Descriptor
			) is
		-- Create and matches against a criteria using the criteria registry
	begin
		Require( User, Criteria_Registry.Create_Criteria( Name, Descriptor ) );
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







end KOW_Sec;
