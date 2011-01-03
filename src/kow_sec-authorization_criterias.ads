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


------------------------------------------------------------------------------
-- This is the KOW_Sec.Authorization_Criteria_Types package                      --
------------------------------------------------------------------------------



------------------------------------------------------------------------------
-- This package contains some common criterias                              --
------------------------------------------------------------------------------


with KOW_Sec.Logic_Criterias;		use KOW_Sec.Logic_Criterias;

package KOW_Sec.Authorization_Criterias is
pragma Elaborate_Body( KOW_Sec.Authorization_Criterias );


	------------------------------
	-- CURRENT MANAGER CRITERIA --
	------------------------------

	type Current_Manager_Criteria_Type is new Logic_Criteria_Type with record
		-- check if the user has been authenticated by the given criteria
		Current_Manager	: Authentication_Manager_Access;
	end record;

	overriding
	function Get_Name( Criteria : in Current_Manager_Criteria_Type ) return String;
	-- return CURRENT_MANAGER 


  	overriding
	procedure Require_Specific(
					Criteria	: in out Current_Manager_Criteria_Type;
					Descriptor	: in     Criteria_Descriptor;
					Is_Allowed	:    out Boolean
				);
	overriding
	procedure Initialize(
				Criteria	: in out Current_Manager_Criteria_Type;
				User		: in     User_Type
			);
	overriding
	procedure Finalize(
				Criteria	: in out Current_Manager_Criteria_Type
			);

	function Create_Current_Manager_Criteria is new Generic_Logic_Criteria_Factory( Criteria_Type => Current_Manager_Criteria_Type );

	-------------------------
	-- IN MANAGER CRITERIA --
	-------------------------

	type In_Manager_Criteria_Type is new Logic_Criteria_Type with record
		-- check if the user can be authenticated by the given criteria
		User_Identity	: User_Identity_Type;
	end record;

	overriding
	function Get_Name( Criteria : in In_Manager_Criteria_Type ) return String;
	-- return In_Manager 


  	overriding
	procedure Require_Specific(
					Criteria	: in out In_Manager_Criteria_Type;
					Descriptor	: in     Criteria_Descriptor;
					Is_Allowed	:    out Boolean
				);
	overriding
	procedure Initialize(
				Criteria	: in out In_Manager_Criteria_Type;
				User		: in     User_Type
			);
	overriding
	procedure Finalize(
				Criteria	: in out In_Manager_Criteria_Type
			);
	function Create_In_Manager_Criteria is new Generic_Logic_Criteria_Factory( Criteria_Type => In_Manager_Criteria_Type );


	-------------------------
	-- EXPRESSION CRITERIA --
	-------------------------
	

	type Expression_Criteria_Type is new Logic_Criteria_Type with record
		-- Criteria of authorization associating others criterias.
		-- Example: USERS={adele|OgRo}&GROUPS={!design&(dev|admin)} 
		User		: User_Type;
	end record;
	


	overriding
	function Get_Name( Criteria: in Expression_Criteria_Type ) return String;
	-- return EXPRESSION

	overriding
	function Describe( Criteria: in Expression_Criteria_Type ) return String;
	
  	overriding
	procedure Require_Specific(
					Criteria	: in out Expression_Criteria_Type;
					Descriptor	: in     Criteria_Descriptor;
					Is_Allowed	:    out Boolean
				);
	overriding
	procedure Initialize(
				Criteria	: in out Expression_Criteria_Type;
				User		: in     User_Type
			);
	overriding
	procedure Finalize(
				Criteria	: in out Expression_Criteria_Type
			);

	function Create_Expression_Criteria is new Generic_Logic_Criteria_Factory( Criteria_Type => Expression_Criteria_Type );



	--------------------
	-- GROUP CRITERIA --
	--------------------

	type Group_Criteria_Type is new Logic_Criteria_Type with record
		-- matches group names
		Groups		: Group_Vectors.Vector;
	end record;

	overriding
	function Get_Name( Criteria: in Group_Criteria_Type ) return String;

	overriding
	function Describe( Criteria: in Group_Criteria_Type ) return String;
	
  	overriding
	procedure Require_Specific(
					Criteria	: in out Group_Criteria_Type;
					Descriptor	: in     Criteria_Descriptor;
					Is_Allowed	:    out Boolean
				);
	overriding
	procedure Initialize(
				Criteria	: in out Group_Criteria_Type;
				User		: in     User_Type
			);
	overriding
	procedure Finalize(
				Criteria	: in out Group_Criteria_Type
			);

	function Create_Group_Criteria is new Generic_Logic_Criteria_Factory( Criteria_Type => Group_Criteria_Type );




	-------------------
	-- ROLE CRITERIA --
	-------------------
	type Role_Criteria_Type is new Logic_Criteria_Type with record
		-- matches user Role (including the group Role)
		Roles		: Role_Vectors.Vector;
	end record;

	overriding
	function Get_Name( Criteria : Role_Criteria_Type ) return String;
	-- return ROLE


	overriding
	function Describe( Criteria : Role_Criteria_Type ) return String;

  
  	overriding
	procedure Require_Specific(
					Criteria	: in out Role_Criteria_Type;
					Descriptor	: in     Criteria_Descriptor;
					Is_Allowed	:    out Boolean
				);

	overriding
	procedure Initialize(
				Criteria	: in out Role_Criteria_Type;
				User		: in     User_Type
			);
	overriding
	procedure Finalize(
				Criteria	: in out Role_Criteria_Type
			);

	function Create_Role_Criteria is new Generic_Logic_Criteria_Factory( Criteria_Type => Role_Criteria_Type );



	-------------------
	-- USER CRITERIA --
	-------------------

	type User_Criteria_Type is new Logic_Criteria_Type with record
		-- matches the user identity
		User_Identity	: User_Identity_Type;
	end record;


	overriding
	function Get_Name( Criteria: in User_Criteria_Type ) return String;
	-- return USER

	overriding
	function Describe( Criteria: in User_Criteria_Type ) return String;
	
  	overriding
	procedure Require_Specific(
					Criteria	: in out User_Criteria_Type;
					Descriptor	: in     Criteria_Descriptor;
					Is_Allowed	:    out Boolean
				);
	overriding
	procedure Initialize(
				Criteria	: in out User_Criteria_Type;
				User		: in     User_Type
			);
	overriding
	procedure Finalize(
				Criteria	: in out User_Criteria_Type
			);

	function Create_User_Criteria is new Generic_Logic_Criteria_Factory( Criteria_Type => User_Criteria_Type );


	
	
end KOW_Sec.Authorization_Criterias;
