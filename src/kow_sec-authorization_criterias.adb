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



--------------
-- Ada 2005 --
--------------
with Ada.Characters.Handling; 	use Ada.Characters.Handling;
with Ada.Containers.Vectors;
with Ada.Text_IO;		use Ada.Text_IO;	


-------------------
-- KOW Framework --
-------------------
with KOW_Sec;			use KOW_Sec;


package body KOW_Sec.Authorization_Criterias is

	------------------------------
	-- CURRENT MANAGER CRITERIA --
	------------------------------

	overriding
	function Get_Name( Criteria : in Current_Manager_Criteria_Type ) return String is
	begin
		return "CURRENT_MANAGER";
	end Get_Name;


  	overriding
	procedure Require_Specific(
					Criteria	: in out Current_Manager_Criteria_Type;
					Descriptor	: in     Criteria_Descriptor;
					Is_Allowed	:    out Boolean
				) is
	begin
		Is_Allowed := Get_Manager( Descriptor ) = Criteria.Current_Manager;
	end Require_Specific;


	overriding
	procedure Initialize(
				Criteria	: in out Current_Manager_Criteria_Type;
				User		: in     User_Type
			) is
	begin
		Criteria.Current_Manager := User.Current_Manager;
	end Initialize;


	overriding
	procedure Finalize(
				Criteria	: in out Current_Manager_Criteria_Type
			) is
	begin
		Criteria.Current_Manager := null;
	end Finalize;




	-------------------------
	-- IN MANAGER CRITERIA --
	-------------------------

	overriding
	function Get_Name( Criteria : in In_Manager_Criteria_Type ) return String is
	begin
		return "IN_MANAGER";
	end Get_Name;


  	overriding
	procedure Require_Specific(
					Criteria	: in out In_Manager_Criteria_Type;
					Descriptor	: in     Criteria_Descriptor;
					Is_Allowed	:    out Boolean
				) is
	begin
		Is_Allowed := Has_User( Get_Manager( Descriptor ).all, Criteria.User_Identity );
	end Require_Specific;


	overriding
	procedure Initialize(
				Criteria	: in out In_Manager_Criteria_Type;
				User		: in     User_Type
			) is
	begin
		Criteria.User_Identity := User.Data.Identity;
	end Initialize;

	overriding
	procedure Finalize(
				Criteria	: in out In_Manager_Criteria_Type
			) is
	begin
		Criteria.User_Identity := Anonymous_User_Identity;
	end Finalize;



	--------------------------
	-- EXPRESSIONS CRITERIA --
	--------------------------



	function Get_Name( Criteria: in Expression_Criteria_Type ) return String is
		-- return a String representing the criteria
		-- it's the same string that will be used by the methods:
		--      Register( Name, Factory )
		--      Create_Criteria( Name, Patern ) return Criteria_Interface'Class;
	begin
		return ("EXPRESSION"); 
	end Get_Name;


	function Describe( Criteria: in Expression_Criteria_Type ) return String is
		-- return a string describing the current criteria
	begin
		return To_String( Criteria.Descriptor );
	end Describe;

  	overriding
	procedure Require_Specific(
					Criteria	: in out Expression_Criteria_Type;
					Descriptor	: in     Criteria_Descriptor;
					Is_Allowed	:    out Boolean
				) is

		Index		: Integer		:= 1;		
		Next_Char	: Character		:= Element( Descriptor, Index );
		My_Name		: Unbounded_String	:= To_Unbounded_String("") ;
		My_Descriptor	: Criteria_Descriptor	:= Null_Unbounded_String;


		-- TODO :: require_specific for expression criteria needs a refactoring so it can be easier to read
	begin
		if Is_Valid_Character( Next_Char ) then
			while Next_Char /= '=' and then Index <= Length( Descriptor ) loop
				-- The Name of the Criteria is before the '='.
				My_Name := My_Name & Next_Char; 
				Index := Index + 1;
				Next_Char := Element( Descriptor, Index );
			end loop;	
			
			Index := Index + 1;
			
			if Index <= Length( Descriptor ) then
				Next_Char := Element( Descriptor, Index );
			
				if Next_Char = '{' and then 
					-- takes descriptor enclosed in curly brackets and 
					-- initialize my_descriptor without the curly brackets.
					Element(Descriptor, Length( Descriptor )) = '}' then
					My_Descriptor := To_Unbounded_String( 
						Slice( Descriptor, Index + 1, Length( Descriptor )-1 ) );
				
				elsif Is_Valid_Character( Next_Char ) then
					-- initialize my_descriptor with all characters after the '='.
					My_Descriptor := To_Unbounded_String( 
						Slice( Descriptor, Index, Length( Descriptor ) ) );
				
				else
					raise INVALID_CRITERIA_DESCRIPTOR with
						"Expected curly brackets after of the '=' in " & 
						To_String( Descriptor );
				end if;
			end if;
		end if;

		if My_Descriptor = Null_Unbounded_String or else
			My_Name = To_Unbounded_String("") then
			
			raise INVALID_CRITERIA_DESCRIPTOR with
				"Expected Pattern Criteria_Name '=' Descriptor in " &
				To_String( Descriptor ); 
		end if;

		declare 
			My_Criteria: Criteria_Interface'Class := Criteria_Registry.Create_Criteria( My_Name, My_Descriptor );
		begin
			-- call require using dynamic dispatching
			Require( My_Criteria, Criteria.User);
			Is_Allowed := True;
		exception
			when ACCESS_DENIED => Is_Allowed := False;	
		end;		

	end Require_Specific;




	overriding
	procedure Initialize(
				Criteria	: in out Expression_Criteria_Type;
				User		: in     User_Type
			) is
	begin
		Criteria.User := User;
	end Initialize;

	overriding
	procedure Finalize(
				Criteria	: in out Expression_Criteria_Type
			) is
	begin
		Criteria.User.Data := KOW_Sec.Anonymous_User;
		Criteria.User.Current_manager := null;
	end Finalize;




	--------------------
	-- GROUP CRITERIA --
	--------------------
	
	function Get_Name( Criteria: in Group_Criteria_Type ) return String is
	begin
		return ("GROUP"); 
	end Get_Name;


	function Describe( Criteria: in Group_Criteria_Type ) return String is
	begin
		return "Matches groups based on :: " & To_String( Criteria.Descriptor );
	end Describe;


  	overriding
	procedure Require_Specific(
					Criteria	: in out Group_Criteria_Type;
					Descriptor	: in     Criteria_Descriptor;
					Is_Allowed	:    out Boolean
				) is
	begin
		Is_Allowed := Group_Vectors.Contains( Criteria.Groups, Group_Type( To_String( Descriptor ) ) );
	end Require_Specific;

	overriding
	procedure Initialize(
				Criteria	: in out Group_Criteria_Type;
				User		: in     User_Type
			) is
	begin
		Criteria.Groups := KOW_Sec.Get_Groups( User );
	end Initialize;

	overriding
	procedure Finalize(
				Criteria	: in out Group_Criteria_Type
			) is
	begin
		Group_Vectors.Clear( Criteria.Groups );
	end Finalize;

	-------------------
	-- ROLE CRITERIA --
	-------------------

	overriding
	function Get_Name( Criteria : Role_Criteria_Type ) return String is
	begin
		return "ROLE";
	end Get_Name;


	overriding
	function Describe( Criteria : Role_Criteria_Type ) return String is
	begin
		return "Matches roles based on :: " & To_String( Criteria.Descriptor );
	end Describe;



  	overriding
	procedure Require_Specific(
					Criteria	: in out Role_Criteria_Type;
					Descriptor	: in     Criteria_Descriptor;
					Is_Allowed	:    out Boolean
				) is
	begin
		Is_Allowed := Role_Vectors.Contains( Criteria.Roles, To_Role( To_Identity( To_String( Descriptor ) ) ) );
	end Require_Specific;

	overriding
	procedure Initialize(
				Criteria	: in out Role_Criteria_Type;
				User		: in     User_Type
			) is
	begin
		Criteria.Roles := KOW_Sec.Get_Roles( User, True );
	end initialize;

	overriding
	procedure Finalize(
				Criteria	: in out Role_Criteria_Type
			) is
	begin
		Role_Vectors.Clear( Criteria.Roles );
	end Finalize;



	--------------------
	-- USERS CRITERIA --
	--------------------
	

	
	function Get_Name( Criteria: in User_Criteria_Type ) return String is
	begin
		return ("USER"); 
	end Get_Name;


	function Describe( Criteria: in User_Criteria_Type ) return String is
		-- return a string describing the current criteria
	begin
		return "Matches user identity based on :: " & To_String( Criteria.Descriptor );
	end Describe;

	overriding
	procedure Require_Specific(
					Criteria	: in out User_Criteria_Type;
					Descriptor	: in     Criteria_Descriptor;
					Is_Allowed	:    out Boolean
				) is
	begin
		Is_Allowed := User_Identity_Type( To_String( Descriptor ) ) = Criteria.User_Identity;
	end Require_Specific;

	overriding
	procedure Initialize(
				Criteria	: in out User_Criteria_Type;
				User		: in     User_Type
			) is
	begin
		Criteria.User_Identity := User.Data.Identity;
	end Initialize;

	overriding
	procedure Finalize(
				Criteria	: in out User_Criteria_Type
			) is
	begin
		Criteria.User_Identity := KOW_Sec.Anonymous_User_Identity;
	end Finalize;




begin
	KOW_Sec.Criteria_Registry.Register( Create_Current_Manager_Criteria'Access );
	KOW_Sec.Criteria_Registry.Register( Create_In_Manager_Criteria'Access );
	KOW_Sec.Criteria_Registry.Register( Create_Expression_Criteria'Access );
	KOW_Sec.Criteria_Registry.Register( Create_Group_Criteria'Access );
	KOW_Sec.Criteria_Registry.Register( Create_Role_Criteria'Access );
	KOW_Sec.Criteria_Registry.Register( Create_User_Criteria'Access );

end KOW_Sec.Authorization_Criterias;
