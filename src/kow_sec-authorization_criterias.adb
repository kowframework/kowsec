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
-- This is the KOW_Sec.Authorization_Criterias package                       --
------------------------------------------------------------------------------


--------------
-- Ada 2005 --
--------------
with Ada.Characters.Handling; 	use Ada.Characters.Handling;
with Ada.Containers.Vectors;
with Ada.Text_IO;		use Ada.Text_IO;	


---------------
-- Ada Works --
---------------
with KOW_Sec;			use KOW_Sec;
with KOW_Sec.Criterias_Util;	use KOW_Sec.Criterias_Util;


package body KOW_Sec.Authorization_Criterias is


	-----------
	-- Roles --
	-----------

	type Roles_Criteria_Type is new KOW_Sec.Criteria_Interface with private;

	function Create_Roles_Criteria( Descriptor : in Criteria_Descriptor ) return Criteria_Interface'Class;

	overriding
	function Get_Name( Criteria : Roles_Criteria_Type ) return String;


	overriding
	function Describe( Criteria : Roles_Criteria_Type ) return String;

	overriding
	procedure Require(
				User	: in out User_Type;
				Criteria: in     Roles_Criteria_Type
			);


	---------------------
	-- GROUPS CRITERIA --
	---------------------
	
	procedure Eval_Groups(	
				Descriptor	: in     Criteria_Descriptor;
				User		: in out User_Type;
				Ret_Code	: out    Boolean
			) is
		-- Procedure evaluate to the Bool_Parse. Descriptor is
		-- a group name.

		Groups	: Group_Vectors.Vector;
		C	: Group_Vectors.Cursor;
	begin
		Groups := KOW_Sec.Get_Groups( User );
	
		if Group_Vectors.Contains(Groups, Group_Type( To_String( Descriptor ) ) ) then
			Ret_Code := True;
		else
			Ret_Code := False;
		end if;
	end Eval_Groups;

	package Groups_Parse is new Bool_Parse( Pattern		=> Criteria_Descriptor,
						Evaluate	=> Eval_Groups); 
	
	function Create_Group_Criteria( Descriptor: in Criteria_Descriptor )
		return Criteria_Interface'Class is
		-- create a GROUPS criteria to be matched
		-- based on the given Descriptor.
		My_Criteria: Group_Criteria_Type := ( Descriptor => Descriptor );
	begin		
		return My_Criteria;
	end Create_Group_Criteria;


	procedure Require(	User	: in out User_Type;
				Criteria	: in Group_Criteria_Type ) is
		use Groups_Parse;

		Parser : Bool_Parser := (
					User		=> User,
					Descriptor	=> Criteria.Descriptor,
					Index		=> 0
				);
		Exp : Expression_Access;
		Ret_Value : Boolean := False;
	begin
		Parse(Parser, Exp); 
		IsTrue(Exp.all, Parser, Ret_Value); 

		if not Ret_Value then
			raise ACCESS_DENIED with "Reason: " &
			To_String( Criteria.Descriptor );
		end if;
	end Require;
	

	function Get_Name( Criteria: in Group_Criteria_Type ) return String is
		-- return a String representing the criteria
		-- it's the same string that will be used by the methods:
		--      Register( Name, Factory )
		--      Create_Criteria( Name, Patern ) return Criteria_Interface'Class;
	begin
		return ("GROUPS"); 
	end Get_Name;


	function Describe( Criteria: in Group_Criteria_Type ) return String is
		-- return a string describing the current criteria
	begin
		return To_String( Criteria.Descriptor );
	end Describe;

	--------------------
	-- USERS CRITERIA --
	--------------------
	
	procedure Eval_Users(	Descriptor	: in Criteria_Descriptor;
				User	: in out User_Type;
				Ret_Code	: out Boolean ) is
		-- Procedure evaluate to the Bool_Parse. Descriptor is
		-- a username.
	begin
		if User_Identity_Type( To_String( Descriptor ) ) = User.Identity then
			Ret_Code := True;
		else
			Ret_Code := False;
		end if;
	end Eval_Users;

	package Users_Parse is new Bool_Parse(	Pattern		=> Criteria_Descriptor,
						Evaluate	=> Eval_Users); 
	
	function Create_User_Criteria( Descriptor: in Criteria_Descriptor )
		return Criteria_Interface'Class is
		-- create a User_Criteria_Type to be matched
		-- based on the given Descriptor.
		
		My_Criteria: User_Criteria_Type := ( Descriptor => Descriptor );
	begin
		return My_Criteria;
	end Create_User_Criteria;


	procedure Require(	User: in out User_Type; 
				Criteria: in User_Criteria_Type ) is
		use Users_Parse;
		
		Parser: Bool_Parser := (
				User	=> User,
				Descriptor	=> Criteria.Descriptor,
				Index		=> 0 );
		Exp : Expression_Access;
		Ret_Value : Boolean := False;
	begin
		Parse( Parser, Exp ); 
		IsTrue( Exp.all, Parser, Ret_Value ); 


		if not Ret_Value then
			raise ACCESS_DENIED with "Reason: " &
			To_String( Criteria.Descriptor );
		end if;
	end Require;
	
	
	function Get_Name( Criteria: in User_Criteria_Type ) return String is
		-- return a String representing the criteria
		-- it's the same string that will be used by the methods:
		--      Register( Name, Factory )
		--      Create_Criteria( Name, Patern ) return Criteria_Interface'Class;
	begin
		return ("USERS"); 
	end Get_Name;


	function Describe( Criteria: in User_Criteria_Type ) return String is
		-- return a string describing the current criteria
	begin
		return To_String( Criteria.Descriptor );
	end Describe;



	--------------------------
	-- EXPRESSIONS CRITERIA --
	--------------------------

	procedure Eval_Expressions(	Descriptor	: in Criteria_Descriptor;
					User	: in out User_Type;
					Ret_Code	: out Boolean ) is
		-- Procedure evaluate to the Bool_Parse. Descriptor is a 
		-- expression like 'criteria_name={criteria_descriptor}'. 
	
		Index		: Integer		:= 1;		
		Next_Char	: Character		:= Element( Descriptor, Index );
		My_Name		: Unbounded_String	:= To_Unbounded_String("") ;
		My_Descriptor	: Criteria_Descriptor	:= Null_Unbounded_String;
	begin
		if Is_Valid_Character( Next_Char ) then
		
			while Next_Char /= '=' and then Index <= Length( Descriptor ) 
			loop
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
			Require( User, My_Criteria );
			Ret_Code := True;
		exception
			when ACCESS_DENIED => Ret_Code := False;	
		end;		

	end Eval_Expressions;


	package Expressions_Parse is new Bool_Parse(	Pattern		=> Criteria_Descriptor,
							Evaluate	=> Eval_Expressions); 
	
	function Create_Expression_Criteria( Descriptor: in Criteria_Descriptor )
		return Criteria_Interface'Class is
		-- create a Expression_Criteria_Type to be matched
		-- based on the given Descriptor.
		
		My_Criteria: Expression_Criteria_Type := (Descriptor => Descriptor );
	begin
		return My_Criteria;
	end Create_Expression_Criteria;


	procedure Require(	User	: in out User_Type;
				Criteria	: in Expression_Criteria_Type ) is
		use Expressions_Parse;
	
		Parser: Bool_Parser := (
				User	=> User,
				Descriptor	=> Criteria.Descriptor,
				Index		=> 0 );
		Exp : Expression_Access;
		Ret_Value : Boolean := False;
	begin
		Parse(Parser, Exp); 
		IsTrue(Exp.all, Parser, Ret_Value); 

		if not Ret_Value then
			raise ACCESS_DENIED with "Reason: " &
			To_String( Criteria.Descriptor );
		end if;
	end Require;
	
	
	function Get_Name( Criteria: in Expression_Criteria_Type ) return String is
		-- return a String representing the criteria
		-- it's the same string that will be used by the methods:
		--      Register( Name, Factory )
		--      Create_Criteria( Name, Patern ) return Criteria_Interface'Class;
	begin
		return ("EXPRESSIONS"); 
	end Get_Name;


	function Describe( Criteria: in Expression_Criteria_Type ) return String is
		-- return a string describing the current criteria
	begin
		return To_String( Criteria.Descriptor );
	end Describe;



begin
	KOW_Sec.Criteria_Registry.Register( Create_Roles_Criteria'Access );
	KOW_Sec.Criteria_Registry.Register( Create_Group_Criteria'Access );
	KOW_Sec.Criteria_Registry.Register( Create_User_Criteria'Access );
	KOW_Sec.Criteria_Registry.Register( Create_Expression_Criteria'Access );

end KOW_Sec.Authorization_Criterias;
