------------------------------------------------------------------------------
--                                                                          --
--                          Ada Works :: Security                           --
--                                                                          --
--                                Ada Works                                 --
--                                                                          --
--                                 B o d y                                  --
--                                                                          --
--        Copyright (C) 2007-2008, Ydea Desenv. de Softwares Ltda           --
--                                                                          --
--                                                                          --
-- AwSec; free software; you can redistribute it  and/or modify it under    --
-- terms of the  GNU General Public License as published  by the Free Soft- --
-- ware  Foundation;  either version 2,  or (at your option) any later ver- --
-- sion. AwSec; distributed in the hope that it will be useful, but WITH- --
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

------------------------------------------------------------------------------
-- This is the Aw_Sec.Authorization_Criterias package                       --
------------------------------------------------------------------------------


with Aw_Sec.Criterias_Util;	use Aw_Sec.Criterias_Util;


package body Aw_Sec.Authorization_Criterias is

	---------------------
	-- GROUPS CRITERIA --
	---------------------
	
	procedure Eval_Groups(	Descriptor	: in Criteria_Descriptor;
				User_Object	: in out User_Access;
				Ret_Code	: out Boolean ) is
	begin
		if To_String( Descriptor ) = User_Object.Username then
			Ret_Code := True;
		else
			Ret_Code := False;
		end if;
	end Eval_Groups;

	package Groups_Parse is new Bool_Parse( Pattern => Criteria_Descriptor,
						Evaluate => Eval_Groups); 
	
	function Create_Groups_Criteria( Descriptor: in Criteria_Descriptor )
		return Criteria'Class is
		-- create a GROUPS criteria to be matched
		-- based on the given Descriptor.
		My_Criteria: Groups_Criteria := (Descriptor => Descriptor );
	begin		
		return My_Criteria;
	end Create_Groups_Criteria;


	procedure Require( User_Object: in out User'Class; Criteria_Object: in Groups_Criteria ) is
		use Groups_Parse;

		Parser: Bool_Parser := (	User_Object	=> User_object'Unchecked_Access,
						Descriptor	=> Criteria_Object.Descriptor,
						Index		=> 0 );
		Exp : Expression_Access;
		Ret_Value : Boolean := False;
	begin
		Parse(Parser, Exp); 
		IsTrue(Exp.all, Parser, Ret_Value); 

		if not Ret_Value then
			raise ACCESS_DENIED with "Reason: " & To_String( Criteria_Object.Descriptor );
		end if;
	end Require;
	

	function Get_Type( Criteria_Object: in Groups_Criteria ) return String is
		-- return a String representing the criteria
		-- it's the same string that will be used by the methods:
		--      Register( Name, Factory )
		--      Create_Criteria( Name, Patern ) return Criteria'Class;
	begin
		return ("CRITERIA_GROUPS"); 
	end Get_Type;


	function Describe( Criteria_Object: in Groups_Criteria ) return String is
		-- return a string describing the current criteria
	begin
		return To_String( Criteria_Object.Descriptor );
	end Describe;

	--------------------
	-- USERS CRITERIA --
	--------------------
	
	procedure Eval_Users(	Descriptor	: in Criteria_Descriptor;
				User_Object	: in out User_Access;
				Ret_Code	: out Boolean ) is
	begin
		if To_String( Descriptor ) = User_Object. Username then
			Ret_Code := True;
		else
			Ret_Code := False;
		end if;
	end Eval_Users;

	package Users_Parse is new Bool_Parse(	Pattern => Criteria_Descriptor,
						Evaluate => Eval_Users); 
	
	function Create_Users_Criteria( Descriptor: in Criteria_Descriptor )
		return Criteria'Class is
		-- create a Users_Criteria to be matched
		-- based on the given Descriptor.
		
		My_Criteria: Users_Criteria := (Descriptor => Descriptor );
	begin
		return My_Criteria;
	end Create_Users_Criteria;


	procedure Require( User_Object: in out User'Class; Criteria_Object: in Users_Criteria ) is
		use Users_Parse;
		
		Parser: Bool_Parser := (
				User_Object	=> User_Object'Unchecked_Access,
				Descriptor	=> Criteria_Object.Descriptor,
				Index		=> 0 );
		Exp : Expression_Access;
		Ret_Value : Boolean := False;
	begin
		Parse(Parser, Exp); 
		IsTrue(Exp.all, Parser, Ret_Value); 

		if not Ret_Value then
			raise ACCESS_DENIED with "Reason: " & To_String( Criteria_Object.Descriptor );
		end if;
	end Require;
	
	
	function Get_Type( Criteria_Object: in Users_Criteria ) return String is
		-- return a String representing the criteria
		-- it's the same string that will be used by the methods:
		--      Register( Name, Factory )
		--      Create_Criteria( Name, Patern ) return Criteria'Class;
	begin
		return ("CRITERIA_USERS"); 
	end Get_Type;


	function Describe( Criteria_Object: in Users_Criteria ) return String is
		-- return a string describing the current criteria
	begin
		return To_String( Criteria_Object.Descriptor );
	end Describe;



	--------------------------
	-- EXPRESSIONS CRITERIA --
	--------------------------
	
	procedure Eval_Expressions(	Descriptor	: in Criteria_Descriptor;
					User_Object	: in out User_Access;
					Ret_Code	: out Boolean ) is
	begin
		if To_String( Descriptor ) =  User_Object.Username  then
			Ret_Code := True;
		else
			Ret_Code := False;
		end if;
	end Eval_Expressions;

	package Expressions_Parse is new Bool_Parse(	Pattern => Criteria_Descriptor,
							Evaluate => Eval_Expressions); 
	
	function Create_Expressions_Criteria( Descriptor: in Criteria_Descriptor )
		return Criteria'Class is
		-- create a Expressions_Criteria to be matched
		-- based on the given Descriptor.
		
		My_Criteria: Expressions_Criteria := (Descriptor => Descriptor );
	begin
		return My_Criteria;
	end Create_Expressions_Criteria;


	procedure Require( User_Object: in out User'Class; Criteria_Object: in Expressions_Criteria ) is
		use Expressions_Parse;
	
		Parser: Bool_Parser := (
				User_Object	=> User_Object'Unchecked_Access,
				Descriptor	=> Criteria_Object.Descriptor,
				Index		=> 0 );
		Exp : Expression_Access;
		Ret_Value : Boolean := False;
	begin
		Parse(Parser, Exp); 
		IsTrue(Exp.all, Parser, Ret_Value); 

		if not Ret_Value then
			raise ACCESS_DENIED with "Reason: " & To_String( Criteria_Object.Descriptor );
		end if;
	end Require;
	
	
	function Get_Type( Criteria_Object: in Expressions_Criteria ) return String is
		-- return a String representing the criteria
		-- it's the same string that will be used by the methods:
		--      Register( Name, Factory )
		--      Create_Criteria( Name, Patern ) return Criteria'Class;
	begin
		return ("CRITERIA_EXPRESSIONS"); 
	end Get_Type;


	function Describe( Criteria_Object: in Expressions_Criteria ) return String is
		-- return a string describing the current criteria
	begin
		return To_String( Criteria_Object.Descriptor );
	end Describe;



begin
	Aw_Sec.Criterias.Register( "GROUPS", Create_Groups_Criteria'Access );
	Aw_Sec.Criterias.Register( "USERS", Create_Users_Criteria'Access );
	Aw_Sec.Criterias.Register( "EXPRESSIONS", Create_Expressions_Criteria'Access );

end Aw_Sec.Authorization_Criterias;
