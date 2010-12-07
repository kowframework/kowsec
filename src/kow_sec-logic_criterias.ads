------------------------------------------------------------------------------
--                                                                          --
--                          Ada Works :: Security                           --
--                                                                          --
--                                Ada Works                                 --
--                                                                          --
--                                 S p e c                                  --
--                                                                          --
--               Copyright (C) 2007-2009, Ada Works Project                 --
--                                                                          --
--                                                                          --
-- KOWSec; free software; you can redistribute it  and/or modify it under    --
-- terms of the  GNU General Public License as published  by the Free Soft- --
-- ware  Foundation;  either version 2,  or (at your option) any later ver- --
-- sion. KOWSec; distributed in the hope that it will be useful, but WITH- --
-- OUT ANY WARRANTY;  without even the  implied warranty of MERCHANTABILITY --
-- or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License --
-- for  more details.  You should have  received  a copy of the GNU General --
-- Public License distributed with KOWSec; see file COPYING.  If not, write  --
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
-- This is the KOW_Sec.Criteria_Util package                                 --
------------------------------------------------------------------------------


package KOW_Sec.Logic_Criterias is

	type Logic_Criteria_Type is abstract new kOW_Sec.Criteria_Interface with record
		-- this represents the interface we will use for parsing our criterias..
		Descriptor : KOW_Sec.Criteria_Descriptor;
		-- the descriptor has got to be intialized by the element
	end record;

	overriding
	procedure Require(
				User	: in out User_Type;
				Criteria: in     Logic_Criteria_Type
			);


	procedure Require_Specific(
					Criteria	: in out Logic_Criteria_Type;
					Descriptor	: in     Criteria_Descriptor;
					Return_Value	:    out Boolean
				) is abstract;
		-- check if the specific criteria matches

	procedure Initialize(
				Criteria	: in out Logic_Criteria_Type;
				User		: in out User_Type
			) is null;
	-- optional procedure, when initializing the require procedure

	procedure Finalize(
				Criteria	: in out Logic_Criteria_Type
			) is null;
	-- optional procedure, called at the end of require procedure
	-- usefull for cleaning up memory and such


	generic
		type Criteria_Type is new Logic_Criteria_Type with private;
	function Generic_Logic_Criteria_Factory( Descriptor : in Criteria_Descriptor ) return Criteria_interface'Class;

private
	type Parser_Type is record
		User	: User_Type;  
		Descriptor	: Criteria_Descriptor_Type; -- the full expression.
		Index		: Integer := 1; -- the index to start the parse from.	
	end record;

	type Expression is abstract tagged null record;
	procedure Is_True(	Exp		: Expression;
				Parser		: in out Parser_Type;
				Ret_Value 	: out Boolean)  is abstract; 	

	type Expression_Access is access all Expression'Class;

	
	type Terminal is new Expression with
	record
		Word : Criteria_Descriptor_Type;
	end record;
	procedure Is_True(	Term		: Terminal;
				Parser		: in out Parser_Type;
				Ret_Value	: out Boolean);
	-- Verifies if the terminal's word is true according to generic
	-- 'evaluate' procedure and set the boolean value in Ret_Value.
	
	
	type Not_Operator is new Expression with
	record
		Exp : Expression_Access;
		-- Not_Operator is a unary operator. Its operator is 
		-- 'Not' ('!') and its expression is 'Exp'.
		-- Example: !designer
	end record;
	procedure Is_True(	Op	 	: Not_Operator;
				Parser		: in out Parser_Type;
				Ret_Value	: out Boolean);
	-- Ret_Value indicates if a condition !Exp is true or false.

	
	
	type Binary_Operator is abstract new Expression with 
	record
		Exp1 : Expression_Access;
		Exp2 : Expression_Access;
	end record;
		
	
	type Or_Operator is new Binary_Operator with null record;
	-- Or_Operator is a binary operator. Its operator is 
	-- 'Or' ('|'), its left expression is 'Exp1' and its
	-- right expression is 'Exp2'.
	-- Example: dev|admin
	procedure Is_True(	Op		: Or_Operator;
				Parser		: in out Parser_Type;
				Ret_Value	: out Boolean);
	-- Ret_Value indicates if a condition Exp1|Exp2 is true or false.
	
	
	type And_Operator is new Binary_Operator with null record;
	-- And_Operator is a binary operator. Its operator is 
	-- 'And' ('&'), its left expression is 'Exp1' and its
	-- right expression is 'Exp2'.
	-- Example: dev&admin

	procedure Is_True(	Op		: And_Operator;
				Parser		: in out Parser_Type;
				Ret_Value	: out Boolean);
	-- Ret_Value indicates if a condition Exp1&Exp2 is true or false.
 
	procedure Match_Not_Or_Block_Or_Terminal(	Parser	: in out Parser_Type;
							Exp	: out Expression_Access);
	-- Searches for a Not_Operator or a 
	-- Block (Expression within a pair of brackets) or a
	-- Terminal (Expression with one word).
	
	procedure Match_Block_Or_Terminal(	Parser	: in out Parser_Type;
						Exp 	: out Expression_Access);
	-- Searches for Block (Expression within a pair of brackets) or a
	-- Terminal (Expression with one word).
	

	procedure Match_Terminal(	Parser	: in out Parser_Type;
					Exp	: out Expression_Access);
	-- Searches for a Terminal (Expression with one word).
	
	procedure Match_Block(	Parser	: in out Parser_Type;
				Exp	: out Expression_Access);
	-- Searches for a Block (Expression within a pair of brackets).
	
	procedure Parse(	Parser	: in out Parser_Type;
				Exp	: out Expression_Access);
	--  Reads the whole Parser.Descriptor identifying Not_Operators,
	--  And_Operators and Or_Operators. 
	--  Exp is the expression with  all operators and expression.
	--  To verify if Exp is true, call Is_True(Exp.all, Parser, Ret_Value)
	--  and Ret_Value will contain the answer.




	function Is_Valid_Character ( Char : Character ) return Boolean;
	-- Returns a Boolean that defines if a character
	-- can be used in Criteria_Descriptor_Type or not.

end KOW_Sec.Logic_Criterias;

