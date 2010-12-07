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
		-- A logic criteria is a criteria that allow the user to write Logic expressions using
		-- the operators:
		-- 	&	=> and
		-- 	|	=> or
		-- and grouping with ( and )
		--
		-- such as
		--
		-- a_group&(other_group|another_group)
		--
		-- This will alow when
		-- 	a_group&other_group
		-- or when
		-- 	a_group&another_group
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
					Is_Allowed	:    out Boolean
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


	-------------------------
	-- The Expression Type --
	-------------------------

	type Expression_Type is abstract tagged null record;
	procedure Evaluate(
			Exp		: in     Expression_Type;
			Criteria	: in out Logic_Criteria_Type'Class;
			Is_Allowed 	:    out Boolean
		)  is abstract;

	type Expression_Access is access all Expression'Class;

	
	----------------------------------
	-- The Criteria Expression Type --
	----------------------------------

	type Criteria_Expression_Type is new Expression_Type with record
		-- the final expression represents a direct call to a criteria's require_specific method
		Specific_Descriptor : Criteria_Descriptor_Type;
	end record;

	procedure Evaluate(
			Exp		: in     Criteria_Expression_Type;
			Criteria	: in out Logic_Criteria_Type
			Is_Allowed	:    out Boolean
		);
	-- Verifies if the terminal's word is true according to generic
	-- 'Evaluateuate' procedure and set the boolean value in Is_Allowed.
	

	-------------------------
	-- Not Expression Type --
	-------------------------
	
	type Not_Expression_Type is new Expression_Type with record
		-- Not_Operator is a unary operator. Its operator is 
		-- 'Not' ('!') and its expression is 'Exp'.
		-- Example: !designer

		Exp : Expression_Access;
	end record;

	procedure Evaluate(
				Exp	 	: in     Not_Expression_Type;
				Criteria	: in out Logic_Criteria_Type'Class;
				Is_Allowed	:    out Boolean
			);
	-- Is_Allowed indicates if a condition !Exp is true or false.

	

	------------------------
	-- OR Expression Type --
	------------------------
	
	type Or_Expression_Type is new Expression_Type with record
		-- Or_Operator is a binary operator. Its operator is 
		-- 'Or' ('|'), its left expression is 'Exp1' and its
		-- right expression is 'Exp2'.
		-- Example: dev|admin

		Exp1, Exp2 : Expression_Access;
	end record;

	procedure Evaluate(
				Exp		: in     Or_Expression_Type;
				Criteria	: in out Logic_Criteria_Type'Class;
				Is_Allowed	:        out Boolean
			);
	
	------------------------
	-- AND Expresion Type --
	------------------------
	
	type And_Expression_Type is new Expression_Type with record 
		-- And_Operator is a binary operator. Its operator is 
		-- 'And' ('&'), its left expression is 'Exp1' and then its
		-- right expression is 'Exp2'.
		-- Example: dev&admin

		Exp1, Exp2 : Expression_Access;
	end record;

	procedure Evaluate(	
				Exp		: in     And_Expression_Type;
				Criteria	: in out Logic_Criteria_Type'Class;
				Is_Allowed	: out    Boolean
			);
	-- Is_Allowed indicates if a condition Exp1&Exp2 is true or false.
 


 	package Parsers is


		function Is_Valid_Character ( Char : Character ) return Boolean;
		-- Returns a Boolean that defines if a character
		-- can be used in a call to Require_Specific in the Criteria_Descriptor or not.

		---------------------
		-- The Parser Type --
		---------------------
	
		type Parser_Type is record
			-- this type is so it's a lot easier for us to control the parameters
			-- it's never used directly by the final user

			Descriptor	: Criteria_Descriptor_Type; -- the full expression.
			Index		: Integer := 1; -- the index to start the parse from.	
		end record;


		procedure Match_Not_Or_Block_Or_Criteria(
					Parser	: in out Parser_Type;
					Exp	:    out Expression_Access
				);
		-- Searches for a Not_Operator or a 
		-- Block (Expression within a pair of brackets) or a
		-- Terminal (Expression with one word).
	
		procedure Match_Block_Or_Criteria(
					Parser	: in out Parser_Type;
					Exp 	:    out Expression_Access
				);
		-- Searches for Block (Expression within a pair of brackets) or a
		-- Terminal (Expression with one word).
	

		procedure Match_Criteria(
					Parser	: in out Parser_Type;
					Exp	:    out Expression_Access
				);
		-- Searches for a Terminal (Expression with one word).
	
		procedure Match_Block(
					Parser	: in out Parser_Type;
					Exp	:    out Expression_Access
				);
		-- Searches for a Block (Expression within a pair of brackets).
	
		function Parse( Descriptor : in Criteria_Descriptor_Type ) return Expression_Access;
		-- parse the descriptor returning an expression Evaluateuator


	end Parsers;


end KOW_Sec.Logic_Criterias;
