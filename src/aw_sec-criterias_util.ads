------------------------------------------------------------------------------
--                                                                          --
--                          Ada Works :: Security                           --
--                                                                          --
--                                Ada Works                                 --
--                                                                          --
--                                 S p e c                                  --
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
-- This is the Aw_Sec.Criteria_Util package                                 --
------------------------------------------------------------------------------


package Aw_Sec.Criterias_Util is

	function Is_Valid_Character ( Char : Character ) 
		return Boolean;
	-- Returns a Boolean that defines if a character
	-- can be used in Pattern or not.



	generic
		type Pattern is new Unbounded_String;
		-- The descriptor type.	

		with procedure Evaluate (	Descriptor	: Pattern;
						User_Object	: in out User_Access;
						Ret_Value	: out Boolean);
		-- Procedure called to evaluate a Terminal. Ret_Value will define if
		-- the user 'User_Object' has access to the terminal 'Descriptor' or not. 

	package Bool_Parse is
		type Bool_Parser is record
			User_Object	: User_Access;  
			Descriptor	: Pattern; -- the full expression.
			Index		: Integer := 1; -- the index to start the parse from.	
		end record;

		type Expression is abstract tagged null record;
		procedure isTrue(	Exp		: Expression;
					Parser		: in out Bool_Parser;
					Ret_Value 	: out Boolean)  is abstract; 	

		type Expression_Access is access all Expression'Class;

		
		type Terminal is new Expression with
		record
			Word : Pattern;
		end record;
		procedure isTrue(	Term		: Terminal;
					Parser		: in out Bool_Parser;
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
		procedure isTrue(	Op	 	: Not_Operator;
					Parser		: in out Bool_Parser;
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
		procedure isTrue(	Op		: Or_Operator;
					Parser		: in out Bool_Parser;
					Ret_Value	: out Boolean);
		-- Ret_Value indicates if a condition Exp1|Exp2 is true or false.
		
		
		type And_Operator is new Binary_Operator with null record;
		-- And_Operator is a binary operator. Its operator is 
		-- 'And' ('&'), its left expression is 'Exp1' and its
		-- right expression is 'Exp2'.
		-- Example: dev&admin

		procedure isTrue(	Op		: And_Operator;
					Parser		: in out Bool_Parser;
					Ret_Value	: out Boolean);
		-- Ret_Value indicates if a condition Exp1&Exp2 is true or false.
	 
		procedure Match_Not_Or_Block_Or_Terminal(	Parser	: in out Bool_Parser;
								Exp	: out Expression_Access);
		-- Searches for a Not_Operator or a 
		-- Block (Expression within a pair of brackets) or a
		-- Terminal (Expression with one word).
		
		procedure Match_Block_Or_Terminal(	Parser	: in out Bool_Parser;
							Exp 	: out Expression_Access);
		-- Searches for Block (Expression within a pair of brackets) or a
		-- Terminal (Expression with one word).
		

		procedure Match_Terminal(	Parser	: in out Bool_Parser;
						Exp	: out Expression_Access);
		-- Searches for a Terminal (Expression with one word).
		
		procedure Match_Block(	Parser	: in out Bool_Parser;
					Exp	: out Expression_Access);
		-- Searches for a Block (Expression within a pair of brackets).
		
		procedure Parse(	Parser	: in out Bool_Parser;
					Exp	: out Expression_Access);
		--  Reads the whole Parser.Descriptor identifying Not_Operators,
		--  And_Operators and Or_Operators. 
		--  Exp is the expression with  all operators and expression.
		--  To verify if Exp is true, call IsTrue(Exp.all, Parser, Ret_Value)
		--  and Ret_Value will contain the answer.

	end Bool_Parse;


end Aw_Sec.Criterias_Util;

