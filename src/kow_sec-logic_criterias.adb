------------------------------------------------------------------------------
--                                                                          --
--                          Ada Works :: Security                           --
--                                                                          --
--                                Ada Works                                 --
--                                                                          --
--                                 B o d y                                  --
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

with Ada.Text_IO;		use Ada.Text_IO;	
with Ada.Characters.Handling; 	use Ada.Characters.Handling;

package body KOW_Sec.Logic_Criterias is



	----------------------
	-- Helper Functions --
	----------------------

	function Is_Valid_Character ( Char : Character ) return Boolean is
		-- Returns a Boolean that defines if a character
		-- can be used in a call to Require_Specific in the Criteria_Descriptor or not.
	begin
		if Is_Alphanumeric( Char )
			or else  Char = '_'
			or else	Char = '.'
			or else Char = '-'
			or else Char = ':' then
			
			return True;
		else
			return False;
		end if;
	end Is_Valid_Character;




	-----------------------------
	-- The Logic Criteria Type --
	-----------------------------



	overriding
	procedure Require(
				Criteria: in out Logic_Criteria_Type;
				User	: in     User_Type
			) is
		Exp		: Expression_Access;
		Is_Allowed	: Boolean := False;
	begin
		Exp := Parsers.Parse( Criteria.Descriptor );

		Initialize( Logic_Criteria_type'Class( Criteria ), User );
		Evaluate( Exp.all, Logic_Criteria_type'Class( Criteria ), Is_Allowed );

		if not Is_Allowed then
			declare
				Description : constant String := Describe( Logic_Criteria_type'Class( Criteria ) );
			begin
				Finalize( Logic_Criteria_type'Class( Criteria ) );
				raise ACCESS_DENIED with Description;
			end;
		else
			Finalize( Logic_Criteria_type'Class( Criteria ) );
		end if;

	end Require;




	function Generic_Logic_Criteria_Factory( Descriptor : in Criteria_Descriptor ) return Criteria_interface'Class is
		C: Criteria_Type;
	begin
		C.Descriptor := Descriptor;
		return Criteria_interface'Class( C );
	end Generic_Logic_Criteria_Factory;




-- private





	----------------------------------
	-- The Criteria Expression Type --
	----------------------------------

	overriding
	procedure Evaluate(
			Exp		: in     Criteria_Expression_Type;
			Criteria	: in out Logic_Criteria_Type'Class;
			Is_Allowed	:    out Boolean
		) is
		-- Verifies if the terminal's word is true according to generic
		-- 'Evaluateuate' procedure and set the boolean value in Is_Allowed.
	begin
		Require_Specific( Criteria, Exp.Specific_Descriptor, Is_Allowed );
	end Evaluate;

	-------------------------
	-- Not Expression Type --
	-------------------------
	
	overriding
	procedure Evaluate(
				Exp	 	: in     Not_Expression_Type;
				Criteria	: in out Logic_Criteria_Type'Class;
				Is_Allowed	:    out Boolean
			) is
		-- Is_Allowed indicates if a condition !Exp is true or false.
		Tmp: Boolean;
	begin
		Evaluate( Exp.Exp.all, Criteria, Tmp );
		Is_Allowed := not Tmp;
	end Evaluate;
	

	------------------------
	-- OR Expression Type --
	------------------------
	
	overriding
	procedure Evaluate(
				Exp		: in     Or_Expression_Type;
				Criteria	: in out Logic_Criteria_Type'Class;
				Is_Allowed	:        out Boolean
			) is
		Tmp: Boolean;
	begin
		Evaluate( Exp.Exp1.all, Criteria, Tmp );

		if not tmp then
			Evaluate( Exp.Exp2.all, Criteria, Tmp );
		end if;

		Is_Allowed := Tmp;
	end Evaluate;
	
	------------------------
	-- AND Expresion Type --
	------------------------
	
	overriding
	procedure Evaluate(	
				Exp		: in     And_Expression_Type;
				Criteria	: in out Logic_Criteria_Type'Class;
				Is_Allowed	: out    Boolean
			) is
		-- Is_Allowed indicates if a condition Exp1&Exp2 is true or false.
 		Tmp: Boolean;
	begin
		Evaluate( Exp.Exp1.All, Criteria, Tmp );
		if Tmp then
			Evaluate( Exp.Exp2.All, Criteria, Tmp );
		end if;
		Is_Allowed := Tmp;
	end Evaluate;





	package body Parsers is



		procedure Match_Not_Or_Block_Or_Criteria(	Parser : in out Parser_Type;
								Exp : out Expression_Access) is
			
		-- Searches for a Not_Operator or a 
		-- Block (Expression within a pair of brackets) or a
		-- Terminal (Expression with one word).
			
			Next_Char : Character := Element(Parser.Descriptor, Parser.Index); 
		
		begin
			if Next_Char = '!' then
				-- Matches a Not_Operator.	
				Parser.Index := Parser.Index + 1;
				Match_Block_Or_Criteria(Parser, Exp);
				Exp := new Not_Expression_Type'(Expression_Type with Exp => Exp); 
			else
				-- Searches for a Block or Terminal.
				Match_Block_Or_Criteria(Parser, Exp);
			end if;
		end Match_Not_Or_Block_Or_Criteria;


		procedure Match_Block_Or_Criteria(	Parser : in out Parser_Type;
							Exp : out Expression_Access) is
		-- Searches for Block (Expression within a pair of brackets) or a
		-- Terminal (Expression with one word).
		begin
			Match_Block( Parser, Exp );
		
			if Exp = Null then
				-- Didn't match a block. Trying to match a terminal.
				Match_Criteria (Parser, Exp);
			end if;

			if Exp = Null then
				raise INVALID_CRITERIA_DESCRIPTOR with
					"Block or terminal expected in at: " & 
					Integer'Image( Parser.Index );
			end if;
		end Match_Block_Or_Criteria;


		procedure Match_Criteria(	Parser : in out Parser_Type;
						Exp : out Expression_Access) is
		-- Searches for a Terminal (Expression with one word).

			Next_Char : Character := Element( Parser.Descriptor, Parser.Index );
			Op_Buffer : Criteria_Descriptor;
		begin
			if Is_Valid_Character( Next_Char ) then
				
				while Is_Valid_Character( Next_Char ) or else Next_Char = '='
				loop
					Op_Buffer := Op_Buffer & Next_Char;
					Parser.Index := Parser.Index + 1;
			
					exit when Length( Parser.Descriptor ) <= Parser.Index - 1;
					
					Next_Char := Element( Parser.Descriptor, Parser.Index );
					
					-- add all characters encloses in curly brackets
					if Next_Char = '{' then
						loop
							Op_Buffer := Op_Buffer & Next_Char;
							Parser.Index := Parser.Index + 1;
							
							exit when Next_Char = '}' or else
								Length( Parser.Descriptor ) <= Parser.Index - 1;
					
							Next_Char := Element( Parser.Descriptor, Parser.Index );
						end loop;
					
					exit when Length( Parser.Descriptor ) <= Parser.Index - 1;
					
					end if;
				end loop;

				Exp := new Criteria_Expression_Type'( Specific_Descriptor => Op_Buffer );
			else
				Exp := null;
			end if;

		end Match_Criteria;


		procedure Match_Block(	Parser : in out Parser_Type;
					Exp : out Expression_Access ) is
		-- Searches for a Block (Expression within a pair of brackets).
		
			Next_Char : Character := Element( Parser.Descriptor, Parser.Index );
		begin
			if Next_Char = '(' then
				declare
					Begin_Index : Integer := Parser.Index;
					Level : Integer := 1; -- bracket level
				begin
					while Parser.Index <= Length( Parser.Descriptor ) and then Level > 0
					loop
						Parser.Index := Parser.Index + 1;
						Next_Char := Element ( Parser.Descriptor, Parser.Index );

						if Next_Char = '(' then 
							Level := Level + 1; -- found a nested bracket.
						elsif Next_Char = ')' then
							-- found a closing bracket, so decrease a level. 
							Level := Level - 1; 
						end if;		
					end loop;
					
					if Level = 0 then
						-- all opening brackets have corresponding closing brackets.
						-- call recursively the parse to the expression within of
						-- the brackets. 
						Exp := Parse( To_Unbounded_String( Slice( Parser.Descriptor, Begin_Index + 1, Parser.Index-1 ) ) );
						Parser.Index := Parser.Index + 1;
					else
						raise INVALID_CRITERIA_DESCRIPTOR with
							"Unmatched '(' at " & Integer'Image(Parser.Index);		
					end if;
				end;
			else
				Exp := null;
			end if;
		end Match_Block;
		


		function Parse( Descriptor : in Criteria_Descriptor ) return Expression_Access is
		-- parse the descriptor returning an expression Evaluateuator
		--  Reads the whole Parser.Descriptor identifying Not_Operators,
		--  And_Operators and Or_Operators. 
		--  Exp is the expression with  all operators and expression.
			
			OpBuffer	: String := "";
			Exp1,Exp2	: Expression_Access;		
			Next_Char 	: Character;

			Parser		: Parser_Type := (
								Descriptor	=> Descriptor,
								Index		=> 1
							);
		begin
			
			while Parser.Index <= Length( Parser.Descriptor ) loop
				Next_Char := Element( Parser.Descriptor, Parser.Index );
			
				if Exp1 = Null then
					-- Initialize the Exp with a Not_Operator and/or
					-- the left expression of the Or_Operator
					-- or And_Opertator.
					Match_Not_Or_Block_Or_Criteria( Parser, Exp1 );

				elsif Next_Char = '|' then
					-- The parse found a '|', so it will initialize
					-- a Or_Operator.
					
					Parser.Index := Parser.Index + 1;
					
					-- Searches for a Block or Terminal and initializes
					-- the right expression of the Or_Operator.
					Match_Not_Or_Block_Or_Criteria( Parser, Exp2 );
					
					Exp1 := new Or_Expression_Type'( Exp1 => Exp1, Exp2 => Exp2 );

				elsif Next_Char = '&' then
					-- The parse found a '|', so it will initialize
					-- a Or_Operator.
					
					Parser.Index := Parser.Index + 1;
					
					-- Searches for a Block or Terminal and initializes
					-- the right expression of the Or_Operator.
					Match_Not_Or_Block_Or_Criteria( Parser, Exp2 );
					
					Exp1 := new And_Expression_Type'( Exp1 => Exp1, Exp2 => Exp2 );
				else
					raise INVALID_CRITERIA_DESCRIPTOR with To_String( Parser.Descriptor );  
				end if;
			end loop;

			return Exp1;
		end Parse;

	end Parsers;

end KOW_Sec.Logic_Criterias;

