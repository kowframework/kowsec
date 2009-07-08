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

package body KOW_Sec.Criterias_Util is


	function Is_Valid_Character ( Char : Character ) 
		return Boolean is
		-- Returns a Boolean that defines if a character
		-- can be used in Pattern or not.
	begin
		if Is_Alphanumeric( Char )
			or else  Char = '_'
			or else	Char = '.'
			or else Char = '-' then
			
			return True;
		else
			return False;
		end if;
	end Is_Valid_Character;



	-------------------
	-- BOOLEAN PARSE --
	-------------------
	
	package body Bool_Parse is 

		procedure isTrue(	Term		: Terminal; 
					Parser		: in out Bool_Parser;
					Ret_Value	: out Boolean ) is 	
		-- Verifies if the terminal's word is true according to generic
		-- 'evaluate' procedure and set the boolean value in Ret_Value.
		begin 
			if Length( Term.Word ) = 0 then
				raise INVALID_CRITERIA_DESCRIPTOR with 
					"Terminal has length 0. Oops.";
			end if;
		
			-- calling the generic procedure
			Evaluate( Term.Word, Parser.User_Object, Ret_Value );
		end isTrue;


		procedure isTrue(	Op		: Not_Operator;
					Parser		: in out Bool_Parser;
					Ret_Value	: out Boolean ) is
			Value1 : Boolean;
		-- Ret_Value indicates if a condition !Exp is true or false.
		begin
			isTrue( Op.Exp.all, Parser, Value1 );
			Ret_Value := not Value1;
		end isTrue;


		procedure isTrue(	Op		: Or_Operator;
					Parser		: in out Bool_Parser;
					Ret_Value	: out Boolean) is
			Value1, Value2 : Boolean;
		-- Ret_Value indicates if a condition Exp1|Exp2 is true or false.
		begin
			isTrue( Op.Exp1.all, Parser, Value1 );
			isTrue( Op.Exp2.all, Parser, Value2 );	
			Ret_Value := Value1 or else Value2;
		end isTrue;

		procedure isTrue(	Op : And_Operator;
					Parser : in out Bool_Parser;
					Ret_Value : out Boolean) is
			Value1, Value2 : Boolean;
		-- Ret_Value indicates if a condition Exp1&Exp2 is true or false.
		begin
			isTrue( Op.Exp1.all, Parser, Value1 );
			if Value1 = False then
				Ret_Value := False;
			else			
				isTrue( Op.Exp2.all, Parser, Value2 );	
				Ret_Value := Value1 and then  Value2;
			end if;
		end isTrue;


		procedure Match_Not_Or_Block_Or_Terminal(	Parser : in out Bool_Parser;
								Exp : out Expression_Access) is
			
		-- Searches for a Not_Operator or a 
		-- Block (Expression within a pair of brackets) or a
		-- Terminal (Expression with one word).
			
			Next_Char : Character := Element(Parser.Descriptor, Parser.Index); 
		
		begin
			if Next_Char = '!' then
				-- Matches a Not_Operator.	
				Parser.Index := Parser.Index + 1;
				Match_Block_Or_Terminal(Parser, Exp);
				Exp := new Not_Operator'(Expression with Exp => Exp); 
			else
				-- Searches for a Block or Terminal.
				Match_Block_Or_Terminal(Parser, Exp);
			end if;
		end Match_Not_Or_Block_Or_Terminal;


		procedure Match_Block_Or_Terminal(	Parser : in out Bool_Parser;
							Exp : out Expression_Access) is
		-- Searches for Block (Expression within a pair of brackets) or a
		-- Terminal (Expression with one word).
		begin
			Match_Block( Parser, Exp );
		
			if Exp = Null then
				-- Didn't match a block. Trying to match a terminal.
				Match_Terminal (Parser, Exp);
			end if;

			if Exp = Null then
				raise INVALID_CRITERIA_DESCRIPTOR with
					"Block or terminal expected in at: " & 
					Integer'Image( Parser.Index );
			end if;
		end Match_Block_Or_Terminal;


		procedure Match_Terminal(	Parser : in out Bool_Parser;
						Exp : out Expression_Access) is
		-- Searches for a Terminal (Expression with one word).
	
			Next_Char : Character := Element( Parser.Descriptor, Parser.Index );
			Op_Buffer : Pattern := To_Unbounded_String("") ;
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

				Exp := new Terminal'( Word => Op_Buffer );
			else
				Exp := null;
			end if;

		end Match_Terminal;


		procedure Match_Block(	Parser : in out Bool_Parser;
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
						declare
							Desc : Pattern := To_Unbounded_String( 
								Slice(Parser.Descriptor, Begin_Index + 1, Parser.Index-1 ) );
							New_Parser : Bool_Parser := (	User_object	=> Parser.User_Object,
											Descriptor	=> Desc,
											Index 		=> 0 ); 
						begin	
							-- call recursively the parse to the expression within of
							-- the brackets. 
							Parse( New_Parser, Exp );	
						
							Parser.Index := Parser.Index + 1;
						end;
					else
						raise INVALID_CRITERIA_DESCRIPTOR with
							"Unmatched '(' at " & Integer'Image(Parser.Index);		
					end if;
				end;
			else
				Exp := null;
			end if;
		end Match_Block;
		

		procedure Parse(Parser : in out Bool_Parser; Exp : out Expression_Access) is
		--  Reads the whole Parser.Descriptor identifying Not_Operators,
		--  And_Operators and Or_Operators. 
		--  Exp is the expression with  all operators and expression.
			
			OpBuffer	: String := "";
			Term1		: Terminal;  
			Term2		: Expression_Access;		
			Next_Char 	: Character;
		begin
			
			Parser.Index := 1;

			while Parser.Index <= Length( Parser.Descriptor ) 
			loop
				Next_Char := Element( Parser.Descriptor, Parser.Index );
			
				if Exp = Null then
					-- Initialize the Exp with a Not_Operator and/or
					-- the left expression of the Or_Operator
					-- or And_Opertator.
					Match_Not_Or_Block_Or_Terminal( Parser, Exp );

				elsif Next_Char = '|' then
					-- The parse found a '|', so it will initialize
					-- a Or_Operator.
					
					Parser.Index := Parser.Index + 1;
					
					-- Searches for a Block or Terminal and initializes
					-- the right expression of the Or_Operator.
					Match_Not_Or_Block_Or_Terminal( Parser, Term2 );
					
					Exp := new Or_Operator'(Exp, Term2);

				elsif Next_Char = '&' then
					-- The parse found a '|', so it will initialize
					-- a Or_Operator.
					
					Parser.Index := Parser.Index + 1;
					
					-- Searches for a Block or Terminal and initializes
					-- the right expression of the Or_Operator.
					Match_Not_Or_Block_Or_Terminal( Parser, Term2 );
					
					Exp := new And_Operator'( Exp, Term2 );
				else
					raise INVALID_CRITERIA_DESCRIPTOR with To_String( Parser.Descriptor );  
				end if;
			end loop;
		end Parse;

	end Bool_Parse;

end KOW_Sec.Criterias_Util;
