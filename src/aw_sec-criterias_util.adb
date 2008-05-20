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
-- This is the Aw_Sec.Criteria_Util package                                 --
------------------------------------------------------------------------------

with Ada.Text_IO;		use Ada.Text_IO;	
with Ada.Characters.Handling; 	use Ada.Characters.Handling;

package body Aw_Sec.Criterias_Util is

	-------------------
	-- BOOLEAN PARSE --
	-------------------
	
	package body Bool_Parse is 

		procedure isTrue( Term : Terminal; Parser : in out Bool_Parser; Ret_Value : out Boolean ) is
		begin
			if Length( Term.Word ) = 0 then
				raise INVALID_CRITERIA_DESCRIPTOR with 
					"Terminal has length 0. Oops.";
			end if;
			
			Evaluate( Term.Word, Parser.User_Object, Ret_Value );
		end isTrue;


		procedure isTrue( Op : Not_Operator; Parser : in out Bool_Parser; Ret_Value : out Boolean ) is
			Value1 : Boolean;
		begin
			isTrue( Op.Exp.all, Parser, Value1 );
			Ret_Value := not Value1;
		end isTrue;


		procedure isTrue( Op : Or_Operator; Parser : in out Bool_Parser; Ret_Value : out Boolean) is
			Value1, Value2 : Boolean;
		begin
			isTrue( Op.Exp1.all, Parser, Value1 );
			isTrue( Op.Exp2.all, Parser, Value2 );	
			Ret_Value := Value1 or else Value2;
		end isTrue;

		procedure isTrue( Op : And_Operator; Parser : in out Bool_Parser; Ret_Value : out Boolean) is
			Value1, Value2 : Boolean;
		begin
			isTrue( Op.Exp1.all, Parser, Value1 );
			isTrue( Op.Exp2.all, Parser, Value2 );	
			Ret_Value := Value1 and then  Value2;
		end isTrue;


		procedure Match_Not_Or_Block_Or_Terminal(	Parser : in out Bool_Parser;
								Exp : out Expression_Access) is
			
			Next_Char : Character := Element(Parser.Descriptor, Parser.Index); 
			
		begin
			if Next_Char = '!' then
				Parser.Index := Parser.Index + 1;
				Match_Block_Or_Terminal(Parser, Exp);
				Exp := new Not_Operator'(Expression with Exp => Exp); 
			else
				Match_Block_Or_Terminal(Parser, Exp);
			end if;
		end Match_Not_Or_Block_Or_Terminal;


		procedure Match_Block_Or_Terminal(	Parser : in out Bool_Parser;
							Exp : out Expression_Access) is
		begin
			Match_Block( Parser, Exp );
		
			if Exp = Null then
				Match_Terminal (Parser, Exp);
			end if;

			if Exp = Null then
				raise INVALID_CRITERIA_DESCRIPTOR with
					"Block or terminal expected in at: " & Integer'Image( Parser.Index );
			end if;
		end Match_Block_Or_Terminal;


		procedure Match_Terminal(	Parser : in out Bool_Parser;
						Exp : out Expression_Access) is
		
			Next_Char : Character := Element( Parser.Descriptor, Parser.Index );
			Op_Buffer : Pattern := To_Unbounded_String("") ;
		begin

			if Is_Letter( Next_Char ) then
				while Is_Letter( Next_Char )
				loop
					Op_Buffer := Op_Buffer & Next_Char;
					Parser.Index := Parser.Index + 1;
				
					exit when Length( Parser.Descriptor ) <= Parser.Index - 1;
				
					Next_Char := Element( Parser.Descriptor, Parser.Index );
				end loop;

				Exp := new Terminal'( Word => Op_Buffer );
			else
				Exp := null;
			end if;

		end Match_Terminal;


		procedure Match_Block(	Parser : in out Bool_Parser;
					Exp : out Expression_Access) is

			Next_Char : Character := Element( Parser.Descriptor, Parser.Index );
		begin
			if Next_Char = '(' then
				declare
					Begin_Index : Integer := Parser.Index;
					Level : Integer := 1;
				begin
					while Parser.Index <= Length( Parser.Descriptor ) and then Level > 0
					loop
						Parser.Index := Parser.Index + 1;
						Next_Char := Element ( Parser.Descriptor, Parser.Index );

						if Next_Char = '(' then 
							Level := Level + 1;
						elsif Next_Char = ')' then
							Level := Level - 1;
						end if;		
					end loop;
					
					if Level = 0 then
						declare
							Desc : Pattern := To_Unbounded_String( 
								Slice(Parser.Descriptor, Begin_Index + 1, Parser.Index-1 ) );
							New_Parser : Bool_Parser := (	User_object => Parser.User_Object,
											Descriptor => Desc,
											Index => 0 ); 
						begin	
							Parse( New_Parser, Exp );	
						
							Parser.Index := Parser.Index + 1;
						end;
					else
						raise INVALID_CRITERIA_DESCRIPTOR with
							"Unmatched '(' at " & Integer'Image(Parser.Index);		
					end if;
				end;
			end if;
		end Match_Block;
		

		procedure Parse(Parser : in out Bool_Parser; Exp : out Expression_Access) is

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
					Match_Not_Or_Block_Or_Terminal( Parser, Exp );

				elsif Next_Char = '|' then
					Parser.Index := Parser.Index + 1;
					Match_Not_Or_Block_Or_Terminal( Parser, Term2 );
					Exp := new Or_Operator'(Exp, Term2);

				elsif Next_Char = '&' then
					Parser.Index := Parser.Index + 1;
					Match_Not_Or_Block_Or_Terminal( Parser, Term2 );
					Exp := new And_Operator'( Exp, Term2 );
				else
					raise INVALID_CRITERIA_DESCRIPTOR with "Descriptor is " & To_String( Parser.Descriptor );  
				end if;
			end loop;
		end Parse;

	end Bool_Parse;


end Aw_Sec.Criterias_Util;

