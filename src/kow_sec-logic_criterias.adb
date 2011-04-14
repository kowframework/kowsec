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
with Ada.Characters.Handling; 		use Ada.Characters.Handling;
with Ada.Containers.Ordered_Maps;
with Ada.Tags;
with Ada.Text_IO;			use Ada.Text_IO;	

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
	procedure Add_Context(
				Criteria: in out Logic_Criteria_Type;
				Context	: in     Context_Type
			) is
	begin
		Criteria.Context_Count := Criteria.Context_Count + 1;
		Criteria.Contexts( Criteria.Context_Count ) := Context;
	end Add_Context;




	overriding
	procedure Is_Allowed(
				Criteria: in out Logic_Criteria_Type;
				User	: in     User_Type;
				Response:    out Boolean
			) is
		Exp		: Expression_Access;
		Is_Allowed	: Boolean := False;
	begin
		Exp := Parsers.Parse( Criteria.Descriptor );

		Initialize( Logic_Criteria_type'Class( Criteria ), User );
		Evaluate( Exp.all, Logic_Criteria_type'Class( Criteria ), Is_Allowed );

		Free( Exp );
		-- this will call free in chain for every child inside exp..

		Finalize( Logic_Criteria_type'Class( Criteria ) );

		Response := Is_Allowed;
	end Is_Allowed;


	overriding
	function Describe( Criteria : in Logic_Criteria_Type ) return String is
	begin
		return Get_Name( Logic_Criteria_type'Class( Criteria ) ) & " " & To_String( Criteria.Descriptor );
	end Describe;


	function Generic_Logic_Criteria_Factory( Descriptor : in Criteria_Descriptor ) return Criteria_Type'Class is
		C: Specific_Criteria_Type;
	begin
		C.Descriptor := Descriptor;
		return Criteria_Type'Class( C );
	end Generic_Logic_Criteria_Factory;


	function Get_Contexts( Criteria : in Logic_Criteria_Type ) return Context_Array is
	begin
		return Criteria.Contexts( 1 .. Criteria.Context_Count );
	end Get_Contexts;



-- private

	type Free_Access is access procedure( Acc : in out Expression_Access );

	function "<"( L, R : in Ada.Tags.Tag ) return Boolean is
		A : constant String := Ada.Tags.Expanded_Name( L );
		B : constant String := Ada.Tags.Expanded_Name( R );
	begin
		return A < B;
	end "<";


	package Free_Maps is new Ada.Containers.Ordered_Maps(
				Key_Type	=> Ada.Tags.Tag,
				Element_Type	=> Free_Access
			);
	
	My_Frees : Free_Maps.Map;

	procedure Free( Exp_Access : in out Expression_Access ) is
		-- this is used for cleaning the memory all over the place :)
		-- the memory_pools package will register it's instance in a internal registry
		-- that's used to select the proper free procedure. :)
	begin
		Free_Maps.Element( My_Frees, Exp_Access'Tag ).all( Exp_Access );
	end Free;

	package body Memory_Pools is
		function New_Object( Element : in Element_Type ) return Expression_Access is
			-- allocate initializing with the values in element
			Acc : Access_Type := new Element_type'( Element );
		begin
			return Expression_Access( Acc );
		end New_Object;


		procedure Free_Object( Element : in out Expression_Access ) is
			procedure My_Free is new Ada.Unchecked_Deallocation(
						Object	=> Element_Type,
						Name	=> Access_Type
					);
		begin
			My_Free( Access_Type( Element ) );
		end Free_Object;
	begin
		Free_Maps.Include(
				My_Frees,
				Element_Type'Tag,
				Free_Object'Unrestricted_Access
			);

	end Memory_Pools;



	----------------------------------
	-- The Criteria Expression Type --
	----------------------------------

	package Criteria_Expression_Pools is new Memory_Pools( Element_Type => Criteria_Expression_Type );

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
	
	package Not_Expression_Pools is new Memory_Pools( Element_Type => Not_Expression_Type );

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
	
	overriding
	procedure Finalize( Exp : in out Not_Expression_Type ) is
	begin
		Free( Exp.Exp );
	end Finalize;

	------------------------
	-- OR Expression Type --
	------------------------
	
	package Or_Expression_Pools is new Memory_Pools( Element_Type => Or_Expression_Type );

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

	overriding
	procedure Finalize( Exp : in out Or_Expression_Type ) is
	begin
		Free( Exp.Exp1 );
		Free( Exp.Exp2 );
	end Finalize;

	
	------------------------
	-- AND Expresion Type --
	------------------------
	
	package And_Expression_Pools is new Memory_Pools( Element_Type => And_Expression_Type );

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

	overriding
	procedure Finalize( Exp : in out And_Expression_Type ) is
	begin
		Free( Exp.Exp1 );
		Free( Exp.Exp2 );
	end Finalize;




	-------------------------
	-- The parsers Package --
	-------------------------
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
				Exp := Not_Expression_Pools.New_Object( (Expression_Type with Exp => Exp) ); 
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

				Exp := Criteria_Expression_Pools.New_Object( ( Expression_Type with Specific_Descriptor => Op_Buffer ) );
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
					-- or And_Operator.
					Match_Not_Or_Block_Or_Criteria( Parser, Exp1 );

				elsif Next_Char = '|' then
					-- The parse found a '|', so it will initialize
					-- a Or_Operator.
					
					Parser.Index := Parser.Index + 1;
					
					-- Searches for a Block or Terminal and initializes
					-- the right expression of the Or_Operator.
					Match_Not_Or_Block_Or_Criteria( Parser, Exp2 );
					
					Exp1 := Or_Expression_Pools.New_Object( ( Expression_Type with Exp1 => Exp1, Exp2 => Exp2 ) );

				elsif Next_Char = '&' then
					-- The parse found a '|', so it will initialize
					-- a Or_Operator.
					
					Parser.Index := Parser.Index + 1;
					
					-- Searches for a Block or Terminal and initializes
					-- the right expression of the Or_Operator.
					Match_Not_Or_Block_Or_Criteria( Parser, Exp2 );
					
					Exp1 := And_Expression_Pools.New_object( ( Expression_Type with Exp1 => Exp1, Exp2 => Exp2 ) );
				else
					raise INVALID_CRITERIA_DESCRIPTOR with To_String( Parser.Descriptor );  
				end if;
			end loop;

			return Exp1;
		end Parse;

	end Parsers;


end KOW_Sec.Logic_Criterias;

