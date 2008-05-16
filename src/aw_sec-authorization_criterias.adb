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


with APQ;	use APQ;

package body Aw_Sec.Authorization_Criterias is

	
	function Create_Criteria( Descriptor: in Criteria_Descriptor ) 
		return Criteria'Class is
		-- create a criteria, Users_Criteria by default,
		-- to be matched based on the given Descriptor.
  	begin
		return  Create_Users_Criteria( Descriptor );
	end Create_Criteria;
	
	function Create_Groups_Criteria( Descriptor: in Criteria_Descriptor )
		return Criteria'Class is
		-- create a GROUPS criteria to be matched
		-- based on the given Descriptor.
		
		Groups_Criteria : Auth_Criteria := (	To_Unbounded_String("GROUPS"),
						   	Descriptor );
	begin
		return Groups_Criteria;	
	end Create_Groups_Criteria;
	
	function Create_Users_Criteria( Descriptor: in Criteria_Descriptor )
		return Criteria'Class is
		-- create a USERS criteria to be matched
		-- based on the given Descriptor.
		
		Users_Criteria : Auth_Criteria := (	To_Unbounded_String("USERS"),
						  	Descriptor );
	begin
		return Users_Criteria;	
		
	end Create_Users_Criteria;
	
	function Create_Expression_Criteria( Descriptor: in Criteria_Descriptor )
		return Criteria'Class is
		-- create a EXPRESSION criteria to be matched
		-- based on the given Descriptor.
		
		Ex_Criteria : Auth_Criteria := (	To_Unbounded_String("EXPRESSION"),
							Descriptor );
	begin
		return Ex_Criteria;	
	end Create_Expression_Criteria;
	

	function Get_Type( Criteria_Object: in Auth_Criteria ) return String is
		-- return a String representing the criteria
		-- it's the same string that will be used by the methods:
		--      Register( Name, Factory )
		--      Create_Criteria( Name, Patern ) return Criteria'Class;
	begin
		return ("CRITERIA_" & To_String( Criteria_Object.Criteria_Name ) ); 
	end Get_Type;


	function Describe( Criteria_Object: in Auth_Criteria ) return String is
		-- return a string describing the current criteria
	begin
		return To_String( Criteria_Object.Criteria_Descriptor );
	end Describe;

	procedure Require(	User_Object     : in out User'Class;
				Criteria_Object : in Auth_Criteria ) is
		-- matches the user against some criteria.
		-- raise ACCESS_DENIED if the user fails this criteria.
	begin
		null;		
	end Require;




	function isTrue( Term : Terminal ) return Boolean is
	begin
		return False;	
	end isTrue;


	function isTrue( Op : NotOperator ) return Boolean is
	begin
		return not isTrue(Op.Exp.all); 
	end isTrue;


	function isTrue( Op : OrOperator ) return Boolean is
	begin
		return isTrue(Op.Exp1.all) and then isTrue(Op.Exp2.all);	
	end isTrue;

	function isTrue( Op : AndOperator) return Boolean is
	begin
		return isTrue(Op.Exp1.all) or else  isTrue(Op.Exp2.all);	
	end isTrue;


	function Parse(Descriptor : Criteria_Descriptor) return Boolean is

		OpBuffer	: String := "";
		Term1		: Terminal;  
		Exp		: Expression_Access; 	
		i 		: Integer := 0;
		Next_Character 	: Character; 
	begin
		while i < Lenght(Descriptor) then
		loop
			Next_Character = Descriptor[i];
			
			if Expression = Null
				Expression := Match_Terminal;

			else if Next_Char = '|'
				i++;
				Term2 := Match_Terminal;
				Expression := new OrOperator'(Expression, Term2);

			else if Next_Char = '&'
				i++;
				Term2 := Match_Terminal;
				Expression := new AndOperator'(Expression, Term2);
		
			else
				raise Exception...
			end if;
		end loop;
	
		return Expression.isTrue;

	end Parse;
	




begin
	Aw_Sec.Criterias.Register( "GROUPS", Create_Groups_Criteria'Access );
	Aw_Sec.Criterias.Register( "USERS", Create_Users_Criteria'Access );
	Aw_Sec.Criterias.Register( "EXPRESSION", Create_Expression_Criteria'Access );

end Aw_Sec.Authorization_Criterias;
