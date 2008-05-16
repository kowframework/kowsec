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
-- This is the Aw_Sec.Authorization_Criterias package                       --
------------------------------------------------------------------------------


with APQ;	use APQ;

package Aw_Sec.Authorization_Criterias is


	type Auth_Criteria is new Aw_Sec.Criteria with private;


	function Create_Criteria( Descriptor: in Criteria_Descriptor )
		return Criteria'Class;
	-- create a criteria to be matched based on the given Descriptor.
 

	function Create_Groups_Criteria( Descriptor: in Criteria_Descriptor )
		return Criteria'Class;
	-- create a GROUPS criteria to be matched based on the given Descriptor.
	
	function Create_Users_Criteria( Descriptor: in Criteria_Descriptor ) 
		return Criteria'Class;
	-- create a USERS criteria to be matched based on the given Descriptor.
	
	function Create_Expression_Criteria( Descriptor: in Criteria_Descriptor ) 
		return Criteria'Class;
	-- create a EXPRESSION criteria to be matched based on the given Descriptor.


	function Get_Type( Criteria_Object: in Auth_Criteria ) return String;
	-- return a String representing the criteria
	-- it's the same string that will be used by the methods:
	--      Register( Name, Factory )
	--      Create_Criteria( Name, Patern ) return Criteria'Class;

	function Describe( Criteria_Object: in Auth_Criteria ) return String;
	-- return a string describing the current criteria


	procedure Require(	User_Object     : in out User'Class;
				Criteria_Object : in Auth_Criteria );
	-- matches the user against some criteria.
	-- raise ACCESS_DENIED if the user fails this criteria.



	type Expression is abstract tagged null record;
	function isTrue( Exp : Expression ) return Boolean is abstract; 	

	type Expression_Access is access all Expression'Class;

	type Terminal is new Expression with
	record
		Word : Unbounded_String;
	end record;
	function isTrue( Term : Terminal ) return Boolean;

	type NotOperator is new Expression with
	record
		Exp : Expression_Access;
	end record;
	function isTrue( Op : NotOperator ) return Boolean;


	type BinaryOperator is abstract new Expression with 
	record
		Exp1 : Expression_Access;
		Exp2 : Expression_Access;
	end record;
		
	type OrOperator is new BinaryOperator with null record;
	function isTrue( Op : OrOperator ) return Boolean;

	type AndOperator is new BinaryOperator with null record;
	function isTrue( Op : AndOperator) return Boolean;







private

	type Auth_Criteria is new Aw_Sec.Criteria with 
	record
		Criteria_Name : Aw_Sec.Criteria_Name;
		Criteria_Descriptor : Aw_Sec.Criteria_Descriptor;
	end record;

end Aw_Sec.Authorization_Criterias;
