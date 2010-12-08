------------------------------------------------------------------------------
--                                                                          --
--                          KOW Framework Security                          --
--                                                                          --
--                              KOW Framework                               --
--                                                                          --
--                                 B o d y                                  --
--                                                                          --
--             Copyright (C) 2007-2009, KOW Framework Project               --
--                                                                          --
--                                                                          --
-- KOWSec is free software; you can redistribute it  and/or modify it under  --
-- terms of the  GNU General Public License as published  by the Free Soft- --
-- ware  Foundation;  either version 2,  or (at your option) any later ver- --
-- sion. KOWSec is distributed in the hope that it will be useful, but WITH- --
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


with Ada.Numerics.Discrete_Random;





package body KOW_Sec.Util is

	function Random_Password( Length : in Integer ) return String is
		-- generates a random password of length using the characters
		-- A-Z
		-- a-z
		-- 0-9



		type Valid_Character is (
					'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 
					'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 
					'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'
				);
		
		package Char_Random is new Ada.Numerics.Discrete_Random( Result_Subtype => Valid_Character );

		Generator : Char_Random.Generator;



		function To_Char( C : in Valid_Character ) return Character is
			Img : constant String := Valid_Character'Image( C );
		begin
			return Img( Img'First + 1 );
		end To_Char;

		function Rand_Char return Character is
		begin
			return To_Char( Char_Random.Random( Generator ) );
		end Rand_Char;


		Ret : String ( 1 .. Length );

	begin
		Char_Random.Reset( Generator );
		for idx in Ret'Range loop
			Ret( idx ) := Rand_Char;
		end loop;


		return Ret;
	end Random_Password;

end KOW_Sec.Util;
