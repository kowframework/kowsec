with Ada.Text_IO;	use Ada.Text_IO;

package body Aw_Sec is
	function Is_Anonymous( U: in User ) return Boolean is
	begin
		return U.Is_Anonymous;
	end Is_Anonymous;



	procedure Adjust( U : in out User ) is
	begin
		U.Is_Anonymous := False;
	end Adjust;


begin
	Put_Line("bu!");
end Aw_Sec;
