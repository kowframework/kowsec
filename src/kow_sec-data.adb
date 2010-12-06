




-- Data backend for KOW Sec --

-- this package works by storing and indexing private types


--------------
-- Ada 2005 --
--------------
with Ada.Containers.Vectors;
with Ada.Sequential_IO;


package body KOW_Sec.Data is

	package Element_IO is new Ada.Sequential_IO( Element_Type );

	function Storage_Path( Index : in Index_Type ) return String is
	begin
		return Storage_Root / To_String( Index );
	end Storage_Path;


	procedure Store(
				Index	: in Index_Type;
				Element	: in Element_Type
			) is
	begin
		-- TODO :: store
		null;
	end Store;


	function Get_First(
				Index	: in Index_Type;
				Uniduqe	: in Boolean := False
			) return Element_Type is
		E : Element_Type;
	begin
		-- TODO :: Get_First
		return E;
	end Get_First;

	
	function Get_All( Index : in Index_Type ) return Element_Vectors.Vector is
		V: Element_Vectors.Vector;
	begin
		-- TODO :: get_All
		return V;
	end Get_All;

end KOW_Sec.Data;
