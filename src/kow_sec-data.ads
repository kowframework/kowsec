




-- Data backend for KOW Sec --

-- this package works by storing and indexing private types


--------------
-- Ada 2005 --
--------------
with Ada.Containers.Vectors;


-------------------
-- KOW Framework --
-------------------

with KOW_Lib.File_System;		use KOW_Lib.File_System;
with KOW_Sec;

generic
	Storage_Name : constant String;
	type Index_Type is private;
	function To_String( Index : in Index_Type ) return String;
	type Element_Type is private;
	package Element_Vectors is new Ada.Containers.Vectors(
					Index_Type	=> Positive,
					Element_Type	=> Element_Type
				);
	--Cache_Size	: Natural;	-- elements in cache
	--Index_Data	: Boolean;	-- should the data be indexed?
package KOW_Sec.Data is


	Storage_Root : constant String := KOW_Sec.Storage_Root / Storage_Name;


	function Storage_Path( Index : in Index_Type ) return String;
	

	procedure Store(
				Index	: in Index_Type;
				Element	: in Element_Type
			);

	function Get_First(
				Index	: in Index_Type;
				Uniduqe	: in Boolean := False
			) return Element_Type;
	
	function Get_All( Index : in Index_Type ) return Element_Vectors.Vector;

end KOW_Sec.Data;
