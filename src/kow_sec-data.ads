




-- Data backend for KOW Sec --

-- this package works by storing and indexing private types


--------------
-- Ada 2005 --
--------------
with Ada.Containers.Vectors;
with Ada.Sequential_IO;


-------------------
-- KOW Framework --
-------------------

with KOW_Lib.File_System;		use KOW_Lib.File_System;
with KOW_Sec;

generic
	Storage_Name : String;
	type Index_Type is private;
	with function To_String( Index : in Index_Type ) return String;
	type Element_Type is private;
	with package Element_Vectors is new Ada.Containers.Vectors(
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
				Unique	: in Boolean := False
			) return Element_Type;
	
	function Get_All( Index : in Index_Type ) return Element_Vectors.Vector;

private
	package Element_IO is new Ada.Sequential_IO( Element_Type );

end KOW_Sec.Data;
