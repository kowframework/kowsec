




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
	type Key_Type is private;
	with function To_String( Key : in Key_Type ) return String;
	type Element_Type is private;
	with package Element_Vectors is new Ada.Containers.Vectors(
					Index_Type	=> Positive,
					Element_Type	=> Element_Type
				);
	--Cache_Size	: Natural;	-- elements in cache
	--Index_Data	: Boolean;	-- should the data be indexed?
package KOW_Sec.Data is


	Storage_Root : constant String := KOW_Sec.Storage_Root / Storage_Name;




	function Storage_Path( Key : in Key_Type ) return String;
	

	procedure Append(
				Key	: in Key_Type;
				Element	: in Element_Type
			);

	procedure Store(
				Key	: in Key_Type;
				Element	: in Element_Type
			);

	procedure Store(
				Key	: in Key_Type;
				Elements: in Element_Vectors.Vector 
			);


	function Get_First(
				Key	: in Key_Type;
				Unique	: in Boolean := False
			) return Element_Type;
	
	function Get_All( Key : in Key_Type ) return Element_Vectors.Vector;

end KOW_Sec.Data;
