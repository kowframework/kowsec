




-- Data backend for KOW Sec --

-- this package works by storing and indexing private types


--------------
-- Ada 2005 --
--------------
with Ada.Containers.Vectors;
with Ada.Containers.Ordered_Maps;
with Ada.Finalization;
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
	with function "<"( L,R : in Key_Type ) return Boolean;
	type Element_Type is private;
	with package Element_Vectors is new Ada.Containers.Vectors(
					Index_Type	=> Positive,
					Element_Type	=> Element_Type
				);
	--Cache_Size	: Natural;	-- elements in cache
	--Index_Data	: Boolean;	-- should the data be indexed?
package KOW_Sec.Data is


	------------------
	-- Storage Path --
	------------------
	Storage_Root : constant String := KOW_Sec.Storage_Root / Storage_Name;


	function Storage_Path( Key : in Key_Type ) return String;


	---------------------
	-- In-memory cache --
	---------------------

	package Cache_Maps is new Ada.Containers.Ordered_Maps(
				Key_type	=> Key_Type,
				Element_Type	=> Element_Vectors.Vector,
				"="		=> Element_Vectors."="
			);

	protected Cache is
		-- it's a infinite cache for every element loaded so far...
		-- to avoid colisions we are using ordered maps.. the ideal is to use an
		-- ordered map with a hash function with no colisions at all tough

		procedure Read(
					Key		: in     Key_Type;
					Item		:    out Element_Vectors.Vector;
					From_Disk	: in     Boolean := False
				);
		-- tries reading from cache.. if not cache, read file...
		-- if from_disk = true reads from the file anyway

		procedure Write(
					Key	: in     Key_Type;
					Item	: in     Element_Vectors.Vector
				);
		-- update cache with new value
		-- if on_disk = true then update the disk file also

		procedure Append(
					Key	: in     Key_Type;
					Item	: in     Element_Type
				);
		-- append a new item into the storage
		-- if on_disk = true then update the disk also

		procedure Delete(
					Key		: in     Key_Type;
					From_Disk	: in     Boolean := False
				);
		-- delete from map and, if required, from disk also
	private
		Cache_Map : Cache_Maps.Map;
	end Cache;


	-------------
	-- Aliases --
	-------------

	procedure Append(
				Key	: in Key_Type;
				Element	: in Element_Type
			) renames Cache.Append;


	procedure Store(
				Key	: in Key_Type;
				Elements: in Element_Vectors.Vector 
			) renames Cache.Write;
	
	procedure Delete(
				Key		: in Key_type;
				From_Disk	: in Boolean := False
			) renames Cache.Delete;

	---------------------
	-- Other functions --
	---------------------

	function Get_First(
				Key	: in Key_Type;
				Unique	: in Boolean := False
			) return Element_Type;
	-- get only the first element..
	-- if unique and it's not the only element then raise constraint_error
	-- if there is no element raise constraint_error also
	
	function Get_All( Key : in Key_Type ) return Element_Vectors.Vector;
	-- get all elements


	procedure Store(
				Key	: in Key_Type;
				Element	: in Element_Type
			);
	-- store the element making it the only one in the file

private
	package Element_IO is new Ada.Sequential_IO( Element_Type );

end KOW_Sec.Data;
