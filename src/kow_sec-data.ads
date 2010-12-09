




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

private

	type Semaphor_Type is new Ada.Finalization.Limited_Controlled with record
		-- the semaphor will automatically unlock the resource when removed from memory
		-- that's why it's a limited controlled type. :)
		--
		-- even though there is no need to unlock the resources, it's good to use
		-- the unlock method so distractec people that don't read this message
		-- won't get mad for no reason
		Key		: Key_Type;
		Is_Locked	: Boolean := False;
	end record;

	overriding
	procedure Finalize( Semaphor : in out Semaphor_Type );
	-- make sure the semaphor is not locked

	procedure Lock(
				Semaphor: in out Semaphor_Type;
				Key	: in     Key_Type
			);
	procedure Unlock( Semaphor : in out Semaphor_Type ) renames Finalize;



	package Key_Maps is new Ada.Containers.Ordered_Maps(
				Key_type	=> Key_Type,
				Element_Type	=> Boolean
			);

	In_Use	: Exception;
	-- used by Semaphor_Controller to warn the caller - procedure Lock - that the
	-- resource is already in use

	protected Semaphor_Controller is
		procedure Lock(
					Semaphor: in out Semaphor_Type;
					Key	: in     Key_Type
				);
		procedure Unlock( Semaphor: in out Semaphor_Type );
	private

		My_Map : Key_Maps.Map;
	end Semaphor_Controller;

end KOW_Sec.Data;
