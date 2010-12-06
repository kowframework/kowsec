




-- Data backend for KOW Sec --

-- this package works by storing and indexing private types


--------------
-- Ada 2005 --
--------------
with Ada.Containers.Vectors;
with Ada.Directories;

package body KOW_Sec.Data is


	function Storage_Path( Index : in Index_Type ) return String is
	begin
		return Storage_Root / To_String( Index );
	end Storage_Path;




	procedure Do_Open(
				Index	: in     Index_type;
				File	: in out Element_IO.File_Type;
				Mode	: in     Element_IO.File_Mode
			) is
		use Element_IO;
		Path : constant String := Storage_Path( Index );
	begin
		if Ada.Directories.Exists( Path ) then
			Open( Mode, File, Path );
		else
			Create( Mode, File, Path );
		end if;
	end Do_Open;


	procedure Store(
				Index	: in Index_Type;
				Element	: in Element_Type
			) is
		use Element_IO;
		File : File_Type;

		Item : Element_Type;
	begin
		Do_Open( Index, File, In_File );

		while not End_Of_File( File ) loop
			Read( File, Item );
			if Item = Element then
				Close( File );
				return;
			end if;
		end loop;

		Close( File );
		Do_Open( Index, File, Append_File );
		Write( File, Element );
		Close( File );
	end Store;


	function Get_First(
				Index	: in Index_Type;
				Unique	: in Boolean := False
			) return Element_Type is
		use Element_IO;
		Item : Element_Type;
		File : File_Type;
	begin

		Do_Open( Index, File, In_File );
		Read( File, item );
		
		if Unique and then not End_Of_File( File ) then
			Close( File );
			raise CONSTRAINT_ERROR with "more than one item at [" & Storage_Name & "::" & To_String( Index ) & "]";
		else
			Close( File );
		end if;

		return Item;
	end Get_First;

	
	function Get_All( Index : in Index_Type ) return Element_Vectors.Vector is
		use Element_IO;
		V : Element_Vectors.Vector;
		File : File_Type;
		Item : Element_Type;
	begin
		Do_Open( Index, File, In_File );

		while not End_Of_File( File ) loop
			Read( File, Item );
		end loop;

		Element_Vectors.Append( V, Item );

		return V;
	end Get_All;

begin
	if not Ada.Directories.Exists( Storage_Root ) then
		Ada.Directories.Create_Path( Storage_Root );
	end if;

end KOW_Sec.Data;
