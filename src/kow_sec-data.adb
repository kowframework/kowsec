




-- Data backend for KOW Sec --

-- this package works by storing and Keying private types


--------------
-- Ada 2005 --
--------------
with Ada.Containers.Vectors;
with Ada.Directories;

package body KOW_Sec.Data is


	function Storage_Path( Key : in Key_Type ) return String is
	begin
		return Storage_Root / To_String( Key );
	end Storage_Path;

	package Element_IO is new Ada.Sequential_IO( Element_Type );


	procedure Delete( Key : in Key_Type ) is
		use Ada.Directories;
		Path : constant String := Storage_Path( Key );
	begin
		if Exists( Path ) then
			Delete_File( Path );
		end if;
	end Delete;


	procedure Do_Open(
				File	: in out Element_IO.File_Type;
				Mode	: in     Element_IO.File_Mode;
				Key	: in     Key_type
			) is
		Path : constant String := Storage_Path( Key );
	begin
		if Ada.Directories.Exists( Path ) then
			Element_IO.Open( File, Mode, Path );
		else
			Element_IO.Create( File, Mode, Path );
		end if;
	end Do_Open;


	procedure Append(
				Key	: in Key_Type;
				Element	: in Element_Type
			) is
		use Element_IO;
		File : File_Type;

		Item : Element_Type;
	begin
		Do_Open( File, In_File, Key );

		while not End_Of_File( File ) loop
			Read( File, Item );
			if Item = Element then
				Close( File );
				return;
			end if;
		end loop;

		Close( File );
		Do_Open( File, Append_File, Key );
		Write( File, Element );
		Close( File );
	end Append;


	procedure Store(
				Key	: in Key_Type;
				Elements: in Element_Vectors.Vector 
			) is
		use Element_IO;
		File : File_Type;
		procedure Iterator( C : Element_Vectors.Cursor ) is
		begin
			Write( File, Element_Vectors.Element( C ) );
		end Iterator;
	begin
		Delete( Key );
		Do_Open( File, Out_File, Key );
		Element_Vectors.Iterate( Elements, Iterator'Access );
		Close( File );
	end Store;


	procedure Store(
				Key	: in Key_Type;
				Element	: in Element_Type
			) is
		V : Element_Vectors.Vector;
	begin
		Element_Vectors.Append( V, Element );
		Store( Key, V );
	end Store;


	function Get_First(
				Key	: in Key_Type;
				Unique	: in Boolean := False
			) return Element_Type is
		use Element_IO;
		Item : Element_Type;
		File : File_Type;
	begin

		Do_Open( File, In_File, Key );
		Read( File, item );
		
		if Unique and then not End_Of_File( File ) then
			Close( File );
			raise CONSTRAINT_ERROR with "more than one item at [" & Storage_Name & "::" & To_String( Key ) & "]";
		else
			Close( File );
		end if;

		return Item;
	end Get_First;

	
	function Get_All( Key : in Key_Type ) return Element_Vectors.Vector is
		use Element_IO;
		V : Element_Vectors.Vector;
		File : File_Type;
		Item : Element_Type;
	begin
		Do_Open( File, In_File, Key );

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
