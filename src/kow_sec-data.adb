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
		Semaphor : Semaphor_Type;
	begin
		Lock( Semaphor, key );
		if Exists( Path ) then
			Delete_File( Path );
		end if;
		Unlock( Semaphor );
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
		File 		: File_Type;
		Item 		: Element_Type;
		Semaphor	: Semaphor_Type;
	begin
		
		Lock( Semaphor, key );
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
		Unlock( Semaphor );
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

		Semaphor	: Semaphor_Type;
	begin
		Delete( Key );
		
		Lock( Semaphor, Key );
		Do_Open( File, Out_File, Key );
		Element_Vectors.Iterate( Elements, Iterator'Access );
		Close( File );
		Unlock( Semaphor );
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
		Item		: Element_Type;
		File		: File_Type;
		Semaphor	: Semaphor_type;
	begin

		Lock( Semaphor, key );
		Do_Open( File, In_File, Key );
		Read( File, item );
		
		if Unique and then not End_Of_File( File ) then
			Close( File );
			raise CONSTRAINT_ERROR with "more than one item at [" & Storage_Name & "::" & To_String( Key ) & "]";
		else
			Close( File );
		end if;

		Unlock( Semaphor );
		return Item;
	end Get_First;

	
	function Get_All( Key : in Key_Type ) return Element_Vectors.Vector is
		use Element_IO;
		V	: Element_Vectors.Vector;
		File	: File_Type;
		Item	: Element_Type;
		Semaphor: Semaphor_type;
	begin

		Lock( Semaphor, Key );
		Do_Open( File, In_File, Key );


		while not End_Of_File( File ) loop
			Read( File, Item );
			Element_Vectors.Append( V, Item );
		end loop;
		Close( File );
		Unlock( Semaphor );


		return V;
	end Get_All;



-- private

	overriding
	procedure Finalize( Semaphor : in out Semaphor_Type ) is
		-- make sure the semaphor is not locked
	begin
		if Semaphor.Is_Locked then
			Semaphor_Controller.Unlock( Semaphor );
		end if;
	end Finalize;

	procedure Lock(
				Semaphor: in out Semaphor_Type;
				Key	: in     Key_Type
			) is
	begin
		loop
			begin
				Semaphor_Controller.Lock( Semaphor, Key );
				exit;
			exception
				when IN_USE =>
					null;
			end;
		end loop;
	end Lock;
	


	protected body Semaphor_Controller is
		procedure Lock(
					Semaphor: in out Semaphor_Type;
					Key	: in     Key_Type
				) is
			Is_Locked : Boolean;
		begin
			pragma Assert( Semaphor.Is_Locked = False, "Can't lock twice a resource" );

			begin
				Is_Locked := Key_Maps.Element( My_Map, Key );
			exception
				when CONSTRAINT_ERROR => null;
			end;

			if Is_locked then
				raise IN_USE;
			end if;

			Key_Maps.Include( My_Map, Key, True );
			Semaphor.Key := Key;
			Semaphor.Is_Locked := True;
		end Lock;

		procedure Unlock(
					Semaphor: in out Semaphor_Type
				) is
		begin
			pragma Assert( Semaphor.Is_Locked = True, "Can't unlock a not-locked semaphor" );

			Key_Maps.Include( My_Map, Semaphor.Key, False );
			Semaphor.Is_Locked := False;
		end Unlock;
	end Semaphor_Controller;







begin
	if not Ada.Directories.Exists( Storage_Root ) then
		Ada.Directories.Create_Path( Storage_Root );
	end if;

end KOW_Sec.Data;
