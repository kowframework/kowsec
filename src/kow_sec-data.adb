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

	--------------------
	-- Helper Methods --
	--------------------
	

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



	------------------
	-- Storage Path --
	------------------


	function Storage_Path( Key : in Key_Type ) return String is
	begin
		return Storage_Root / To_String( Key );
	end Storage_Path;

	---------------------
	-- In-memory cache --
	---------------------





	protected body Cache is
		-- it's a infinite cache for every element loaded so far...
		-- to avoid colisions we are using ordered maps.. the ideal is to use an
		-- ordered map with a hash function with no colisions at all tough

		procedure Read(
					Key		: in     Key_Type;
					Item		:    out Element_Vectors.Vector;
					From_Disk	: in     Boolean := False
				) is
		begin
			if From_Disk or else not Cache_Maps.Contains( Cache_Map, Key ) then
				declare
					use Element_IO;
					File	: File_Type;
					Elements: Element_Vectors.Vector;
					Tmp	: Element_Type;
				begin

					Do_Open( File, In_File, Key );


					while not End_Of_File( File ) loop
						Read( File, Tmp );
						Element_Vectors.Append( Elements, Tmp );
					end loop;
					Close( File );

					Cache_Maps.Include( Cache_Map, Key, Elements );

					Item := Elements;
				end;

			else
				Item := Cache_Maps.Element( Cache_Map, Key );
			end if;
		end Read;


		procedure Write(
					Key	: in     Key_Type;
					Item	: in     Element_Vectors.Vector
				) is
			use Element_IO;
			File : File_type;

			procedure Appender( C : in Element_Vectors.Cursor ) is
			begin
				Write( File, Element_Vectors.Element( C ) );
			end Appender;
		begin
			Cache_Maps.Include( Cache_Map, Key, Item );

			Do_Open( File, Out_File, Key );
			Element_Vectors.Iterate( Item, Appender'Access );
			Close( File );
		end Write;


		procedure Append(
					Key	: in     Key_Type;
					Item	: in     Element_Type
				) is
			use Element_IO;
			File 		: File_Type;
			Elements	: Element_Vectors.Vector;
		begin
			Read( Key, Elements );
			Element_Vectors.Append( Elements, Item );
			Cache_Maps.Include( Cache_Map, Key, Elements );

			Do_Open( File, Append_File, Key );
			Write( File, Item );
			Close( File );
		end Append;


		procedure Delete(
					Key		: in     Key_Type;
					From_Disk	: in     Boolean := False
				) is
		-- delete from map and, if required, from disk also
		begin
			if Cache_Maps.Contains( Cache_Map, Key ) then
				Cache_Maps.Delete( Cache_Map, Key );
			end if;

			if From_Disk then
				declare
					Path : constant String := Storage_Path( Key );
				begin
					if Ada.Directories.Exists( Path ) then
						Ada.Directories.Delete_File( Path );
					end if;
				end;
			end if;
		end Delete;
	end Cache;



	---------------------
	-- Other functions --
	---------------------

	function Get_First(
				Key	: in Key_Type;
				Unique	: in Boolean := False
			) return Element_Type is
		-- get only the first element..
		-- if unique and it's not the only element then raise constraint_error
		-- if there is no element raise constraint_error also
		use Ada.Containers;
		Elements : Element_Vectors.Vector;
	begin
		Cache.Read( Key, Elements );

		if Unique and then Element_Vectors.Length( Elements ) /= 1 then
			raise CONSTRAINT_ERROR with "not unique element";
		end if;

		return Element_Vectors.First_Element( Elements );
	end Get_First;

	function Get_All( Key : in Key_Type ) return Element_Vectors.Vector is
		-- get all elements
		Elements : Element_Vectors.Vector;
	begin
		Cache.Read( Key, Elements );
		return Elements;
	end Get_All;

	procedure Store(
				Key	: in Key_Type;
				Element	: in Element_Type
			) is
		-- store the element making it the only one in the file
		V : Element_Vectors.Vector;
	begin
		Element_Vectors.Append( V, Element );

		Cache.Delete( Key, True );
		-- make sure the file is empty

		Cache.Write( Key, V );
	end Store;

begin
	if not Ada.Directories.Exists( Storage_Root ) then
		Ada.Directories.Create_Path( Storage_Root );
	end if;

end KOW_Sec.Data;
