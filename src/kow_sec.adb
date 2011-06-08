------------------------------------------------------------------------------
--                                                                          --
--                       KOW Framework :: Security                          --
--                                                                          --
--                              KOW Framework                               --
--                                                                          --
--                                 B o d y                                  --
--                                                                          --
--               Copyright (C) 2007-2011, KOW Framework Project             --
--                                                                          --
--                                                                          --
-- KOWSec is free software; you can redistribute it  and/or modify it under --
-- terms of the  GNU General Public License as published  by the Free Soft- --
-- ware  Foundation;  either version 2,  or (at your option) any later ver- --
-- sion. KOWSec is distributed in the hope that it will be useful, but WITH---
-- OUT ANY WARRANTY;  without even the  implied warranty of MERCHANTABILITY --
-- or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License --
-- for  more details.  You should have  received  a copy of the GNU General --
-- Public License distributed with KOWSec; see file COPYING.  If not, write --
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
with Ada.Calendar;		use Ada.Calendar;
with Ada.Containers.Vectors;
with Ada.Containers.Hashed_Maps;
with Ada.Containers.Ordered_Maps;
with Ada.Directories;
with Ada.Exceptions;
with Ada.Finalization;
with Ada.Strings;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded;	use Ada.Strings.Unbounded;
with Ada.Strings.Unbounded.Hash;
with Ada.Numerics.Discrete_Random;

----------
-- GNAT --
----------
with GNAT.MD5;


-------------------
-- KOW Framework --
-------------------
with KOW_Config;
with KOW_Lib.Json;
with KOW_Lib.Locales;
with KOW_Lib.UString_Ordered_Maps;



-------------
-- Contrib --
-------------




package body KOW_Sec is

	---------------
	-- Variables --
	---------------
	Group_Labels : KOW_Config.Config_File;

	--------------------
	-- Helper Methods --
	--------------------

	procedure Copy(
			From	: in     String;
			To	: in out String
		) is
		-- copy the contents in From to To ocuping only the first spaces
		-- the remaining in "to" is filled with spaces..
		--
		-- if From'Length > To'Length then raise constraint error
		
		First_Remaining	: Integer := To'First + From'Length;
	begin
		if From'Length > To'Length then
			raise CONSTRAINT_ERROR with "trying to copy way too big string...";
		end if;

		for i in From'Range loop
			To( To'First - From'First + i ) := From( i );
		end loop;

		To( First_Remaining .. To'Last ) := ( others => ' ' );
	end Copy;

	------------------
	-- Data Storage --
	------------------
	package body Data is

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


			function Exists( Key : in Key_Type ) return Boolean is
			begin
				return Cache_Maps.Contains( Cache_Map, Key ) or else Ada.Directories.Exists( Storage_Path( Key ) );
			end Exists;

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

	end Data;




	package Group_Roles_Data is new KOW_Sec.Data(
				Storage_Name	=> "group_roles",
				Key_Type	=> Group_type,
				To_String	=> Get_Name,
				"<"		=> "<",
				Element_Type	=> Role_Type,
				Element_Vectors	=> Role_Vectors
			);

	package User_Groups_Data is new KOW_Sec.Data(
				Storage_Name	=> "user_groups",
				Key_Type	=> User_Identity_Type,
				To_String	=> To_String,
				"<"		=> "<",
				Element_Type	=> Group_Type,
				Element_Vectors	=> Group_Vectors
			);

	package User_Roles_Data is new KOW_Sec.Data(
				Storage_Name	=> "user_roles",
				Key_Type	=> User_Identity_Type,
				To_String	=> To_String,
				"<"		=> "<",
				Element_Type	=> Role_Type,
				Element_Vectors	=> Role_Vectors
			);
	package User_Data is new KOW_Sec.Data(
				Storage_Name	=> "users",
				Key_Type	=> User_Identity_type,
				To_String	=> To_String,
				"<"		=> "<",
				Element_Type	=> User_Data_Type,
				Element_Vectors	=> User_Vectors
			);



	
	----------------------------
	-- The User Identity Type --
	----------------------------
	
	----------------------------
	-- The User Identity Type --
	----------------------------
	

	function MD5_Sign( Str : in String ) return String is

		-- calculates the hash of this identity
		use GNAT.MD5;
		C : Context;
	begin
		Update( C, Str );
		return Digest( C );
	end MD5_Sign;

	
	function MD5_Sign( Str : in String ) return User_Identity_Type is
		S : constant String := MD5_Sign( Str );
	begin
		return User_Identity_Type( S );
	end MD5_Sign;

	function To_Identity( Str : in String ) return User_Identity_Type is
	begin
		if Str'Length /= User_Identity_Type'Length then
			raise CONSTRAINT_ERROR with Str & " is not a valid identity";
		end if;
		return User_Identity_Type( Str );
	end To_Identity;

	function To_String( Identity : in User_Identity_Type ) return String is
	begin
		return String( Identity );
	end to_String;

		


	function New_User_Identity return User_Identity_Type is
		-- this will generate a brand new user identity
		

		function The_Timestamp return String is
			T	: Time := Clock;
			Y	: Year_Number;
			M	: Month_Number;
			D	: Day_Number;
			S	: Day_Duration;
		begin
			Split( T, Y, M, D, S );
			return Year_Number'Image( Y ) & Month_Number'Image( M ) & Day_Number'Image( D ) & Day_Duration'Image( S );
		end The_Timestamp;


		function The_Random_Part return String is
			Str : String( 1 .. 20 );


			package Char_Rand is new Ada.Numerics.Discrete_Random( Result_Subtype => Character );
			use Char_Rand;

			G : Generator;
		begin
			Reset( G );
			for i in Str'Range loop
				Str( I ) := Random( G );
			end loop;
			return Str;
		end The_Random_Part;


		function The_Key return String is
			-- the timestamp + 20 random leters
		begin
			return The_Timestamp & The_Random_Part;
		end The_Key;

		Identity : User_Identity_Type;
	begin
		loop
			Identity := MD5_Sign( The_Key );
			exit when not User_Data.Exists( Identity );
		end loop;
		return Identity;
	end New_User_Identity;


	-------------------------------
	-- AUTHENTICATION MANAGEMENT --
	-------------------------------


	procedure Register_Manager( Manager: in out Authentication_Manager_Access ) is
	-- Register a manager so it's usable by KOW_Sec.
	begin
		Authentication_Manager_Maps.Insert(
						Container	=>Managers_Registry,
						Key		=> To_Unbounded_String( Get_Name( Manager.all ) ),
						New_Item	=> Manager
					);
	end Register_Manager;
	
	function Get_Manager( Manager_Name : in String ) return Authentication_Manager_Access is
	begin
		return Get_Manager( To_Unbounded_String( Manager_Name ) );
	end Get_Manager;

	function Get_Manager( Manager_Name : in Unbounded_String ) return Authentication_Manager_Access is
	begin
		return Authentication_Manager_Maps.Element( Managers_Registry, Manager_Name );
	exception
		when CONSTRAINT_ERROR =>
			raise CONSTRAINT_ERROR with "no such authentication manager :: " & To_String( Manager_Name );
	end Get_Manager;

	function Do_Login(
				Username : in String;
				Password : in String
			) return User_Identity_Type is
		-- tries to login the user using the registered managers.
		-- the pair username vs password here is quite abstract.. the manager can implement
		-- this function giving different meanings to the data received
		use Authentication_Manager_Maps;

		C: Authentication_Manager_Maps.Cursor := First( Managers_Registry );

		User_Identity	: User_Identity_Type;
		User		: User_Data_Type;
	begin
		while Has_Element( C )
		loop
			begin
				User_Identity :=  Do_Login(
							Element( C ).all,
							Username,
							Password
						);
				-- now we check the user status... we only allow enabled users..
				User := Get_User( User_Identity );

				if User.Account_Status /= Account_Enabled then
					raise ACCESS_DENIED with "The user is not enabled right now. The current status is: " & Account_Status_Type'Image( User.Account_Status );
				end if;

				return User_Identity;
			exception
				when INVALID_CREDENTIALS | UNKNOWN_USER => null;
			end;
			C := Next( C );
		end loop;

		raise INVALID_CREDENTIALS with "for username """ & Username & """";

	end Do_Login;



	function To_Json( User : in User_Data_Type ) return KOW_Lib.Json.Object_Type is
		-- return a JSON object representing the user
		use KOW_Lib.Json;
		Response : KOW_Lib.Json.Object_Type;

		procedure Set( Key, Value : in String ) is
			pragma Inline( Set );
		begin
			Set( Response, Key, Ada.Strings.Fixed.Trim( Value, Ada.Strings.Both ) );
		end Set;
	begin
		
		Set( "identity",		String( User.Identity ) );
		Set( "account_status",		Account_Status_type'Image( User.Account_Status ) );
		Set( "account_status_message",	User.Account_Status_Message );
		Set( "first_name",		User.First_Name );
		Set( "last_name",		User.Last_Name );
		Set( "nickname",		User.Nickname );
		Set( "primary_email",		User.Primary_Email );

		return Response;
	end To_Json;


	function To_Json_Array( Users : in User_Vectors.Vector ) return KOW_Lib.Json.Array_Type is
		-- return a JSON array representing the users
		use KOW_Lib.Json;
		Arr : Array_Type;
		procedure Iterator( C : in User_Vectors.Cursor ) is
		begin
			Append( Arr, To_Json( User_Vectors.Element( C ) ) );
		end Iterator;
	begin
		User_Vectors.Iterate( Users, Iterator'Access );
		return Arr;
	end To_Json_Array;

	----------------------
	-- Roles Management --
	----------------------

	function To_Identity( Str : in String ) return Role_Identity_Type is
		Id	: Role_Identity_Type;
	begin
		Copy( From => Str, To => String( id ) );
		return Id;
	exception
		when CONSTRAINT_ERROR =>
			raise CONSTRAINT_ERROR with Str & " is not a valid role identity";
	end To_Identity;

	function Identity( Role : in Role_type ) return Role_Identity_Type is
		use Ada.Strings;
		-- returns Application::Role
	begin
		return To_Identity( Fixed.Trim( Role.Application, Both ) & "::" & Fixed.Trim( Role.Role, Both ) );
	end Identity;


	function To_Role( Identity : in Role_Identity_Type ) return Role_Type is
		-- parse the role identity into a role

		Id_Str	: String := Ada.Strings.Fixed.Trim( String( Identity ), Ada.Strings.Both );
		-- make sure the identity we receive is trimmed

		Idx	: Integer := Ada.Strings.Fixed.Index( Id_Str, "::" );
		Role	: Role_Type;
	begin
		if Idx <= 1 OR ELSE Idx >= 101 then
			raise CONSTRAINT_ERROR with "Not a valid role identity: " & Id_Str;
		end if;

		Copy( From => Id_Str( Id_Str'First .. Idx - 1 ), To => Role.Application );
		Copy( From => Id_Str( Idx + 2 .. Id_Str'Last ), To => Role.Role );

		return Role;
	end To_Role;


	function New_Role(
				Application	: in String;
				Role		: in String
			) return Role_Type is
		-- builds up a new role object
		Role_Obj : Role_Type;
	begin
		Copy( From => Application, To => Role_Obj.Application );
		Copy( From => Role, To => Role_Obj.Role );

		return Role_Obj;
	end New_Role;


	protected body Roles_Registry is
		procedure Register( Role : in Role_Type ) is
		begin
			Role_Maps.Include( My_Roles, Identity( Role ), Role );
		end Register;
		

		function Get_Roles return Role_Maps.Map is
		begin
			return My_Roles;
		end Get_Roles;
	end Roles_Registry;



	-----------------------
	-- Groups Management --
	-----------------------

	function Get_Name( Group : in Group_Type ) return String is
		-- get the trimmed version of the group name
	begin
		return Ada.Strings.Fixed.Trim( String( Group.Name ), Ada.Strings.Both );
	end Get_Name;


	function Get_Label(
				Group	: in Group_Type;
				Locale	: in KOW_Lib.Locales.Locale := KOW_Lib.Locales.Default_Locale
			) return String is
		-- get the label in a given locale
	begin
		return KOW_Config.Element(
					F		=> Group_Labels,
					Key		=> Get_Name( Group ),
					L_Code		=> Locale.Code
				);
	exception
		when CONSTRAINT_ERROR => return Get_Name( Group );
	end Get_Label;

	function Get_Context( Group : in Group_Type ) return String is
		-- get the trimmed version of the group context
	begin
		return Ada.Strings.Fixed.Trim( String( Group.Context ), Ada.Strings.Both );
	end Get_Context;

	function To_String( Group : Group_Type ) return String is
		-- Return Get_Name & "::" & Get_Context
	begin
		return Get_Name( Group ) & "::" & Get_Context( Group );
	end To_String;

	function To_Group( Name : in String; Context : in Context_Type := ( others => ' ' ) ) return Group_Type is
		Group : Group_Type;
	begin
		Copy( From => Name, To => String( Group.Name ) );
		Group.Context := Context;

		return Group;
	end To_Group;


		


	function "<"( L, R : in String ) return Boolean is
	begin
		for i in L'Range loop
			if i not in R'range or else  L( i ) > R( i ) then
				return false;
			elsif L( i ) < R( i ) then
				return true;
			end if;
		end loop;
		return false;
	end "<";

	function "<"( L, R : in Group_Type ) return Boolean is
	begin
		return Get_Name( L ) < Get_Name( R );
	end "<";

	function Get_Roles( Group : in Group_Type ) return Role_Vectors.Vector is
	begin
		return Group_Roles_Data.Get_All( Group );
	end Get_Roles;

	procedure Set_Roles( Group : in Group_Type; Roles : in Role_Vectors.Vector ) is
	begin
		Group_Roles_Data.Store( Group, Roles );
	end Set_Roles;


	procedure Add_Role( Group : in Group_Type; Role : in Role_Type ) is
		Roles : Role_Vectors.Vector := Get_Roles( Group );
	begin
		if not Role_Vectors.Contains( Roles, Role ) then
			Role_Vectors.Append( Roles, Role );
			Set_Roles( Group, Roles );
		end if;
	end Add_Role;


	procedure Load_Group_Labels is
		-- load the labels from disk
	begin
		Group_Labels := KOW_Config.New_Config_File( "kowsec-group_labels" );
	end Load_Group_Labels;


	---------------------
	-- User Management --
	---------------------

	

	function Full_Name(
				User	: in User_Data_Type;
				Locale	: in KOW_Lib.Locales.Locale := KOW_Lib.Locales.Default_Locale
		) return String is
	-- return the full name for this user, respecting the locale's conventions

	begin
		if Is_Anonymous( User ) then
			return KOW_Lib.Locales.Get_Formated_Full_Name(
					L		=> Locale,
					First_Name	=> "Anonymous",
					Last_Name	=> "User"
				);
		else
			return KOW_Lib.Locales.Get_Formated_Full_Name(
					L		=> Locale,
					First_Name	=> Ada.Strings.Fixed.Trim( User.First_Name, Ada.Strings.Both ),
					Last_Name	=> Ada.Strings.Fixed.Trim( User.Last_Name, Ada.Strings.Both )
				);
		end if;
	end Full_Name;


	function Gravatar_URL( User : in User_Data_Type; Size : Positive := 69 ) return String is
		-- return the gravatar URL for the given user
		S : constant String := Ada.Strings.Fixed.Trim( Positive'Image( Size ), Ada.Strings.Both );
	begin
		return "http://www.gravatar.com/avatar/" & MD5_Sign( Ada.Strings.Fixed.Trim( User.Primary_Email, Ada.Strings.Both ) ) & ".jpg?s=" & S;
	end Gravatar_URL;


	function Get_All_Groups( User : in User_Data_Type ) return Group_Vectors.Vector is
	begin
		return User_Groups_Data.Get_All( User.Identity );
	end Get_All_Groups;

	function Get_Groups(
				User	: in User_Data_Type;
				Contexts: in Context_Array
			) return Group_Vectors.Vector is
		-- Get contextualized groups for this user.
		Global_Context	: Context_Type := ( others => ' ' );
		Groups : Group_Vectors.Vector;


		function Has_Context( C : in Context_Type ) return Boolean is
		begin
			for i in Contexts'Range loop
				if C = Contexts( i ) then
					return true;
				end if;
			end loop;

			return false;
		end Has_Context;


		procedure Iterator( C : in Group_Vectors.Cursor ) is
			Group : Group_Type := Group_Vectors.Element( C );
		begin
			if Group.Context = Global_Context or else Has_Context( Group.Context ) then
				Group_Vectors.Append( Groups, Group );
			end if;
		end Iterator;
	begin
		Group_Vectors.Iterate( Get_All_Groups( User ), Iterator'Access );

		return Groups;
	end Get_Groups;

	function Get_All_Groups( User : in User_Type ) return Group_Vectors.Vector is
	begin
		return Get_All_Groups( User.Data );
	end Get_All_Groups;

	function Get_Groups(
				User 	: in User_Type;
				Contexts: in Context_Array
			) return Group_Vectors.Vector is
	begin
		return Get_Groups( User.Data, Contexts );
	end Get_Groups;


	procedure Set_Groups( User : in User_Data_Type; Groups : in Group_Vectors.Vector ) is
	begin
		User_Groups_Data.Store( User.Identity, Groups );
	end Set_Groups;


	procedure Add_Group( User : in User_Data_Type; Group : in Group_Type ) is
		-- add a group to the user;
		-- this procedure doesn't perform any kind of check!
		-- and it uses get_all_groups + set_groups;
		Groups : Group_Vectors.Vector := Get_All_Groups( User );
	begin
		Group_Vectors.Append( Groups, Group );
		Set_Groups( User, Groups );
	end Add_Group;



	procedure Remove_Group( User : in User_Data_Type; Group : in Group_Type ) is

		Found	: Boolean := False;
		Groups	: Group_Vectors.Vector;

		procedure Iterator( C : Group_Vectors.Cursor ) is
			G : Group_Type := Group_Vectors.Element( C );
		begin
			if G.Name = Group.Name and then G.Context = Group.Context then
				Found := true;
			else
				Group_Vectors.Append( Groups, G );
			end if;
		end Iterator;
	begin
		Group_Vectors.Iterate( Get_All_Groups( User ), Iterator'Access );
		if Found then
			Set_Groups( User, Groups );
		else
			raise CONSTRAINT_ERROR with "cant find group with this context for this user";
		end if;
	end Remove_Group;


	function Get_Roles(
				User			: in User_Data_Type;
				Combine_Group_Roles	: in Boolean := False;
				Contexts		: in Context_Array := Empty_Context_Array
			) return Role_Vectors.Vector is
		-- if combine group roles is true, does exactly that given that only one instance of each role is returned

		use Role_Vectors;

		V : Vector;


		procedure Append_Once( Role : Role_Type ) is
		begin
			if not Contains( V, Role ) then
				Append( V, Role );
			end if;
		end Append_Once;

		procedure Append( From_Vector : in Vector ) is
			procedure Iterator( C: in Cursor ) is
			begin
				Append_once( Element( C ) );
			end Iterator;
		begin
			Iterate( From_Vector, Iterator'Access );
		end Append;

		procedure Groups_Iterator( C : Group_Vectors.Cursor ) is
		begin
			Append( Group_Roles_Data.Get_All( Group_Vectors.Element( C ) ) );
		end Groups_Iterator;

	begin
		V := User_Roles_Data.Get_All( User.Identity );
		if Combine_Group_Roles then
			Group_Vectors.Iterate( Get_Groups( User, Contexts), Groups_Iterator'Access );
		end if;

		return V;
	end Get_Roles;


	function Get_Roles(
				User			: in User_Type;
				Combine_Group_Roles	: in Boolean := False;
				Contexts		: in Context_Array := Empty_Context_Array
			) return Role_Vectors.Vector is
		pragma Inline( Get_Roles );
	begin
		return Get_Roles( User.Data, Combine_Group_Roles, Contexts );
	end Get_Roles;

	function Get_All_Roles(
				User			: in User_Data_Type;
				Combine_Group_Roles	: in Boolean := False
			) return Role_Vectors.Vector is
		-- get every single role of this user, no mather in what context
		use Role_Vectors;

		V : Vector;

		procedure Append_Once( Role : Role_Type ) is
		begin
			if not Contains( V, Role ) then
				Append( V, Role );
			end if;
		end Append_Once;

		procedure Append( From_Vector : in Vector ) is
			procedure Iterator( C : CUrsor ) is
			begin
				Append_Once( Element( C ) );
			end Iterator;
		begin
			Iterate( From_Vector, Iterator'Access );
		end Append;

		procedure Groups_Iterator( C : Group_Vectors.Cursor ) is
		begin
			Append( Group_Roles_Data.Get_all( Group_Vectors.Element( C ) ) );
		end Groups_Iterator;
	begin

		V := User_Roles_Data.Get_All( User.Identity );
		if Combine_Group_Roles then
			Group_Vectors.Iterate( Get_All_Groups( User ), Groups_iterator'Access );
		end if;

		return V;
	end Get_All_Roles;

	function Get_All_Roles(
				User			: in User_Type;
				Combine_Group_Roles	: in Boolean := False
			) return Role_Vectors.Vector is
		-- get every single role of this user, no mather in what context
	begin
		return Get_All_Roles( User.Data, Combine_Group_Roles );
	end Get_All_Roles;



	procedure Set_Roles( User : in User_Data_Type; Roles : in Role_Vectors.Vector ) is
	begin
		User_Roles_Data.Store( User.Identity, Roles );
	end Set_Roles;

	procedure Add_Global_Role( User : in User_Data_Type; Role : in Role_Type ) is
		Roles : Role_Vectors.Vector := Get_Roles( User, False );
	begin
		if not Role_Vectors.Contains( Roles, Role ) then
			Role_Vectors.Append( Roles, Role );
			Set_Roles( User, Roles );
		end if;
	end Add_Global_Role;

	function Is_Anonymous( User : in User_Data_Type ) return Boolean is
		-- Return true if this user isn't logged in.
	begin
		return User.Identity = ( 1 .. 32 => ' ' ) or else User.Identity = Anonymous_User_Identity;
	end Is_Anonymous;



	function Is_Anonymous( User : in User_Type ) return Boolean is
		-- Return true if this user isn't logged in.
	begin
		return Is_Anonymous( User.Data );
	end Is_Anonymous;

	function Get_User( User_Identity: in String ) return User_Data_Type is
	begin
		return Get_User( To_Identity( User_Identity ) );
	end Get_User;

	function Get_User( User_Identity: in User_Identity_Type ) return User_Data_Type is
		Data : User_Data_Type;
	begin
		if not User_Data.Exists( User_Identity ) then
			raise CONSTRAINT_ERROR with "no such user: " & String( User_Identity );
		end if;
		Data := User_Data.Get_First( User_Identity, True );
		pragma Assert( Data.Identity = User_Identity, "Stored user identity doesnt match" );
		return Data;
	end Get_User;



	procedure Store_User( User : in User_Data_Type ) is
		-- store the user using the backend
	begin
		User_Data.Store( User.Identity, User );
	end Store_User;



	function Do_Login(
				Username : in String;
				Password : in String
			) return User_Type is
		-- do login and initialize the User_Type variable
		use Authentication_Manager_Maps;

		C: Authentication_Manager_Maps.Cursor := First( Managers_Registry );
	begin
		while Has_Element( C )
		loop
			begin
				declare
					Identity : User_Identity_Type := Do_Login(
										Element( C ).all,
										Username,
										Password
									);
					User 	: User_Type := (
									Data		=> Get_User( Identity ),
									Current_Manager => Element( C )
								);
				begin


					if User.Data.Account_Status /= Account_Enabled then
						raise ACCOUNT_DISABLED_ERROR with "The user is not enabled right now. The current status is: " & Account_Status_Type'Image( User.Data.Account_Status );
					end if;
					return User;
				end;

			exception
				when INVALID_CREDENTIALS | UNKNOWN_USER => null;
			end;
			C := Next( C );
		end loop;

		raise INVALID_CREDENTIALS with "for username """ & Username & """";

	end Do_Login;






	------------------------------
	-- Authorization Management --
	------------------------------
	
	function To_Context( Context_Str : in String ) return Context_Type is
		Context : Context_type;
	begin
		Copy( From => Context_Str, To => String( Context ) );
		return Context;
	end To_Context;


	procedure Require(	
				Criteria	: in out Criteria_Type;
				User		: in     User_Type 
			) is
		-- matches the user against some criteria.
		-- raise ACCESS_DENIED if the user fails this criteria.
		Is_Allowed_Response : Boolean;
	begin
		Is_Allowed( Criteria_Type'Class( Criteria ), User, Is_Allowed_Response );
		if not Is_Allowed_Response then
			raise ACCESS_DENIED with Describe( Criteria_Type'Class( Criteria ) );
		end if;
	end Require;

	procedure Require(	
				Name		: in     Criteria_Name;
				Descriptor	: in     Criteria_Descriptor;
				User		: in     User_Type;
				Contexts	: in     Context_Array
			) is
		-- Create and matches against a criteria using the criteria registry
		Criteria : Criteria_Type'Class := Criteria_Registry.Create_Criteria( Name, Descriptor );
	begin
		for i in Contexts'Range loop
			Add_Context( Criteria, Contexts( i ) );
		end loop;
		Require( Criteria, User );
	exception
		when e: ACCESS_DENIED =>
			if Is_Anonymous( User ) then
				raise LOGIN_REQUIRED with "was ACCESS_DENIED with " & Ada.Exceptions.Exception_Message( e );
			else
				Ada.Exceptions.Reraise_Occurrence( e );
			end if;
	end Require;

	-----------------------
	-- Criteria Registry --
	-----------------------


	protected body Criteria_Registry is
		--  we created a protected type here so our code is task-safe.
		procedure Register( Factory : in Criteria_Factory_Type ) is
			-- Register a criteria based on it's name.
			-- If there is another criteria with the same name,
			-- raises Duplicated_Criteria
		

			D	: Criteria_Descriptor;
			Name	: Criteria_Name := To_Unbounded_String( Get_Name( Factory.all( D ) ) );
		begin
			if Criteria_Maps.Contains( Map, Name ) then
				raise DUPLICATED_CRITERIA with "Name: " & To_String( Name );
			end if;

			Criteria_Maps.Insert( Map, Name, Factory );
		end Register;

		procedure Unload( Name : in Criteria_name ) is
			-- remove this criteria from the registry.
		begin
			if Criteria_Maps.Contains( Map, Name ) then
				Criteria_Maps.Delete( Map, Name );
			end if;

			raise INVALID_CRITERIA with "Can't unload " & To_String(Name);
		end Unload;


		procedure Empty_Criteria_Registry is
			-- used to unload all the criterias from the registry.
		begin
			Criteria_Maps.Clear( Map );
		end Empty_Criteria_Registry;


		function Create_Criteria(
					Name		: in Criteria_Name; 
					Descriptor	: in Criteria_Descriptor
			) return Criteria_Type'Class is
		-- create a new criteria object from an already registered criteria type
		-- based on it's name and the given Descriptor.
		-- if there is no such criteria, raises INVALID_CRITERIA
			Factory: Criteria_Factory_Type;
		begin
			if not Criteria_Maps.Contains( Map, Name ) then
				raise INVALID_CRITERIA with "Can't create " & To_String(Name);
			end if;

			Factory := Criteria_Maps.Element( Map, Name );

			return Factory.all( Descriptor );
		end Create_Criteria;

	end Criteria_Registry;









begin

	Anonymous_User_Identity := MD5_Sign( "anonymous" );
end KOW_Sec;
