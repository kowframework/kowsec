
package body Aw_Sec is

	procedure Check_Anonymous_Access( User_Object: in User; Where: in String ) is
	begin
		if Is_Anonymous( User_Object ) then
			raise ANONYMOUS_ACCESS
				with 
					"Can't get information from anonymous user [" &
					Where &
					"]";
		end if;
	end Check_Anonymous_Access;

	procedure Update_Groups( User_Object: in out User ) is
		-- Tells the user that his groups should be updated in the
		-- next request to Get_Groups.
	begin
		User_Object.Groups_Cache.Set_Update;
	end Update_Groups;


	function Identity( User_Object: in User ) return String is
		-- Return a string identifying the current user. Usually it's the username
		-- but one could implement other methods, such as a numeric id for this user
	begin
		return To_String( User_Object.Username );
	end Identity;


	function Full_Name(	User_Object	: in User;
				Locale		: Aw_Lib.Locales.Locale
					:= Aw_Lib.Locales.Default_Locale
		) return String is
		-- return the full name for this user, respecting the locale's conventions
	begin
		Check_Anonymous_Access( User_Object, "Full_Name" );
		return Aw_Lib.Locales.Format_Full_Name(
			Locale		=> Locale,
			First_Name	=> To_String( First_Name ),
			Last_Name	=> To_String( Last_Name )
			);
	end Full_Name;

	
	function Get_Groups( User_object: in User'Class ) return Authorization_Groups is
	-- Get the groups for this user.
	-- There are two things to notice here:
	-- 	1. This method is task safe. It means it will never return something
	--	 while the user's group list is being generated.
	--	2. The user's group is auto-updated by using the methods:
	--		. Set_Groups_Timeout( User, Duration);
	--		. Update_Groups( User );


	begin
		Check_Anonymous_Access( User_Object, "Get_Groups" );
		return User_Object.Groups_Cache.Get_Groups;
	end Get_Groups;

	function Is_Anonymous(	User_Object: in User ) return Boolean is
	-- Return true if this user isn't logged in.
	-- 
	-- Even though this isn't an abstract method, one can overwrite it
	-- in order to log hits from anonymuos users when using determined Manager.
		Username: String := To_String( User_Object.Username );
	begin
		if Username'Length = 0  OR Username = Anonymous_Username then
			return true;
		else
			return false;
		end if;
	end Is_Anonymous;

	procedure Do_Logout( User_Object: in out User ) is
	-- Not only make sure the user is logged out but also
	-- Make sure Is_Anonymous returns true for now on for this user.
		Null_String := To_Unbounded_String( "" );
	begin
		User.Username := Anonymous_Username;
		User.First_Name := Null_Unbounded_String;
		User.Last_Name := Null_Unbounded_String;

		-- there is no need to clear the user's cache
		-- as Get_Groups always checks if it's an anonymous user or not.
		--
		--
		-- TODO: implement something to clear this cache in order to
		-- recycle the memory
	end Do_Logout;

end Aw_Sec;
