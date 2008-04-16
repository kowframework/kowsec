
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


	procedure Set_Groups_Timeout( User_Object: in out User; New_Timeout: in Duration ) is
	        -- set the timeout of the groups cache for this user
	begin
		User_Object.Groups.Set_timeout( New_Timeout );
	end Set_Groups_Timeout;

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

	
	procedure Get_Groups( User_object: in User'Class; Groups: in out Authorization_Groups ) is
	-- Get the groups for this user.
	-- There are two things to notice here:
	-- 	1. This method is task safe. It means it will never return something
	--	 while the user's group list is being generated.
	--	2. The user's group is auto-updated by using the methods:
	--		. Set_Groups_Timeout( User, Duration);
	--		. Update_Groups( User );


	begin
		Check_Anonymous_Access( User_Object, "Get_Groups" );

		-- Notice:
		-- According Ada2005 RM the Vector needs finalization.
		-- For this reason we don't deallocate the memory here.

		Groups := User_Object.Groups_Cache.Get_Groups;
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





	-- PRIVATE --

	protected body Groups_Cache_Type is 
		function Should_Update return Boolean is
		begin
			if
				Authorization_Groups = NULL	OR
				Need_Update = true		OR
				(
					Timeout /= 0.0 AND THEN 
					Last_Update < (Now - Timeout)
				)
			then
				return true;
		 	else 
		 		return_code := false;
		 	end if;
		
		end Should_Update;
		
		procedure Update( User_Object: in User'Class; Managers: in Authorization_Managers ) is
			-- update the groups and then set:
			-- 	need_update := false
			-- 	last_update := now

			Empty: Authorization_Groups(1 .. 0);
			-- it's used when there is nothing to be returned from Groups.
			
			procedure Free is new Unchecked_Deallocation(
				Object	=> Authorization_Groups
				);


			function Iterate( i: in Integer ) return Authorization_Groups is
				My_Groups := Get_Groups( Managers(i).all, User_Object );
				Next: Integer := I + 1;
			begin
				if Next <= Managers'Last then
					declare
						Next_Groups: Authorization_Groups := Iterate( Next );
					begin
						if Next_Groups'Length > 0 then
							if My_Groups'Length > 0 then
								return My_Groups & Next_Groups;
							else
								return Next_Groups;
							end if;
						end if;
					end;
				end if;

				return My_Groups;
				-- If it hasn't fetched anything from the next groups
				-- return the current groups list.
			end Iterate;
		begin

			Check_Anonymous_Access( User_Object, "Groups_Cache_Type.Update" );

			Free( Groups );

			-- notice we don't check if the user is anonymous
			-- it's due the check if

			if Managers'Length = 0 then
				return; -- there is nothing to be feched if manager is null
			end if;


			-- now we try to fetch the groups information for
			-- the current user:
			declare
				My_Groups : Authorization_Groups := Iterate ( Managers'First );
			begin
				if My_Groups'Length /= 0 then
					Groups := new Authorization_Groups( 1 .. My_Groups'Length );
					Groups.all := My_Groups;
				end if;
			end;

			-- if the update has been a success, then..
			Need_Update := False;
			Last_Update := Now;
		end Update;

		function Get_Groups return Authorization_Groups is
			-- checks if the groups should be update
			-- 	if true, do the update
			-- 	if false, don't update.
			-- return the current groups list
			Empty: Authorization_Groups( 1 .. 0 );
		begin
		end Get_Groups;

		procedure Set_Update is
			-- tell this cache it should be updated in the next call
			-- of Get_Groups.
		begin
			Need_Update := True;
		end Set_Update;
		
		procedure Set_Timeout( New_Timeout: in Duration ) is
		begin
			Timeout := New_Timeout;
		end Set_Timeout;
	end Groups_Cache_Type;

end Aw_Sec;
