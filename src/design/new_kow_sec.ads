


package New_KOW_Sec is

	type User_Attribute_Type is ( Info_Authentication, Info_Groups, Info_Roles, Info_Extra );

	type User_Attribute_Array is array( positive range <> ) of User_Attribute_Type;


	function "&"( L,R : User_Attribute_Array ) return User_Attribute_Array is
		Result : User_Attribute_Array( 1 .. L'Length + R'Length );
		Last: Positive := L'Length;

		function Doesnt_Exist( Element : User_Attribute_Type ) return Boolean is
		begin
			for i in L'Range loop
				if Element = L( i ) then
					return false;
				end if;
			end loop;
			return true;
		end Doesnt_Exist;
	begin
		Result( 1 .. L'Length ) := L;
		for i in R'range loop
			if Doesnt_Exist( R( i ) ) then
				Last := Last + 1;
				Result( Last ) := R( i );
			end if;
		end loop;

		return Result( 1 .. Last );
	end "&";

	function To_Array( Item : in User_Attribute_Type ) return User_Attribute_Array is
	begin
		return User_Attribute_Array'(1 => Item );
	end To_Array;
	
	function "&"(L,R : User_Attribute_Type ) return User_Attribute_Array is
	begin
		return To_Array( L ) & To_Array( R );
	end "&";

	function "&"( L : User_Attribute_Array; R : User_Attribute_Type ) return User_Attribute_Array is
	begin
		return L & To_Array( R );
	end "&";




	type Authentication_Manager is tagged null record;


	function authenticate( Manager : in Authentication_Manager; Variables : in JSon_Object ) return String;
	-- authenticate returning the user identity.. 


	type Group_Type is record
		Identity		: String;
	end record;

	type User_Type is record
		Identity		: String;	-- a hash that identifies the user internally
		Nickname		: String;	-- how the user want's to be called
		First_Name		: String;	-- his real first name
		Last_Name		: String;	-- his real last name
		Email			: String;	-- his email address


		Authentication_Manager	: Authentication_Manager_Access;	-- The authentication manager that has authenticated this very session
		Groups_Cache		: Groups_Stuff;
	end record;



	type user_profile is record
		User_Identity		: String;
		Profile_Identity	: String;

		Variables		: Table;
	end record;


	type variable is record
		the_name		: String;
		data_type		: Supported_Types;
		Editable		: Boolean;

		The_Value		: Variable_Storage;
	end record;



	function get_user_profile( User_identity, Profile_Identity : in String ) return User_Profile;
	procedure Store_user_Profile( Profile : in User_Profile );

	procedure get_user_profile



	function Get_Authentication_Managers( User : in User_Type ) return Authentication_Manager_Array;
	-- return the known authentication managers

end New_KOW_Sec;
