


-------------------------------------
-- Management of User's Attributes --
-------------------------------------



with Ada.Strings.Unbounded;		use Ada.Strings.Unbounded;

package KOW_Sec.Attributes is


	type Attribute_Data_Type is( String_Attribute, Integer_Attribute );

	type Attribute_Type is record
		Name		: Unbounded_String;
		Data_Type	: Attribute_Data_Type;

		String_Data	: Unbounded_String;
		Integer_Data	: Integer;
	end record;


end KOW_Sec.Attributes;
