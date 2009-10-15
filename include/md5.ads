-- Filename        : md5.ads
-- Description     :
-- Author          : Rolf Ebert
-- Created On      : Tue Mar 25 20:06:55 1997
-- Last Modified By: Rolf Ebert
-- Last Modified On: Wed Jun  4 21:37:28 1997
-- Update Count    : 24
-- Status          : Unknown, Use with caution!
-- $Revision$
-- $Name$

package MD5 is

   type Byte is mod 2**8;
   type Byte_Array is array (Long_Integer range <>) of Byte;
   pragma Pack (Byte_Array);

   subtype Fingerprint is Byte_Array (1 .. 16);

   subtype Digest_String is String (1 .. 32);

   Malformed : exception;

   function Digest_From_Text (S : in Digest_String) return Fingerprint;

   function Digest_To_Text (A : in Fingerprint) return Digest_String;

   type Context is private;

   procedure Init (Ctx : in out Context);

   procedure Update
     (Ctx  : in out Context;
      Data : in     Byte_Array);

   procedure Update
     (Ctx  : in out Context;
      Data : in     String);

   procedure Final (Ctx : in out Context; Digest : out Fingerprint);



   function Calculate( Str : in String ) return Digest_String;


private

   type Word is mod 2**32;
   type Word_Array is array (Long_Integer range <>) of Word;
   pragma Pack (Word_Array);

   function Rotate_Left (Value : in Word; Amount : in Natural) return Word;
   pragma Import (Intrinsic, Rotate_Left);

   function Shift_Left (Value : in Word; Amount : in Natural) return Word;
   pragma Import (Intrinsic, Shift_Left);

   function Shift_Right (Value : in Word; Amount : in Natural) return Word;
   pragma Import (Intrinsic, Shift_Right);

   subtype ABCD_State is Word_Array (1 .. 4);
   subtype Count_T    is Word_Array (1 .. 2); -- long_integer ??

   subtype Buffer_T   is Byte_Array (1 .. 64);

   type Context is record
      State  : ABCD_State := (1 => 16#67452301#,
                              2 => 16#Efcdab89#,
                              3 => 16#98badcfe#,
                              4 => 16#10325476#);
      Count  : Count_T    := (1 => 0,
                              2 => 0);
      Buffer : Buffer_T   := (others => 0);
   end record;

end MD5; 
