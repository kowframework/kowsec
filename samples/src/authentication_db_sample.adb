------------------------------------------------------------------------------
--                                                                          --
--                          Ada Works :: Security                           --
--                                                                          --
--                                Ada Works                                 --
--                                                                          --
--                                 B o d y                                  --
--                                                                          --
--               Copyright (C) 2007-2009, Ada Works Project                 --
--                                                                          --
--                                                                          --
-- Aw_Sec is free software; you can redistribute it  and/or modify it under  --
-- terms of the  GNU General Public License as published  by the Free Soft- --
-- ware  Foundation;  either version 2,  or (at your option) any later ver- --
-- sion. AwSec is distributed in the hope that it will be useful, but WITH- --
-- OUT ANY WARRANTY;  without even the  implied warranty of MERCHANTABILITY --
-- or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License --
-- for  more details.  You should have  received  a copy of the GNU General --
-- Public License distributed with Aw_Sec; see file COPYING.  If not, write  --
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

------------------------------------------------------------------------------
-- This is a Aw_Sec.Authentication.DB Example.                              --
------------------------------------------------------------------------------

with Ada.Text_IO;
with Ada.Exceptions;	use Ada.Exceptions;

with Aw_Sec.Authorization_Criterias;
with Aw_Sec.Authentication.DB;	use Aw_Sec.Authentication.DB;

with Ada.Text_IO; 		use Ada.Text_IO;

with Aw_Sec;			use Aw_Sec;
with Ada.Containers.Vectors;


with APQ;		use APQ;
with APQ.MySQL;
with APQ.MySQL.Client;

procedure Authentication_DB_Sample is


	subtype AM is Aw_Sec.Authentication.DB.Authentication_Manager;


	Connection : Connection_Access := new Apq.MySQL.Client.Connection_Type; 
	Another_Connection : Connection_Access := new Apq.MySQL.Client.Connection_Type; 


	Manager: Aw_Sec.Authentication_Manager_Access := new AM'(New_Authentication_Manager( Connection ) );
	Another_Manager: Aw_Sec.Authentication_Manager_Access := new AM'(New_authentication_Manager( Another_Connection ) );
--		new AM'(New_Manager(Aw_Sec.Authentication.DB.Authentication_Manager;
	
begin

	-- Setup the database connection:
	--
	Set_Host_Name( Connection.all, "localhost" );
	Set_User_Password( Connection.all, "root", "senharoot" );
	Set_DB_Name( Connection.all, "aw_sec_samples" );
	Set_Case( Connection.all, Preserve_Case );
	Connect( Connection.all );


	Set_Host_Name( Another_Connection.all, "localhost" );
	Set_User_Password( Another_Connection.all, "root", "senharoot" );
	Set_DB_Name( Another_Connection.all, "aw_sec_samples_another_db" );
	Set_Case( Another_Connection.all, Preserve_Case );
	Connect( Another_Connection.all );



	-- Setup the Manager
	Set_Users_Table(
		AM( Manager.all ),
		"Users" );

	Set_Username_Field(
		AM( Manager.all ),
		"Username" );

	Set_Password_Field(
		AM( Manager.all ),
		"Password" );

	Set_First_Name_Field(
		AM( Manager.all ),
		"First_Name" );

	Set_Last_Name_Field(
		AM( Manager.all ),
		"Last_Name" );

	Set_Groups_Table(
		AM( Manager.all ),
		"Groups" );

	Set_Groups_Username_Field(
		AM( Manager.all ),
		"Username" );
	
	Set_Group_Name_Field(
		AM( Manager.all ),
		"Group_Name" );



	Set_Users_Table(
		AM( Another_Manager.all ),
		"Users" );

	Set_Username_Field(
		AM( Another_Manager.all ),
		"Username" );

	Set_Password_Field(
		AM( Another_Manager.all ),
		"Password" );

	Set_First_Name_Field(
		AM( Another_Manager.all ),
		"First_Name" );

	Set_Last_Name_Field(
		AM( Another_Manager.all ),
		"Last_Name" );

	Set_Groups_Table(
		AM( Another_Manager.all ),
		"Groups" );

	Set_Groups_Username_Field(
		AM( Another_Manager.all ),
		"Username" );
	
	Set_Group_Name_Field(
		AM( Another_Manager.all ),
		"Group_Name" );


	-- Register the manager:
	Register_Manager( Manager );
	Register_Manager( Another_Manager );


	declare

		procedure Test_Aw_Sec( Username,Password: in String; iterations: positive := 4 ) is

			Users_Criteria_Name		: Criteria_Name := To_Criteria_Name("USERS");
			Users_Criteria_Descriptor	: Criteria_Descriptor :=
				To_Criteria_Descriptor("(adele|Ogro)&!(vandick|user_ba.ba-ca)");
			
			Groups_Criteria_Name		: Criteria_Name := To_Criteria_Name("GROUPS");
			Groups_Criteria_Descriptor	: Criteria_Descriptor :=
				To_Criteria_Descriptor("(dev|admin)&!design");
			
			Expressions_Criteria_Name	: Criteria_Name := To_Criteria_Name("EXPRESSIONS");
			Expressions_Criteria_Descriptor	: Criteria_Descriptor :=
				To_Criteria_Descriptor("USERS={(adele|OgRo)&!alex}&GROUPS={!design&(dev|admin)}");

			My_Acc: Accountant_Access := new Accountant'(New_Accountant( Username & "_login" ));

			User_Object: aliased Aw_Sec.User'Class := Aw_Sec.Do_Login( Username, Password, My_Acc );
			-- if the login fails an exception should be raised...
			
			User_Object_Access: User_Access := User_Object'Unchecked_Access;
	
			Groups: Authorization_Groups;
			Group: Authorization_Group;
			
			use Authorization_Group_Vectors;
			
			C: Authorization_Group_Vectors.Cursor;
			
			
			procedure Fetch_Groups is
			begin
				Put_Line( "Fetching my groups ... " );
					
				Aw_Sec.Get_Groups( User_Object, Groups );
				
				C := Authorization_Group_Vectors.First( Groups );
					
				while Has_Element (C) = true
				loop
					Group := Element( C );
						
					Put_Line( "   * " & To_String( Group ) );
						
					C := Next( C );
				end loop;
			end Fetch_Groups;
			
			
			
		begin
				
			Set_Groups_Timeout( User_Object, 10.0 );
				
			Put_Line( "I managed to login into this user account:" );
				
			Put_Line( "Username  : " & Identity( User_Object ) );
			Put_Line( "Real Name : " & Full_Name( User_Object ) );
				
				
--			declare
--				task task1;
--				task task2;
--				task body task1 is
--				begin
--					loop
--						Fetch_Groups;
--						delay 1.0;
--					end loop;
--				end task1;
--				task body task2 is
--				begin
--					loop
--						Fetch_Groups;
--						delay 2.0;
--					end loop;
--				end task2;
			begin
				for i in 1 .. iterations loop
					Fetch_Groups;
					delay 1.0;
				end loop;
			end;

			begin
				Aw_Sec.Require(	User_Object	=> User_Object_Access,
						Name		=> Users_Criteria_Name,
						Descriptor	=> Users_Criteria_Descriptor,
						Root_Accountant	=> My_Acc); 
			exception
				when E: ACCESS_DENIED =>
					Put_Line(Exception_Information( E ) );
			end;
		
			begin
				Aw_Sec.Require(	User_Object	=> User_Object_Access,
						Name		=> Groups_Criteria_Name,
						Descriptor	=> Groups_Criteria_Descriptor,
						Root_Accountant	=> My_Acc); 
			exception
				when E: ACCESS_DENIED =>
					Put_Line(Exception_Information( E ) );
			end;
			
			
			begin
				Aw_Sec.Require(	User_Object	=> User_Object_Access,
						Name		=> Expressions_Criteria_Name,
						Descriptor	=> Expressions_Criteria_Descriptor,
						Root_Accountant	=> My_Acc); 
			exception
				when E: ACCESS_DENIED =>
					Put_Line(Exception_Information( E ) );
			end;
					
		end Test_Aw_Sec;
	begin
		Test_Aw_Sec( "OgRo", "passworded" );
		Test_Aw_Sec( "adele", "passworded" );
	end;

end Authentication_DB_Sample;
