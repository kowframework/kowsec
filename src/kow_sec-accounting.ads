

--------------
-- Ada 2005 --
--------------
with Ada.Finalization;
with Ada.Strings.Unbounded;		use Ada.Strings.Unbounded;

-------------------
-- KOW Framework --
-------------------


package KOW_Sec.Accounting is
	-----------------
	-- EXIT STATUS --  
	-----------------

	type Exit_Status is (
			EXIT_NULL,	-- there is no exit status defined yet.
			EXIT_SUCCESS,	-- no error at all in the exit status	
			EXIT_WARNING,	-- the action has exited with some minor warning
			EXIT_ERROR, 	-- the action has exited with error
			EXIT_FATAL	-- the action has ended in a fatal error!
		);


	for Exit_Status use (
			EXIT_NULL	=> 2#0000#,
			EXIT_SUCCESS	=> 2#0001#, 
			EXIT_WARNING	=> 2#0010#,
			EXIT_ERROR	=> 2#0100#,
			EXIT_FATAL	=> 2#1000#
		);

	STATUS_CONFLICT: Exception;
	-- Raised when one try to change the exit status while it
	-- has already been defined this is so in order to force the 
	-- developer to use Actions to represent only
	-- small pieces of the code...
	--
	-- Usualy, if you need to set more than one exit status you can split your
	-- action in two other tasks.



	----------------------
	-- ACCOUNTANT TYPES --
	----------------------

	type Path_Array is Array( Natural range<> ) of Unbounded_String;
	
	--
	-- the accountant type
	--
	type Accountant_Type is new Ada.Finalization.Limited_Controlled with private;
	-- The Accountant should be overwritten by anyone willing to extend the
	-- Accounting Management schema of KOW_Sec.
	--
	-- There is a basic implementation avaliable in this package that outputs
	-- the messages to stdout and stderr.


	type Accountant_Access is access all Accountant_Type'Class;
	-- All references to accountants are made using this type.
	
	
	-------------
	-- ACTIONS --
	-------------
	
	--
	-- the base_action type
	--
	type Base_Action_Type is abstract new Ada.Finalization.Limited_Controlled with private;
	-- When creating your own action type, please extend this type otherwise your
	-- code won't run as expected (as the finalization is responsible for logging the
	-- action)
	--
	-- See type action for more information.


	function New_Action(
				Name		: in String;
				Root_Accountant	: in Accountant_Access;
				User	: in User_Data_Type
			) return Base_Action_Type'Class is abstract;
	-- This method should be used by the constructor and never be overrided.
	-- It will initialize the common attributes to all action types.
	--
	-- The action implementor should provide a New_Action method 
	-- as a constructor using this Make_Action here.
	
	procedure Set_Exit_Status(
				Action		: in out Base_Action_Type;
				Status		: in     Exit_Status;
				Message		: in     String
			);
	-- Set the exit status and a message describing what hapenned.
	-- Raise STATUS_CONFLICT when the status has been already defined 
	-- or EXIT_NULL is passed as parameter
	-- If the status is EXIT_FATAL, then FATAL_ERROR exception is raised.
	-- As the action is Limited_Controlled, when deallocated it will log the error.


	function Name( Action: in Base_Action_Type ) return String;

	--
	-- the action type
	--
	type Action_Type is new Base_Action_Type with private;
	-- An action is any small and localized task that can be performed by the system.  -- The action controlls:
	-- 	* when the task (not as in paralel computing!) has been started
	-- 	* which user, if any, is responsible for triggering this action
	--	* when the task has been completed
	--	* the exit status and message of the task.
	--
	-- This information is then delegated for logging by the Action's root accountant.
	-- This accountant then decides where and how to send it.
	--
	-- The accountant can then delegate the logging 
	-- for it's root accountant and so on...
	-- till it reaches the root accountant of all accountants.
	--
	-- You must specify what's the root accountant for every action, even when you
	-- already have your own root accountant.
	--
	-- Now, for the accountant, if you don't specify any root it understands you meant
	-- to use the KOW_Sec.Root_Acc instance.

	
	function New_Action(
				Name		: in String;
				Root_Accountant : in Accountant_Access;
				User		: in User_Data_Type
			) return Action_Type;
	-- Used to create a new action which's root is Root_Accountant
	-- Should be used as a constructor.
	--
	-- It's mandatory to use constructors in order to initialize your actions.

	

	Root_Acc: Accountant_Access;
	-- The root acc is initialized by the static code part of the body.
	-- It's not a constant because of the network topology proposed by AdaWorks.
	-- See KOW_Dist.Accountant for more details.



	---------------------------
	-- Accounting Management --
	---------------------------

	function New_Accountant(
				Service	: in String;
				Root	: in Accountant_Access := Root_Acc
		) return Accountant_Type;
	-- This is the constructor for accountants.
	-- It's far preferable to use constructors instead
	-- of simply instantiate the type.


	function Service( Accountant : in Accountant_Type ) return Unbounded_String;
	-- Gets the current service name
	-- The service name is a string representing the accountant.
	
	function Service( Accountant : in Accountant_Type ) return String;
	-- same as the Service() return unbounded_string

	procedure Flush( Accountant : in out Accountant_Type );
	-- Flushes the current acountant.


	procedure Delegate(
				To_Accountant	: in out Accountant_Type;
				Child		: in     Base_Action_Type'Class
			);
	-- Called to log a child action
	
	procedure Delegate(
				To_Accountant	: in out Accountant_Type;
				Relative_Path	: in Path_Array;
				Child		: in Base_Action_Type'Class
			);
	-- delegates the action to from the child accountant to the to_accountant.
	-- Relative_path is the relative path from the to_accountant to it's child.
	-- For instance:
	-- 	Acc1->Acc2->Action1
	-- If Acc2 delegates Action1 to Acc2, it'll call:
	-- 	Delegate(	To_Accountant	=> Acc1,
	-- 			Relative_Path	=> ( Service( Acc2 ) ),
	-- 			Child		=> Action1 );



	

	-----------------------------------
	-- CLASSWIDE METHODS DECLARATION --
	-----------------------------------

	----------------------------------------
	-- User Management - accounting aware --
	----------------------------------------
	function Do_Login(
				Manager:	 in Authentication_Manager_Interface'Class;
				Username:	 in String;
				Password:	 in String;
				Root_Accountant: in Accountant_Access
			) return User_Identity_Type;
	-- This function logs any error returned by Do_Login method
	-- As it's a class wide function, it dynamic dispatching is enabled
	-- for both Authentication_Manager and Accountant types

	function Do_Login(
				Username	: in String;
				Password	: in String;
				Root_Accountant	: in Accountant_Access
			) return User_Identity_Type;

	-------------------------------------------------
	-- Authorization Management - accounting aware --
	-------------------------------------------------


	procedure Require(
				Criteria 	: in out Criteria_Interface'Class; 
				User		: in     User_Type;
				Root_Accountant : in     Accountant_Access
			);
	-- matches the user against some criteria.
	-- raise ACCESS_DENIED if the user fails this criteria.
	-- logs any error that might occur using the root_accountant


	procedure Require(
				Name		: in     Criteria_Name;
				Descriptor	: in     Criteria_Descriptor;
				User		: in     User_Type;
				Root_Accountant	: in     Accountant_Access
			);
	-- matches the user against some criteria that's created at run time.
	-- raises 
	-- 	ACCESS_DENIED if the user fails this criteria.
	-- 	INVALID_CRITERIA if trying to create a criteria that isn't registered
	-- 	INVALID_CRITERIA_DESCRIPTOR if the descriptor is invalid for this criteria
	-- logs any erro that might occur using the root_accountant


private
	type Accountant_Type is new Ada.Finalization.Limited_Controlled with record
		Creation_Time	: Time := Ada.Calendar.Clock;
		Service		: Unbounded_String := To_Unbounded_String("/");
		Root		: Accountant_Access := Root_Acc;
	end record;

	type Base_Action_Type is new Ada.Finalization.Limited_Controlled with record
		Name		: Unbounded_String;
		Creation_Time	: Time;
		User		: User_Data_Type;
		Status		: Exit_Status;
		Message		: Unbounded_String;
		Root_Accountant	: Accountant_Access;
	end record;


	type Action_Type is new Base_Action_Type with null record;

	overriding
	procedure Finalize( A: in out Action_Type );
	-- used to flush the action.

end KOW_Sec.Accounting;
