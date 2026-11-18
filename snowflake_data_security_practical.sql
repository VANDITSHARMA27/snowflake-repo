/*
===============================================================================
SNOWFLAKE LEARNING - DATA SECURITY PRACTICAL
Topics:
  1. Dynamic Data Masking for email addresses
  2. User-to-direction access mapping
  3. Column masking for direction-based access (all rows remain visible)
  4. Testing with ACCOUNTADMIN and ANALYST
  5. Optional display view that shows **** instead of NULL for masked amounts

IMPORTANT:
  - Run this script in Snowflake Snowsight, from top to bottom.
  - This is a DEMO script. CREATE OR REPLACE TABLE rebuilds the demo tables
    and deletes their previous contents.
  - Replace SOUTH_MANAGER and EAST_MANAGER with real Snowflake usernames.
  - The script assumes your Snowflake username is VANDIT1SHARMA.
  - ACCOUNTADMIN sees unmasked values. Other users see only their own
    direction's amount; all directions/rows remain visible.
===============================================================================
*/


-- ============================================================================
-- SECTION 1: DATABASE, SCHEMA, ROLE, AND BASIC PERMISSIONS
-- ============================================================================

USE ROLE ACCOUNTADMIN;

CREATE DATABASE IF NOT EXISTS DEMO_DATA;
USE DATABASE DEMO_DATA;
USE SCHEMA PUBLIC;

CREATE ROLE IF NOT EXISTS ANALYST;

-- Give ANALYST access to the database and schema.
GRANT USAGE ON DATABASE DEMO_DATA TO ROLE ANALYST;
GRANT USAGE ON SCHEMA DEMO_DATA.PUBLIC TO ROLE ANALYST;

-- Assign the ANALYST role to your Snowflake user.
-- Run this as ACCOUNTADMIN.
GRANT ROLE ANALYST TO USER VANDIT1SHARMA;


-- ============================================================================
-- SECTION 2: DYNAMIC DATA MASKING - EMAIL ADDRESS
-- Requirement:
--   Show the first 2 characters of the username.
--   Replace every remaining username character with the same number of '*'.
--   Keep the complete domain after @ visible.
--
-- Examples:
--   amit@gmail.com       -> am**@gmail.com
--   manav@yahoo.com      -> ma***@yahoo.com
--   chavi@outlook.com    -> ch***@outlook.com
--   alexander@gmail.com  -> al*******@gmail.com
--
-- ACCOUNTADMIN sees the original email.
-- Other roles see the masked email.
-- ============================================================================

CREATE OR REPLACE TABLE CUSTOMERS (
    ID NUMBER,
    NAME STRING,
    EMAIL STRING
);

INSERT INTO CUSTOMERS (ID, NAME, EMAIL) VALUES
    (1, 'amit',  'amit@gmail.com'),
    (2, 'manav', 'manav@yahoo.com'),
    (3, 'chavi', 'chavi@outlook.com'),
    (4, 'alex',  'alexander@gmail.com');

-- Create or replace the email masking policy.
CREATE OR REPLACE MASKING POLICY DEMO_DATA.PUBLIC.EMAIL_MASK
    AS (VAL STRING)
    RETURNS STRING ->
        CASE
            WHEN CURRENT_ROLE() = 'ACCOUNTADMIN'
                THEN VAL
            ELSE
                LEFT(SPLIT_PART(VAL, '@', 1), 2)
                ||
                REPEAT(
                    '*',
                    GREATEST(LENGTH(SPLIT_PART(VAL, '@', 1)) - 2, 0)
                )
                ||
                '@'
                ||
                SPLIT_PART(VAL, '@', 2)
        END;

-- Attach the policy to the EMAIL column.
ALTER TABLE DEMO_DATA.PUBLIC.CUSTOMERS
    MODIFY COLUMN EMAIL
    SET MASKING POLICY DEMO_DATA.PUBLIC.EMAIL_MASK;

-- Allow ANALYST to read the customer table.
GRANT SELECT ON TABLE DEMO_DATA.PUBLIC.CUSTOMERS TO ROLE ANALYST;

-- Test as ACCOUNTADMIN: original emails should be visible.
USE ROLE ACCOUNTADMIN;
SELECT CURRENT_USER() AS CURRENT_USER, CURRENT_ROLE() AS CURRENT_ROLE;
SELECT * FROM DEMO_DATA.PUBLIC.CUSTOMERS;

-- Test as ANALYST: emails should be dynamically masked.
USE ROLE ANALYST;
SELECT CURRENT_USER() AS CURRENT_USER, CURRENT_ROLE() AS CURRENT_ROLE;
SELECT * FROM DEMO_DATA.PUBLIC.CUSTOMERS;


-- ============================================================================
-- SECTION 3: USER-TO-DIRECTION MAPPING TABLE
-- Requirement:
--   NORTH manager: NORTH amount visible; SOUTH and EAST amounts masked.
--   SOUTH manager: SOUTH amount visible; NORTH and EAST amounts masked.
--   EAST manager: EAST amount visible; NORTH and SOUTH amounts masked.
--   ACCOUNTADMIN: all amounts visible.
--
-- IMPORTANT:
--   CURRENT_USER() identifies the logged-in Snowflake user.
--   It is NOT the same as CURRENT_ROLE().
--   Replace the example manager usernames below with real Snowflake usernames.
-- ============================================================================

USE ROLE ACCOUNTADMIN;

CREATE OR REPLACE TABLE DEMO_DATA.PUBLIC.USER_ACCESS (
    USER_NAME STRING,
    DIRECTION STRING
);

INSERT INTO DEMO_DATA.PUBLIC.USER_ACCESS (USER_NAME, DIRECTION) VALUES
    ('VANDIT1SHARMA', 'NORTH'),
    ('SOUTH_MANAGER', 'SOUTH'),  -- Replace with the real South manager username.
    ('EAST_MANAGER',  'EAST');   -- Replace with the real East manager username.


-- ============================================================================
-- SECTION 4: EMPLOYEE SALES TABLE
-- There are four columns:
--   ID, EMPLOYEE_NAME, DIRECTION, AMOUNT
--
-- Unlike a ROW ACCESS POLICY, the masking policy below does NOT remove rows.
-- Every manager can see NORTH, SOUTH, and EAST rows.
-- Only the AMOUNT value is masked when the row belongs to another direction.
-- ============================================================================

CREATE OR REPLACE TABLE DEMO_DATA.PUBLIC.EMPLOYEE_SALES (
    ID NUMBER,
    EMPLOYEE_NAME STRING,
    DIRECTION STRING,
    AMOUNT NUMBER
);

INSERT INTO DEMO_DATA.PUBLIC.EMPLOYEE_SALES
    (ID, EMPLOYEE_NAME, DIRECTION, AMOUNT)
VALUES
    (1, 'Amit',  'NORTH', 5000),
    (2, 'Manav', 'SOUTH', 7000),
    (3, 'Chavi', 'EAST',  3000),
    (4, 'Rahul', 'NORTH', 9000),
    (5, 'Priya', 'SOUTH', 6000),
    (6, 'Karan', 'EAST',  4000);


-- ============================================================================
-- SECTION 5: DIRECTION-BASED MASKING POLICY
--
-- The policy receives TWO values:
--   VAL = the AMOUNT in the current row
--   DIR = the DIRECTION in the current row
--
-- Logic:
--   1. ACCOUNTADMIN gets the original amount.
--   2. If USER_ACCESS contains the current user and this row's direction,
--      show the original amount.
--   3. Otherwise return NULL to mask the numeric amount.
--
-- Why NULL?
--   AMOUNT is a NUMBER column, so the masking policy returns NUMBER.
--   A NUMBER masking policy cannot return the text '****'.
--   An optional view in Section 7 displays **** for these NULL values.
-- ============================================================================

CREATE OR REPLACE MASKING POLICY DEMO_DATA.PUBLIC.AMOUNT_MASK
    AS (VAL NUMBER, DIR STRING)
    RETURNS NUMBER ->
        CASE
            WHEN CURRENT_ROLE() = 'ACCOUNTADMIN'
                THEN VAL

            WHEN EXISTS (
                SELECT 1
                FROM DEMO_DATA.PUBLIC.USER_ACCESS AS A
                WHERE UPPER(A.USER_NAME) = UPPER(CURRENT_USER())
                  AND UPPER(A.DIRECTION) = UPPER(DIR)
            )
                THEN VAL

            ELSE NULL
        END;

-- Attach the two-argument masking policy to AMOUNT.
-- USING maps the policy arguments to table columns:
--   VAL receives AMOUNT
--   DIR receives DIRECTION
ALTER TABLE DEMO_DATA.PUBLIC.EMPLOYEE_SALES
    MODIFY COLUMN AMOUNT
    SET MASKING POLICY DEMO_DATA.PUBLIC.AMOUNT_MASK
    USING (AMOUNT, DIRECTION);

-- Give ANALYST permission to read the employee sales table.
GRANT SELECT ON TABLE DEMO_DATA.PUBLIC.EMPLOYEE_SALES TO ROLE ANALYST;


-- ============================================================================
-- SECTION 6: TEST DIRECTION-BASED MASKING
-- ============================================================================

-- Test as ACCOUNTADMIN: all amounts should be visible.
USE ROLE ACCOUNTADMIN;
SELECT * FROM DEMO_DATA.PUBLIC.EMPLOYEE_SALES;

-- Test as your user with ANALYST role.
-- If VANDIT1SHARMA is mapped to NORTH, only NORTH amounts should be visible.
-- SOUTH and EAST rows remain visible, but their AMOUNT will be NULL.
USE ROLE ANALYST;
SELECT CURRENT_USER() AS CURRENT_USER, CURRENT_ROLE() AS CURRENT_ROLE;
SELECT * FROM DEMO_DATA.PUBLIC.EMPLOYEE_SALES;


-- ============================================================================
-- SECTION 7: OPTIONAL DISPLAY VIEW - SHOW **** INSTEAD OF NULL
--
-- The underlying AMOUNT column remains NUMBER and is safely masked as NULL.
-- This view converts the masked result to text for a friendlier display:
--   5000 -> '5000'
--   NULL -> '****'
--
-- Query this view when you want to see asterisks in the result.
-- ============================================================================

USE ROLE ACCOUNTADMIN;

CREATE OR REPLACE VIEW DEMO_DATA.PUBLIC.EMPLOYEE_SALES_DISPLAY AS
SELECT
    ID,
    EMPLOYEE_NAME,
    DIRECTION,
    COALESCE(TO_VARCHAR(AMOUNT), '****') AS AMOUNT_DISPLAY
FROM DEMO_DATA.PUBLIC.EMPLOYEE_SALES;

GRANT SELECT ON VIEW DEMO_DATA.PUBLIC.EMPLOYEE_SALES_DISPLAY TO ROLE ANALYST;

-- Test as ANALYST: all rows appear; only the user's own direction has amounts.
USE ROLE ANALYST;
SELECT * FROM DEMO_DATA.PUBLIC.EMPLOYEE_SALES_DISPLAY;


-- ============================================================================
-- SECTION 8: OPTIONAL TESTING / TROUBLESHOOTING COMMANDS
-- ============================================================================

-- Check the current user and active role.
SELECT CURRENT_USER(), CURRENT_ROLE();

-- Check the masking policies.
USE ROLE ACCOUNTADMIN;
SHOW MASKING POLICIES IN SCHEMA DEMO_DATA.PUBLIC;

-- Describe the customer table and its column policies.
DESC TABLE DEMO_DATA.PUBLIC.CUSTOMERS;

-- Describe the employee sales table and its column policies.
DESC TABLE DEMO_DATA.PUBLIC.EMPLOYEE_SALES;

-- Check the user-direction mapping.
SELECT * FROM DEMO_DATA.PUBLIC.USER_ACCESS;

-- Check grants for the ANALYST role.
SHOW GRANTS TO ROLE ANALYST;


-- ============================================================================
-- SECTION 9: IMPORTANT CONCEPTS - QUICK REVISION
--
-- DYNAMIC DATA MASKING:
--   Hides or transforms a column value depending on the access context.
--   Example: amit@gmail.com -> am**@gmail.com
--
-- ROW ACCESS POLICY:
--   Controls which rows a user can see.
--   A row that fails the policy is not returned.
--
-- MASKING POLICY:
--   Controls what value a user sees in a column.
--   A row can remain visible while a column value is masked.
--
-- CURRENT_USER():
--   Returns the logged-in Snowflake username.
--
-- CURRENT_ROLE():
--   Returns the currently active Snowflake role.
--
-- SPLIT_PART():
--   Extracts a part of a string, such as the username or domain of an email.
--
-- LEFT():
--   Returns characters from the left side of a string.
--
-- REPEAT():
--   Repeats a character a specified number of times.
--
-- EXISTS:
--   Checks whether a matching record exists in USER_ACCESS.
--
-- USING (AMOUNT, DIRECTION):
--   Passes both table-column values to the two-argument masking policy.
--
-- FINAL EXPECTED BEHAVIOUR:
--   ACCOUNTADMIN: sees all original values.
--   NORTH user: all rows visible; NORTH amount visible; other amounts masked.
--   SOUTH user: all rows visible; SOUTH amount visible; other amounts masked.
--   EAST user: all rows visible; EAST amount visible; other amounts masked.
--
-- END OF PRACTICAL
-- ============================================================================
