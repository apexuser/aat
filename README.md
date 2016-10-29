Template of Oracle APEX application

Template contains a number of database objects (tables, triggers, procedures, etc.) and APEX objects (pages, build options, authentication scheme, etc.). It allows you to develop an application with different access models (simple role-based, RBAC, ABAC).
Following features are already implemented in this template:
 * custom authentication scheme
 * all supporting database objects for authentication scheme (package with functions to create user, check password, etc.)
 * pages for access rights tuning
 * default ADMIN user for an application

Also you can use this template for creating multiple applications in one APEX workspace.

UPDATE

Branch "multiple_applications" is reserved for a template, which allows to create multiple applications within one database schema and workspace. Now I don't know, how to design such template. All my attempts look weird. I'll return to this brach later, if ispiration will come.
