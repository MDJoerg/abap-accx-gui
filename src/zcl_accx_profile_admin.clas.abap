"! <p class="shorttext synchronized">Access Explorer: maintenance of server profiles</p>
"! Logic behind the report ZACCX_PROFILE_MAINTAIN: lists, checks, saves and deletes
"! rows of ZACCX_PROFILE (one server profile per row). The input is normalized
"! (profile lower case, groups and mode upper case) and checked before it is
"! written, because a wrong row is not rejected later but changes what a server
"! offers: an unknown privacy mode withholds every result, an unknown tool group
"! hides tools. The class does not commit; the caller does. Display needs
"! S_TABU_NAM activity 03, changes activity 02 for ZACCX_PROFILE. Every change
"! is written to the audit log of Access Explorer.
CLASS zcl_accx_profile_admin DEFINITION PUBLIC FINAL CREATE PUBLIC.

  PUBLIC SECTION.
    TYPES: BEGIN OF ty_profile,
             profile          TYPE zaccx_profile-profile,
             description      TYPE zaccx_profile-description,
             tool_groups      TYPE zaccx_profile-tool_groups,
             privacy_mode     TYPE zaccx_profile-privacy_mode,
             privacy_class    TYPE zaccx_profile-privacy_class,
             authorizer_class TYPE zaccx_profile-authorizer_class,
             max_rows         TYPE zaccx_profile-max_rows,
             allow_write      TYPE zaccx_profile-allow_write,
           END OF ty_profile,
           ty_profiles TYPE STANDARD TABLE OF ty_profile WITH EMPTY KEY.

    TYPES: BEGIN OF ty_finding,
             severity TYPE c LENGTH 1,
             text     TYPE string,
           END OF ty_finding,
           ty_findings TYPE STANDARD TABLE OF ty_finding WITH EMPTY KEY.

    CONSTANTS: BEGIN OF co_severity,
                 error   TYPE c LENGTH 1 VALUE 'E',
                 warning TYPE c LENGTH 1 VALUE 'W',
               END OF co_severity.

    CONSTANTS: BEGIN OF co_action,
                 created   TYPE string VALUE `created`,
                 changed   TYPE string VALUE `changed`,
                 unchanged TYPE string VALUE `unchanged`,
               END OF co_action.

    " before is initial for a new profile
    TYPES: BEGIN OF ty_outcome,
             action   TYPE string,
             before   TYPE ty_profile,
             after    TYPE ty_profile,
             findings TYPE ty_findings,
           END OF ty_outcome.

    "! check_authority = false only for unit tests
    METHODS constructor
      IMPORTING !logger          TYPE REF TO zif_accx_logger OPTIONAL
                !check_authority TYPE abap_bool DEFAULT abap_true.

    "! All profiles of the client sorted by name
    METHODS list
      RETURNING VALUE(result) TYPE ty_profiles
      RAISING   zcx_accx_error.

    "! Profile lower case, groups and mode upper case, classes upper case,
    "! empty groups mean all groups
    METHODS normalize
      IMPORTING !profile      TYPE ty_profile
      RETURNING VALUE(result) TYPE ty_profile.

    "! Findings of the normalized profile: errors prevent saving, warnings do not
    METHODS check
      IMPORTING !profile      TYPE ty_profile
      RETURNING VALUE(result) TYPE ty_findings.

    "! Writes the normalized profile (create or change). Raises with status
    "! invalid if the check finds an error. Does not commit.
    METHODS save
      IMPORTING !profile      TYPE ty_profile
      RETURNING VALUE(result) TYPE ty_outcome
      RAISING   zcx_accx_error.

    "! Deletes a profile. Raises with status not_found if it does not exist.
    METHODS delete
      IMPORTING !name         TYPE csequence
      RETURNING VALUE(result) TYPE ty_profile
      RAISING   zcx_accx_error.

  PRIVATE SECTION.
    DATA logger          TYPE REF TO zif_accx_logger.
    DATA check_authority TYPE abap_bool.

    METHODS ensure_authorized
      IMPORTING !activity TYPE c
      RAISING   zcx_accx_error.

    METHODS read_profile
      IMPORTING !name         TYPE zaccx_profile-profile
      RETURNING VALUE(result) TYPE ty_profile.

    "! Empty if the class exists, implements the interface and can be created without parameters
    METHODS class_problem
      IMPORTING !class_name   TYPE csequence
                !interface    TYPE csequence
      RETURNING VALUE(result) TYPE string.

    METHODS known_groups
      RETURNING VALUE(result) TYPE string_table.

    METHODS write_log
      IMPORTING !profile TYPE csequence
                !message TYPE csequence.

ENDCLASS.

CLASS zcl_accx_profile_admin IMPLEMENTATION.

  METHOD constructor.
    me->logger          = COND #( WHEN logger IS BOUND THEN logger ELSE NEW zcl_accx_logger_db( ) ).
    me->check_authority = check_authority.
  ENDMETHOD.

  METHOD list.
    ensure_authorized( '03' ).
    SELECT profile, description, tool_groups, privacy_mode, privacy_class, authorizer_class, max_rows, allow_write
      FROM zaccx_profile
      ORDER BY profile
      INTO CORRESPONDING FIELDS OF TABLE @result.
  ENDMETHOD.

  METHOD normalize.
    result = profile.
    result-profile          = to_lower( condense( CONV string( profile-profile ) ) ).
    result-description      = condense( CONV string( profile-description ) ).
    result-privacy_mode     = to_upper( condense( CONV string( profile-privacy_mode ) ) ).
    result-privacy_class    = to_upper( condense( CONV string( profile-privacy_class ) ) ).
    result-authorizer_class = to_upper( condense( CONV string( profile-authorizer_class ) ) ).
    result-allow_write      = COND #( WHEN profile-allow_write IS NOT INITIAL THEN abap_true ).

    SPLIT CONV string( profile-tool_groups ) AT ',' INTO TABLE DATA(parts).
    DATA groups TYPE string_table.
    LOOP AT parts INTO DATA(part).
      part = to_upper( condense( part ) ).
      IF part IS NOT INITIAL AND NOT line_exists( groups[ table_line = part ] ).
        APPEND part TO groups.
      ENDIF.
    ENDLOOP.
    result-tool_groups = COND #( WHEN groups IS INITIAL THEN `*` ELSE concat_lines_of( table = groups sep = `,` ) ).
  ENDMETHOD.

  METHOD check.
    DATA(row) = normalize( profile ).

    IF row-profile IS INITIAL
       OR NOT matches( val = row-profile pcre = `[a-z0-9][a-z0-9_-]*/[a-z0-9][a-z0-9_-]*` ).
      APPEND VALUE #( severity = co_severity-error
                      text     = `The profile must be area/server: lower case letters, digits, - and _ on both sides of one /.` ) TO result.
    ENDIF.

    IF row-privacy_mode IS NOT INITIAL
       AND row-privacy_mode <> zcl_accx_factory=>co_privacy_mode-none
       AND row-privacy_mode <> zcl_accx_factory=>co_privacy_mode-pseudonymize
       AND row-privacy_mode <> zcl_accx_factory=>co_privacy_mode-minimize.
      APPEND VALUE #( severity = co_severity-error
                      text     = |Privacy mode { row-privacy_mode } is unknown (NONE, PSEUDONYMIZE or MINIMIZE); the server would withhold every result.| )
             TO result.
    ENDIF.

    IF row-tool_groups <> `*`.
      DATA(known) = known_groups( ).
      SPLIT CONV string( row-tool_groups ) AT ',' INTO TABLE DATA(groups).
      LOOP AT groups INTO DATA(group).
        IF NOT line_exists( known[ table_line = group ] ).
          APPEND VALUE #( severity = co_severity-error
                          text     = |Tool group { group } is unknown ({ concat_lines_of( table = known sep = `, ` ) } or *).| ) TO result.
        ENDIF.
      ENDLOOP.
      IF row-allow_write = abap_true AND NOT line_exists( groups[ table_line = zif_accx_types=>co_group-admin ] ).
        APPEND VALUE #( severity = co_severity-warning
                        text     = |Writing is allowed but the groups do not contain { zif_accx_types=>co_group-admin }: no write tool is offered.| )
               TO result.
      ENDIF.
    ENDIF.

    IF row-max_rows < 0 OR row-max_rows > zcl_accx_factory=>co_limit_max_rows.
      APPEND VALUE #( severity = co_severity-error
                      text     = |The row limit must be 0 (default { zcl_accx_factory=>co_default_max_rows }) to { zcl_accx_factory=>co_limit_max_rows }.| )
             TO result.
    ENDIF.

    IF row-privacy_class IS NOT INITIAL.
      DATA(privacy_problem) = class_problem( class_name = row-privacy_class interface = `ZIF_ACCX_PRIVACY` ).
      IF privacy_problem IS NOT INITIAL.
        APPEND VALUE #( severity = co_severity-error text = |Privacy class: { privacy_problem }| ) TO result.
      ELSEIF row-privacy_mode IS NOT INITIAL AND row-privacy_mode <> zcl_accx_factory=>co_privacy_mode-none.
        APPEND VALUE #( severity = co_severity-warning
                        text     = `Privacy class and privacy mode are both set: the class wins, the mode is ignored.` ) TO result.
      ENDIF.
    ENDIF.

    IF row-authorizer_class IS NOT INITIAL.
      DATA(authorizer_problem) = class_problem( class_name = row-authorizer_class interface = `ZIF_ACCX_AUTHORIZER` ).
      IF authorizer_problem IS NOT INITIAL.
        APPEND VALUE #( severity = co_severity-error text = |Authorizer class: { authorizer_problem }| ) TO result.
      ENDIF.
    ENDIF.
  ENDMETHOD.

  METHOD save.
    DATA(row) = normalize( profile ).
    DATA(findings) = check( row ).
    DATA problems TYPE string.
    LOOP AT findings INTO DATA(finding) WHERE severity = co_severity-error.
      problems = COND #( WHEN problems IS INITIAL THEN finding-text ELSE |{ problems } { finding-text }| ).
    ENDLOOP.
    IF problems IS NOT INITIAL.
      RAISE EXCEPTION NEW zcx_accx_error( status = zif_accx_types=>co_status-invalid message = problems ).
    ENDIF.
    ensure_authorized( '02' ).

    DATA(before) = read_profile( row-profile ).
    DATA(entry) = CORRESPONDING zaccx_profile( row ).
    entry-client = sy-mandt.
    MODIFY zaccx_profile FROM @entry.

    result = VALUE #( action   = COND #( WHEN before-profile IS INITIAL THEN co_action-created
                                         WHEN before = row THEN co_action-unchanged
                                         ELSE co_action-changed )
                      before   = before
                      after    = row
                      findings = findings ).
    write_log( profile = row-profile
               message = |{ result-action }: groups { row-tool_groups }, mode { COND string( WHEN row-privacy_mode IS INITIAL THEN `NONE` ELSE row-privacy_mode ) }, | &&
                         |write { COND string( WHEN row-allow_write = abap_true THEN `yes` ELSE `no` ) }| ).
  ENDMETHOD.

  METHOD delete.
    DATA(profile_name) = CONV zaccx_profile-profile( to_lower( condense( CONV string( name ) ) ) ).
    ensure_authorized( '02' ).
    result = read_profile( profile_name ).
    IF result-profile IS INITIAL.
      RAISE EXCEPTION NEW zcx_accx_error( status  = zif_accx_types=>co_status-not_found
                                          message = |Profile { profile_name } does not exist.| ).
    ENDIF.
    DELETE FROM zaccx_profile WHERE profile = @profile_name.
    write_log( profile = profile_name message = `deleted` ).
  ENDMETHOD.

  METHOD ensure_authorized.
    IF check_authority = abap_false.
      RETURN.
    ENDIF.
    AUTHORITY-CHECK OBJECT 'S_TABU_NAM' ID 'ACTVT' FIELD activity ID 'TABLE' FIELD 'ZACCX_PROFILE'.
    IF sy-subrc <> 0.
      RAISE EXCEPTION NEW zcx_accx_error( status  = zif_accx_types=>co_status-denied
                                          message = |You are not authorized for table ZACCX_PROFILE (S_TABU_NAM, activity { activity }).| ).
    ENDIF.
  ENDMETHOD.

  METHOD read_profile.
    SELECT SINGLE profile, description, tool_groups, privacy_mode, privacy_class, authorizer_class, max_rows, allow_write
      FROM zaccx_profile
      WHERE profile = @name
      INTO CORRESPONDING FIELDS OF @result.
  ENDMETHOD.

  METHOD class_problem.
    DATA descriptor TYPE REF TO cl_abap_typedescr.
    cl_abap_typedescr=>describe_by_name( EXPORTING  p_name         = class_name
                                         RECEIVING  p_descr_ref    = descriptor
                                         EXCEPTIONS type_not_found = 1
                                                    OTHERS         = 2 ).
    IF sy-subrc <> 0 OR descriptor->kind <> cl_abap_typedescr=>kind_class.
      result = |{ class_name } is not a class.|.
      RETURN.
    ENDIF.
    DATA(class_descriptor) = CAST cl_abap_classdescr( descriptor ).
    IF NOT line_exists( class_descriptor->interfaces[ name = to_upper( interface ) ] ).
      result = |{ class_name } does not implement { interface }.|.
      RETURN.
    ENDIF.
    " the server creates the class without parameters
    DATA instance TYPE REF TO object.
    TRY.
        CREATE OBJECT instance TYPE (class_name).
      CATCH cx_root.
        result = |{ class_name } cannot be created without parameters.|.
    ENDTRY.
  ENDMETHOD.

  METHOD known_groups.
    DATA(components) = CAST cl_abap_structdescr( cl_abap_typedescr=>describe_by_data( zif_accx_types=>co_group ) )->components.
    LOOP AT components INTO DATA(component).
      ASSIGN COMPONENT component-name OF STRUCTURE zif_accx_types=>co_group TO FIELD-SYMBOL(<value>).
      IF sy-subrc = 0.
        APPEND |{ <value> }| TO result.
      ENDIF.
    ENDLOOP.
  ENDMETHOD.

  METHOD write_log.
    logger->log( VALUE #( caller    = sy-uname
                          profile   = profile
                          system_id = sy-sysid
                          tool_name = `profile_maintain`
                          status    = zif_accx_types=>co_status-ok
                          message   = message ) ).
  ENDMETHOD.

ENDCLASS.

