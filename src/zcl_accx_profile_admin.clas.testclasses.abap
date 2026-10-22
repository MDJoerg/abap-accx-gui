CLASS ltd_logger DEFINITION FINAL FOR TESTING.
  PUBLIC SECTION.
    INTERFACES zif_accx_logger.
    DATA entries TYPE STANDARD TABLE OF zif_accx_logger=>ty_entry WITH EMPTY KEY.
ENDCLASS.

CLASS ltd_logger IMPLEMENTATION.

  METHOD zif_accx_logger~log.
    APPEND entry TO entries.
  ENDMETHOD.

ENDCLASS.

"! Runs on an OpenSQL test double of ZACCX_PROFILE: nothing real is read or changed
CLASS ltc_profile_admin DEFINITION FINAL FOR TESTING
  DURATION SHORT RISK LEVEL HARMLESS.

  PRIVATE SECTION.
    CLASS-DATA environment TYPE REF TO if_osql_test_environment.

    DATA cut    TYPE REF TO zcl_accx_profile_admin.
    DATA logger TYPE REF TO ltd_logger.

    CLASS-METHODS class_setup.
    CLASS-METHODS class_teardown.
    METHODS setup.
    METHODS valid_profile
      RETURNING VALUE(result) TYPE zcl_accx_profile_admin=>ty_profile.
    METHODS errors_of
      IMPORTING !profile      TYPE zcl_accx_profile_admin=>ty_profile
      RETURNING VALUE(result) TYPE string.
    METHODS warnings_of
      IMPORTING !profile      TYPE zcl_accx_profile_admin=>ty_profile
      RETURNING VALUE(result) TYPE string.

    METHODS normalize_cleans_input      FOR TESTING.
    METHODS empty_groups_mean_all       FOR TESTING.
    METHODS valid_profile_has_no_finding FOR TESTING.
    METHODS profile_name_is_checked     FOR TESTING.
    METHODS privacy_mode_is_checked     FOR TESTING.
    METHODS tool_groups_are_checked     FOR TESTING.
    METHODS row_limit_is_checked        FOR TESTING.
    METHODS classes_are_checked         FOR TESTING.
    METHODS write_without_admin_warns   FOR TESTING.
    METHODS class_and_mode_warn         FOR TESTING.
    METHODS save_creates_and_changes   FOR TESTING RAISING zcx_accx_error.
    METHODS save_refuses_errors         FOR TESTING RAISING zcx_accx_error.
    METHODS delete_removes_profile     FOR TESTING RAISING zcx_accx_error.
    METHODS delete_unknown_not_found    FOR TESTING.
    METHODS list_is_sorted             FOR TESTING RAISING zcx_accx_error.
    METHODS changes_are_logged         FOR TESTING RAISING zcx_accx_error.
ENDCLASS.

CLASS ltc_profile_admin IMPLEMENTATION.

  METHOD class_setup.
    environment = cl_osql_test_environment=>create( i_dependency_list = VALUE #( ( 'ZACCX_PROFILE' ) ) ).
  ENDMETHOD.

  METHOD class_teardown.
    environment->destroy( ).
  ENDMETHOD.

  METHOD setup.
    environment->clear_doubles( ).
    logger = NEW ltd_logger( ).
    cut = NEW zcl_accx_profile_admin( logger = logger check_authority = abap_false ).
  ENDMETHOD.

  METHOD valid_profile.
    result = VALUE #( profile      = `bc/access-audit`
                      description  = `Audit`
                      tool_groups  = `*`
                      privacy_mode = `MINIMIZE` ).
  ENDMETHOD.

  METHOD errors_of.
    LOOP AT cut->check( profile ) INTO DATA(finding) WHERE severity = zcl_accx_profile_admin=>co_severity-error.
      result = COND #( WHEN result IS INITIAL THEN finding-text ELSE |{ result } { finding-text }| ).
    ENDLOOP.
  ENDMETHOD.

  METHOD warnings_of.
    LOOP AT cut->check( profile ) INTO DATA(finding) WHERE severity = zcl_accx_profile_admin=>co_severity-warning.
      result = COND #( WHEN result IS INITIAL THEN finding-text ELSE |{ result } { finding-text }| ).
    ENDLOOP.
  ENDMETHOD.

  METHOD normalize_cleans_input.
    DATA(row) = cut->normalize( VALUE #( profile          = `  BC/Access-Audit `
                                         description      = `  Audit   view `
                                         tool_groups      = ` user, role ,USER,, diag`
                                         privacy_mode     = ` minimize`
                                         privacy_class    = `zcl_accx_privacy_none`
                                         authorizer_class = `zcl_accx_authorizer`
                                         allow_write      = 'y' ) ).
    cl_abap_unit_assert=>assert_equals( exp = `bc/access-audit` act = row-profile ).
    cl_abap_unit_assert=>assert_equals( exp = `Audit view` act = row-description ).
    cl_abap_unit_assert=>assert_equals( exp = `USER,ROLE,DIAG` act = row-tool_groups ).
    cl_abap_unit_assert=>assert_equals( exp = `MINIMIZE` act = row-privacy_mode ).
    cl_abap_unit_assert=>assert_equals( exp = `ZCL_ACCX_PRIVACY_NONE` act = row-privacy_class ).
    cl_abap_unit_assert=>assert_equals( exp = `ZCL_ACCX_AUTHORIZER` act = row-authorizer_class ).
    cl_abap_unit_assert=>assert_equals( exp = abap_true act = row-allow_write ).
  ENDMETHOD.

  METHOD empty_groups_mean_all.
    cl_abap_unit_assert=>assert_equals( exp = `*` act = cut->normalize( VALUE #( profile = `a/b` ) )-tool_groups ).
    cl_abap_unit_assert=>assert_equals( exp = `*` act = cut->normalize( VALUE #( profile = `a/b` tool_groups = ` , ` ) )-tool_groups ).
  ENDMETHOD.

  METHOD valid_profile_has_no_finding.
    cl_abap_unit_assert=>assert_initial( cut->check( valid_profile( ) ) ).
    DATA(all_set) = valid_profile( ).
    all_set-tool_groups      = `USER,ROLE,DIAG,FIORI,DATA,AUDIT,ADMIN`.
    all_set-allow_write      = abap_true.
    all_set-privacy_mode     = ``.
    all_set-max_rows         = 500.
    all_set-authorizer_class = `ZCL_ACCX_AUTHORIZER`.
    cl_abap_unit_assert=>assert_initial( cut->check( all_set ) ).
  ENDMETHOD.

  METHOD profile_name_is_checked.
    DATA(row) = valid_profile( ).
    DATA(names) = VALUE string_table( ( `` ) ( `access-audit` ) ( `bc/` ) ( `/audit` ) ( `bc/a/b` ) ( `bc/access audit` ) ( `bc/ä` ) ).
    LOOP AT names INTO DATA(name).
      row-profile = name.
      cl_abap_unit_assert=>assert_char_cp( exp = `*area/server*` act = errors_of( row ) msg = |Name '{ name }'| ).
    ENDLOOP.
    " upper case input is accepted: the name is stored in lower case
    row-profile = `BC/Access-Support`.
    cl_abap_unit_assert=>assert_initial( errors_of( row ) ).
  ENDMETHOD.

  METHOD privacy_mode_is_checked.
    DATA(row) = valid_profile( ).
    row-privacy_mode = `PSEUDONYM`.
    cl_abap_unit_assert=>assert_char_cp( exp = `*PSEUDONYM is unknown*` act = errors_of( row ) ).
    LOOP AT VALUE string_table( ( `` ) ( `none` ) ( `PSEUDONYMIZE` ) ( `minimize` ) ) INTO DATA(mode).
      row-privacy_mode = mode.
      cl_abap_unit_assert=>assert_initial( act = errors_of( row ) msg = mode ).
    ENDLOOP.
  ENDMETHOD.

  METHOD tool_groups_are_checked.
    DATA(row) = valid_profile( ).
    row-tool_groups = `USER,FIOR`.
    cl_abap_unit_assert=>assert_char_cp( exp = `*Tool group FIOR is unknown*` act = errors_of( row ) ).
    row-tool_groups = `user,audit`.
    cl_abap_unit_assert=>assert_initial( errors_of( row ) ).
    " * alone means all, mixed with names it is an unknown group
    row-tool_groups = `*,USER`.
    cl_abap_unit_assert=>assert_char_cp( exp = `*Tool group * is unknown*` act = errors_of( row ) ).
  ENDMETHOD.

  METHOD row_limit_is_checked.
    DATA(row) = valid_profile( ).
    row-max_rows = 501.
    cl_abap_unit_assert=>assert_char_cp( exp = `*row limit*` act = errors_of( row ) ).
    row-max_rows = -1.
    cl_abap_unit_assert=>assert_char_cp( exp = `*row limit*` act = errors_of( row ) ).
    row-max_rows = 0.
    cl_abap_unit_assert=>assert_initial( errors_of( row ) ).
  ENDMETHOD.

  METHOD classes_are_checked.
    DATA(row) = valid_profile( ).
    row-privacy_mode  = ``.
    row-privacy_class = `ZCL_DOES_NOT_EXIST`.
    cl_abap_unit_assert=>assert_char_cp( exp = `*Privacy class*not a class*` act = errors_of( row ) ).
    " exists but is no privacy strategy
    row-privacy_class = `ZCL_ACCX_AUTHORIZER`.
    cl_abap_unit_assert=>assert_char_cp( exp = `*does not implement ZIF_ACCX_PRIVACY*` act = errors_of( row ) ).
    " the default strategy needs the mode as parameter, the server creates it without
    row-privacy_class = `ZCL_ACCX_PRIVACY_DEFAULT`.
    cl_abap_unit_assert=>assert_char_cp( exp = `*cannot be created without parameters*` act = errors_of( row ) ).
    row-privacy_class = `zcl_accx_privacy_none`.
    cl_abap_unit_assert=>assert_initial( errors_of( row ) ).

    row-authorizer_class = `ZCL_ACCX_PRIVACY_NONE`.
    cl_abap_unit_assert=>assert_char_cp( exp = `*Authorizer class*does not implement ZIF_ACCX_AUTHORIZER*` act = errors_of( row ) ).
    row-authorizer_class = `ZCL_NOPE`.
    cl_abap_unit_assert=>assert_char_cp( exp = `*Authorizer class*not a class*` act = errors_of( row ) ).
    row-authorizer_class = `ZCL_ACCX_AUTHORIZER`.
    cl_abap_unit_assert=>assert_initial( errors_of( row ) ).
  ENDMETHOD.

  METHOD write_without_admin_warns.
    DATA(row) = valid_profile( ).
    row-allow_write = abap_true.
    " all groups include ADMIN
    cl_abap_unit_assert=>assert_initial( warnings_of( row ) ).
    row-tool_groups = `USER,ROLE`.
    cl_abap_unit_assert=>assert_char_cp( exp = `*no write tool is offered*` act = warnings_of( row ) ).
    cl_abap_unit_assert=>assert_initial( errors_of( row ) ).
    row-tool_groups = `USER,ADMIN`.
    cl_abap_unit_assert=>assert_initial( warnings_of( row ) ).
  ENDMETHOD.

  METHOD class_and_mode_warn.
    DATA(row) = valid_profile( ).
    row-privacy_class = `ZCL_ACCX_PRIVACY_NONE`.
    cl_abap_unit_assert=>assert_char_cp( exp = `*the class wins*` act = warnings_of( row ) ).
    row-privacy_mode = `NONE`.
    cl_abap_unit_assert=>assert_initial( warnings_of( row ) ).
  ENDMETHOD.

  METHOD save_creates_and_changes.
    DATA(created) = cut->save( VALUE #( profile = `BC/Access-Audit` description = `Audit` tool_groups = `audit` privacy_mode = `minimize` ) ).
    cl_abap_unit_assert=>assert_equals( exp = zcl_accx_profile_admin=>co_action-created act = created-action ).
    cl_abap_unit_assert=>assert_initial( created-before-profile ).
    cl_abap_unit_assert=>assert_equals( exp = `AUDIT` act = created-after-tool_groups ).

    DATA(rows) = cut->list( ).
    cl_abap_unit_assert=>assert_equals( exp = 1 act = lines( rows ) ).
    cl_abap_unit_assert=>assert_equals( exp = `bc/access-audit` act = rows[ 1 ]-profile ).
    cl_abap_unit_assert=>assert_equals( exp = `MINIMIZE` act = rows[ 1 ]-privacy_mode ).

    " same input again changes nothing
    DATA(same) = cut->save( VALUE #( profile = `bc/access-audit` description = `Audit` tool_groups = `AUDIT` privacy_mode = `MINIMIZE` ) ).
    cl_abap_unit_assert=>assert_equals( exp = zcl_accx_profile_admin=>co_action-unchanged act = same-action ).

    DATA(changed) = cut->save( VALUE #( profile = `bc/access-audit` description = `Audit` tool_groups = `*` privacy_mode = `PSEUDONYMIZE` max_rows = 20 ) ).
    cl_abap_unit_assert=>assert_equals( exp = zcl_accx_profile_admin=>co_action-changed act = changed-action ).
    cl_abap_unit_assert=>assert_equals( exp = `MINIMIZE` act = changed-before-privacy_mode ).
    cl_abap_unit_assert=>assert_equals( exp = `PSEUDONYMIZE` act = changed-after-privacy_mode ).
    cl_abap_unit_assert=>assert_equals( exp = 1 act = lines( cut->list( ) ) ).
    rows = cut->list( ).
    cl_abap_unit_assert=>assert_equals( exp = 20 act = rows[ 1 ]-max_rows ).
  ENDMETHOD.

  METHOD save_refuses_errors.
    TRY.
        cut->save( VALUE #( profile = `bad name` privacy_mode = `NOPE` ) ).
        cl_abap_unit_assert=>fail( `Exception expected` ).
      CATCH zcx_accx_error INTO DATA(error).
        cl_abap_unit_assert=>assert_equals( exp = zif_accx_types=>co_status-invalid act = error->status ).
        " all problems at once
        cl_abap_unit_assert=>assert_char_cp( exp = `*area/server*NOPE*` act = error->get_text( ) ).
    ENDTRY.
    cl_abap_unit_assert=>assert_initial( cut->list( ) ).
    cl_abap_unit_assert=>assert_initial( logger->entries ).
  ENDMETHOD.

  METHOD delete_removes_profile.
    cut->save( valid_profile( ) ).
    cut->save( VALUE #( profile = `bc/access-support` ) ).
    DATA(deleted) = cut->delete( ` BC/Access-Audit ` ).
    cl_abap_unit_assert=>assert_equals( exp = `bc/access-audit` act = deleted-profile ).
    DATA(rows) = cut->list( ).
    cl_abap_unit_assert=>assert_equals( exp = 1 act = lines( rows ) ).
    cl_abap_unit_assert=>assert_equals( exp = `bc/access-support` act = rows[ 1 ]-profile ).
  ENDMETHOD.

  METHOD delete_unknown_not_found.
    TRY.
        cut->delete( `bc/nothing` ).
        cl_abap_unit_assert=>fail( `Exception expected` ).
      CATCH zcx_accx_error INTO DATA(error).
        cl_abap_unit_assert=>assert_equals( exp = zif_accx_types=>co_status-not_found act = error->status ).
    ENDTRY.
  ENDMETHOD.

  METHOD list_is_sorted.
    cut->save( VALUE #( profile = `bc/b` ) ).
    cut->save( VALUE #( profile = `bc/a` ) ).
    cut->save( VALUE #( profile = `ab/z` ) ).
    DATA(rows) = cut->list( ).
    cl_abap_unit_assert=>assert_equals( exp = 3 act = lines( rows ) ).
    cl_abap_unit_assert=>assert_equals( exp = `ab/z` act = rows[ 1 ]-profile ).
    cl_abap_unit_assert=>assert_equals( exp = `bc/b` act = rows[ 3 ]-profile ).
  ENDMETHOD.

  METHOD changes_are_logged.
    cut->save( valid_profile( ) ).
    cut->delete( `bc/access-audit` ).
    cl_abap_unit_assert=>assert_equals( exp = 2 act = lines( logger->entries ) ).
    DATA(first) = logger->entries[ 1 ].
    cl_abap_unit_assert=>assert_equals( exp = `profile_maintain` act = first-tool_name ).
    cl_abap_unit_assert=>assert_equals( exp = `bc/access-audit` act = first-profile ).
    cl_abap_unit_assert=>assert_char_cp( exp = `created*MINIMIZE*` act = first-message ).
    cl_abap_unit_assert=>assert_equals( exp = `deleted` act = logger->entries[ 2 ]-message ).
  ENDMETHOD.

ENDCLASS.
