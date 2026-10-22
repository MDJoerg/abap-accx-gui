*&---------------------------------------------------------------------*
*& Maintains the server profiles of Access Explorer (table ZACCX_PROFILE):
*& list, create or change, delete. A profile is the name of an endpoint
*& (area/server) with its tool groups, privacy mode and write permission.
*& The input is normalized and checked before it is written; the test run
*& (default) shows the result without saving. Needs S_TABU_NAM for
*& ZACCX_PROFILE (display 03, change 02); every change is logged in ZACCX_LOG.
*& Saving writes the whole row as entered: to change one value, list the
*& profiles first and enter the other values again.
*& A new profile becomes an endpoint when the adapter of your transport
*& registers it (mcp2: run ZCL_ACCX_MCP2_SERVER with F9).
*&---------------------------------------------------------------------*
REPORT zaccx_profile_maintain.

PARAMETERS p_list RADIOBUTTON GROUP act DEFAULT 'X'.
PARAMETERS p_save RADIOBUTTON GROUP act.
PARAMETERS p_del  RADIOBUTTON GROUP act.

SELECTION-SCREEN SKIP.

PARAMETERS p_prof  TYPE zaccx_profile-profile LOWER CASE.
PARAMETERS p_desc  TYPE zaccx_profile-description LOWER CASE.
PARAMETERS p_grp   TYPE zaccx_profile-tool_groups LOWER CASE DEFAULT '*'.
PARAMETERS p_priv  TYPE zaccx_profile-privacy_mode LOWER CASE.
PARAMETERS p_pcls  TYPE zaccx_profile-privacy_class.
PARAMETERS p_acls  TYPE zaccx_profile-authorizer_class.
PARAMETERS p_rows  TYPE zaccx_profile-max_rows.
PARAMETERS p_write AS CHECKBOX.

SELECTION-SCREEN SKIP.

PARAMETERS p_test AS CHECKBOX DEFAULT 'X'.

CLASS lcl_report DEFINITION FINAL.
  PUBLIC SECTION.
    METHODS run.

  PRIVATE SECTION.
    DATA admin TYPE REF TO zcl_accx_profile_admin.

    METHODS show_list RAISING zcx_accx_error.
    METHODS save      RAISING zcx_accx_error.
    METHODS delete    RAISING zcx_accx_error.
    METHODS write_profile
      IMPORTING !title   TYPE csequence
                !profile TYPE zcl_accx_profile_admin=>ty_profile.
    METHODS write_findings
      IMPORTING !findings TYPE zcl_accx_profile_admin=>ty_findings.
ENDCLASS.

CLASS lcl_report IMPLEMENTATION.

  METHOD run.
    admin = NEW zcl_accx_profile_admin( ).
    TRY.
        CASE abap_true.
          WHEN p_list.
            show_list( ).
          WHEN p_save.
            save( ).
          WHEN p_del.
            delete( ).
        ENDCASE.
      CATCH zcx_accx_error INTO DATA(error).
        MESSAGE error->get_text( ) TYPE 'S' DISPLAY LIKE 'E'.
    ENDTRY.
  ENDMETHOD.

  METHOD show_list.
    DATA(profiles) = admin->list( ).
    IF profiles IS INITIAL.
      MESSAGE 'No profile maintained: all servers use the default settings.' TYPE 'S'.
      RETURN.
    ENDIF.
    TRY.
        cl_salv_table=>factory( IMPORTING r_salv_table = DATA(table)
                                CHANGING  t_table      = profiles ).
        table->get_functions( )->set_all( ).
        table->get_columns( )->set_optimize( ).
        table->display( ).
      CATCH cx_salv_msg INTO DATA(salv_error).
        MESSAGE salv_error->get_text( ) TYPE 'S' DISPLAY LIKE 'E'.
    ENDTRY.
  ENDMETHOD.

  METHOD save.
    DATA(row) = admin->normalize( VALUE #( profile          = p_prof
                                           description      = p_desc
                                           tool_groups      = p_grp
                                           privacy_mode     = p_priv
                                           privacy_class    = p_pcls
                                           authorizer_class = p_acls
                                           max_rows         = p_rows
                                           allow_write      = p_write ) ).
    write_profile( title = 'Profile as entered (normalized)' profile = row ).
    IF p_test = abap_true.
      DATA(findings) = admin->check( row ).
      write_findings( findings ).
      IF NOT line_exists( findings[ severity = zcl_accx_profile_admin=>co_severity-error ] ).
        SKIP.
        WRITE / 'Test run: nothing saved. Clear "Test run" to save.'.
      ENDIF.
      RETURN.
    ENDIF.

    DATA(outcome) = admin->save( row ).
    COMMIT WORK.
    SKIP.
    WRITE: / 'Profile', outcome-after-profile, outcome-action.
    IF outcome-before-profile IS NOT INITIAL AND outcome-action = zcl_accx_profile_admin=>co_action-changed.
      write_profile( title = 'Before' profile = outcome-before ).
    ENDIF.
    write_findings( outcome-findings ).
    IF outcome-action = zcl_accx_profile_admin=>co_action-created.
      SKIP.
      WRITE / 'The endpoint exists once the adapter registers it (mcp2: run ZCL_ACCX_MCP2_SERVER with F9).'.
    ENDIF.
  ENDMETHOD.

  METHOD delete.
    DATA(name) = to_lower( condense( CONV string( p_prof ) ) ).
    IF p_test = abap_true.
      LOOP AT admin->list( ) INTO DATA(existing) WHERE profile = name.
        write_profile( title = 'Would be deleted' profile = existing ).
        SKIP.
        WRITE / 'Test run: nothing deleted. Clear "Test run" to delete.'.
        RETURN.
      ENDLOOP.
      MESSAGE |Profile { name } does not exist.| TYPE 'S' DISPLAY LIKE 'E'.
      RETURN.
    ENDIF.
    DATA(deleted) = admin->delete( name ).
    COMMIT WORK.
    WRITE: / 'Profile', deleted-profile, 'deleted. Servers using it now run with the default settings.'.
  ENDMETHOD.

  METHOD write_profile.
    WRITE: / title COLOR COL_HEADING.
    WRITE: / 'Profile         ', profile-profile,
           / 'Description     ', profile-description,
           / 'Tool groups     ', profile-tool_groups,
           / 'Privacy mode    ', profile-privacy_mode,
           / 'Privacy class   ', profile-privacy_class,
           / 'Authorizer class', profile-authorizer_class,
           / 'Row limit       ', profile-max_rows,
           / 'Write allowed   ', profile-allow_write.
  ENDMETHOD.

  METHOD write_findings.
    IF findings IS INITIAL.
      RETURN.
    ENDIF.
    SKIP.
    LOOP AT findings INTO DATA(finding).
      IF finding-severity = zcl_accx_profile_admin=>co_severity-error.
        WRITE: / 'Error:  ' COLOR COL_NEGATIVE, finding-text.
      ELSE.
        WRITE: / 'Warning:' COLOR COL_TOTAL, finding-text.
      ENDIF.
    ENDLOOP.
  ENDMETHOD.

ENDCLASS.

START-OF-SELECTION.
  NEW lcl_report( )->run( ).
