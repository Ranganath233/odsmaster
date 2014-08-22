CREATE EXTENSION IF NOT EXISTS hstore WITH SCHEMA gemsods;
set search_path='gemsods';
CREATE TABLE gemsods.audit_logged_actions (
    event_id bigserial PRIMARY KEY,
    schema_name text NOT NULL,
    table_name text NOT NULL,
    relid oid NOT NULL,
    session_user_name text,
    action_tstamp_tx TIMESTAMP WITH TIME ZONE NOT NULL,
    action_tstamp_stm TIMESTAMP WITH TIME ZONE NOT NULL,
    action_tstamp_clk TIMESTAMP WITH TIME ZONE NOT NULL,
    transaction_id bigint,
    application_name text,
    client_addr inet,
    client_port integer,
    client_query text NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('I','D','U', 'T')),
    row_data hstore,
    changed_fields hstore,
    statement_only BOOLEAN NOT NULL
);

COMMENT ON TABLE gemsods.audit_logged_actions IS 'History of gemsodsable actions on gemsodsed tables, from gemsods.if_modified_func()';
COMMENT ON COLUMN gemsods.audit_logged_actions.event_id IS 'Unique identifier for each gemsodsable event';
COMMENT ON COLUMN gemsods.audit_logged_actions.schema_name IS 'Database schema gemsodsed table for this event is in';
COMMENT ON COLUMN gemsods.audit_logged_actions.table_name IS 'Non-schema-qualified table name of table event occured in';
COMMENT ON COLUMN gemsods.audit_logged_actions.relid IS 'Table OID. Changes with drop/create. Get with ''tablename''::regclass';
COMMENT ON COLUMN gemsods.audit_logged_actions.session_user_name IS 'Login / session user whose statement caused the gemsodsed event';
COMMENT ON COLUMN gemsods.audit_logged_actions.action_tstamp_tx IS 'Transaction start timestamp for tx in which gemsodsed event occurred';
COMMENT ON COLUMN gemsods.audit_logged_actions.action_tstamp_stm IS 'Statement start timestamp for tx in which gemsodsed event occurred';
COMMENT ON COLUMN gemsods.audit_logged_actions.action_tstamp_clk IS 'Wall clock time at which gemsodsed event''s trigger call occurred';
COMMENT ON COLUMN gemsods.audit_logged_actions.transaction_id IS 'Identifier of transaction that made the change. May wrap, but unique paired with action_tstamp_tx.';
COMMENT ON COLUMN gemsods.audit_logged_actions.client_addr IS 'IP address of client that issued query. Null for unix domain socket.';
COMMENT ON COLUMN gemsods.audit_logged_actions.client_port IS 'Remote peer IP port address of client that issued query. Undefined for unix socket.';
COMMENT ON COLUMN gemsods.audit_logged_actions.client_query IS 'Top-level query that caused this gemsodsable event. May be more than one statement.';
COMMENT ON COLUMN gemsods.audit_logged_actions.application_name IS 'Application name set when this gemsods event occurred. Can be changed in-session by client.';
COMMENT ON COLUMN gemsods.audit_logged_actions.action IS 'Action type; I = insert, D = delete, U = update, T = truncate';
COMMENT ON COLUMN gemsods.audit_logged_actions.row_data IS 'Record value. Null for statement-level trigger. For INSERT this is the new tuple. For DELETE and UPDATE it is the old tuple.';
COMMENT ON COLUMN gemsods.audit_logged_actions.changed_fields IS 'New values of fields changed by UPDATE. Null except for row-level UPDATE events.';
COMMENT ON COLUMN gemsods.audit_logged_actions.statement_only IS '''t'' if gemsods event is from an FOR EACH STATEMENT trigger, ''f'' for FOR EACH ROW';
 
 CREATE INDEX audit_logged_actions_relid_idx ON gemsods.audit_logged_actions(relid);
CREATE INDEX audit_logged_actions_action_tstamp_tx_stm_idx ON gemsods.audit_logged_actions(action_tstamp_stm);
CREATE INDEX audit_logged_actions_action_idx ON gemsods.audit_logged_actions(action);

CREATE OR REPLACE FUNCTION gemsods.audit_ods_master_changes_func() RETURNS TRIGGER AS $body$
DECLARE
    gemsods_row gemsods.audit_logged_actions;
    include_values BOOLEAN;
    log_diffs BOOLEAN;
    h_old hstore;
    h_new hstore;
    excluded_cols text[] = ARRAY[]::text[];
    audit_user text;
BEGIN
    IF TG_WHEN <> 'AFTER' THEN
        RAISE EXCEPTION 'gemsods.if_modified_func() may only run as an AFTER trigger';
    END IF;
 
    IF TG_OP = 'DELETE' THEN
		audit_user := session_user;
    ELSE
		audit_user := NEW.config_user;
    END IF;
    
    gemsods_row = ROW(
        NEXTVAL('gemsods.audit_logged_actions_event_id_seq'), -- event_id
        TG_TABLE_SCHEMA::text,                        -- schema_name
        TG_TABLE_NAME::text,                          -- table_name
        TG_RELID,                                     -- relation OID for much quicker searches
        audit_user::text,                        -- session_user_name
        current_timestamp,                            -- action_tstamp_tx
        statement_timestamp(),                        -- action_tstamp_stm
        clock_timestamp(),                            -- action_tstamp_clk
        txid_current(),                               -- transaction ID
        'ODS_MASTER Configuration',                   -- application name
        inet_client_addr(),                           -- client_addr
        inet_client_port(),                           -- client_port
        current_query(),                              -- top-level query or queries (if multistatement) from client
        substring(TG_OP,1,1),                         -- action
        NULL, NULL,                                   -- row_data, changed_fields
        'f'                                           -- statement_only
        );
 
    IF NOT TG_ARGV[0]::BOOLEAN IS DISTINCT FROM 'f'::BOOLEAN THEN
        gemsods_row.client_query = NULL;
    END IF;
 
    IF TG_ARGV[1] IS NOT NULL THEN
        excluded_cols = TG_ARGV[1]::text[];
    END IF;
 
    IF (TG_OP = 'UPDATE' AND TG_LEVEL = 'ROW') THEN
        gemsods_row.row_data = hstore(OLD.*);
        gemsods_row.changed_fields =  (hstore(NEW.*) - gemsods_row.row_data) - excluded_cols;
        IF gemsods_row.changed_fields = hstore('') THEN
            -- All changed fields are ignored. Skip this update.
            RETURN NULL;
        END IF;
    ELSIF (TG_OP = 'DELETE' AND TG_LEVEL = 'ROW') THEN
        gemsods_row.row_data = hstore(OLD.*) - excluded_cols;
    ELSIF (TG_OP = 'INSERT' AND TG_LEVEL = 'ROW') THEN
        gemsods_row.row_data = hstore(NEW.*) - excluded_cols;
    ELSIF (TG_LEVEL = 'STATEMENT' AND TG_OP IN ('INSERT','UPDATE','DELETE','TRUNCATE')) THEN
        gemsods_row.statement_only = 't';
    ELSE
        RAISE EXCEPTION '[gemsods.if_modified_func] - Trigger func added as trigger for unhandled case: %, %',TG_OP, TG_LEVEL;
        RETURN NULL;
    END IF;
    INSERT INTO gemsods.audit_logged_actions VALUES (gemsods_row.*);
    RETURN NULL;
END;
$body$
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, gemsods;

CREATE OR REPLACE FUNCTION gemsods.audit_table(target_table regclass, audit_rows BOOLEAN, audit_query_text BOOLEAN, ignored_cols text[]) RETURNS void AS $body$
DECLARE
  stm_targets text = 'INSERT OR UPDATE OR DELETE OR TRUNCATE';
  _q_txt text;
  _ignored_cols_snip text = '';
BEGIN
    EXECUTE 'DROP TRIGGER IF EXISTS audit_trigger_row ON ' || quote_ident(target_table::text);
    EXECUTE 'DROP TRIGGER IF EXISTS audit_trigger_stm ON ' || quote_ident(target_table::text);
 
    IF audit_rows THEN
        IF array_length(ignored_cols,1) > 0 THEN
            _ignored_cols_snip = ', ' || quote_literal(ignored_cols);
        END IF;
        _q_txt = 'CREATE TRIGGER audit_trigger_row AFTER INSERT OR UPDATE OR DELETE ON ' || 
                 quote_ident(target_table::text) || 
                 ' FOR EACH ROW EXECUTE PROCEDURE audit.if_modified_func(' ||
                 quote_literal(audit_query_text) || _ignored_cols_snip || ');';
        RAISE NOTICE '%',_q_txt;
        EXECUTE _q_txt;
        stm_targets = 'TRUNCATE';
    ELSE
    END IF;
 
    _q_txt = 'CREATE TRIGGER audit_trigger_stm AFTER ' || stm_targets || ' ON ' ||
             quote_ident(target_table::text) ||
             ' FOR EACH STATEMENT EXECUTE PROCEDURE audit.if_modified_func('||
             quote_literal(audit_query_text) || ');';
    RAISE NOTICE '%',_q_txt;
    EXECUTE _q_txt;
 
END;
$body$
LANGUAGE 'plpgsql';

CREATE OR REPLACE FUNCTION gemsods.audit_table(target_table regclass, audit_rows BOOLEAN, audit_query_text BOOLEAN) RETURNS void AS $body$
SELECT gemsods.audit_table($1, $2, $3, ARRAY[]::text[]);
$body$ LANGUAGE SQL;

CREATE OR REPLACE FUNCTION gemsods.audit_table(target_table regclass) RETURNS void AS $$
SELECT gemsods.audit_table($1, BOOLEAN 't', BOOLEAN 't');
$$ LANGUAGE 'sql';

