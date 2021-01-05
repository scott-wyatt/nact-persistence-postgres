module.exports.create = (
  tablePrefix,
  schema = null,
  eventTable = 'event_journal',
  snapshotTable = 'snapshot_store',
  persistenceKey = 'persistence_key',
  sequenceNr = 'sequence_nr'
) => {
  const crypto = `
    CREATE EXTENSION IF NOT EXISTS pgcrypto;
  `;

  const triggerGenEventFunctionQuery = `
    CREATE OR REPLACE FUNCTION generate_${tablePrefix}${eventTable}_encryption()
      RETURNS TRIGGER
      LANGUAGE PLPGSQL

      AS

      $$

      DECLARE
        encryption_key UUID;

      BEGIN
        IF NEW.${sequenceNr} = 1 THEN

          encryption_key := MD5(random()::text)::uuid;

          INSERT INTO ${schema ? schema + '.' : ''}${tablePrefix}${eventTable}_encryption (
            ${persistenceKey},
            encryption_key,
            created_at
          ) VALUES (
            NEW.${persistenceKey},
            encryption_key,
            NEW.created_at
          );

        ELSE

          encryption_key := (
            SELECT e.encryption_key FROM ${schema ? schema + '.' : ''}${tablePrefix}${eventTable}_encryption e
            WHERE e.${persistenceKey} = NEW.${persistenceKey}
            LIMIT 1
          );

        END IF;

        NEW.data := encrypt_${tablePrefix}${eventTable}(NEW.data, NEW.annotations, encryption_key, false);

        RETURN NEW;
      END;
      $$;
  `;

  const triggerGenSnapshotFunctionQuery = `
    CREATE OR REPLACE FUNCTION generate_${tablePrefix}${snapshotTable}_encryption()
      RETURNS TRIGGER
      LANGUAGE PLPGSQL

      AS

      $$

      DECLARE
        encryption_key UUID;
        annotations jsonb;

      BEGIN

        encryption_key := (
          SELECT e.encryption_key FROM ${schema ? schema + '.' : ''}${tablePrefix}${eventTable}_encryption e
          WHERE e.${persistenceKey} = NEW.${persistenceKey}
          LIMIT 1
        );

        annotations := (
          SELECT e.annotations FROM ${schema ? schema + '.' : ''}${tablePrefix}${eventTable} e
          WHERE e.${persistenceKey} = NEW.${persistenceKey} AND e.${sequenceNr} = NEW.${sequenceNr}
          LIMIT 1
        );

        NEW.data := encrypt_${tablePrefix}${eventTable}(NEW.data, annotations, encryption_key, false);

        RETURN NEW;
      END;
      $$;
  `;

  const triggerGenConstraintEventFunctionQuery = `
    CREATE OR REPLACE FUNCTION generate_${tablePrefix}${eventTable}_constraint()
      RETURNS TRIGGER
      LANGUAGE PLPGSQL

      AS

      $$

      DECLARE
        constrained BOOLEAN;

      BEGIN

        constrained = evaluate_${tablePrefix}${eventTable}_constraint(NEW.data, NEW.annotations, true);

        RETURN NEW;
      END;
      $$;
  `;

  const triggerEvaluateConstraintFunctionQuery = `
    CREATE OR REPLACE FUNCTION evaluate_${tablePrefix}${eventTable}_constraint(data jsonb, annotations jsonb, insert_constraint boolean)
      RETURNS BOOLEAN
      LANGUAGE PLPGSQL

      AS

      $$

      DECLARE
        constraining jsonb;
        _key         text;
        _value       text;

      BEGIN

        constraining := COALESCE(
          CASE
            WHEN (annotations #> '{constraint}') IS NULL then NULL
            ELSE (annotations #> '{constraint}')
          END,
          '{}'::jsonb
        );

        FOR _key, _value IN
          SELECT * FROM jsonb_each_text(constraining)
        LOOP

        END LOOP;

        RETURN true;
      END;
      $$;
  `;

  const triggerDropConstraintEventFunctionQuery = `
    CREATE OR REPLACE FUNCTION drop_${tablePrefix}${eventTable}_constraint()
      RETURNS TRIGGER
      LANGUAGE PLPGSQL

      AS

      $$

      BEGIN
        /* TODO delete or not delete if all of the records are deleted or not */
        UPDATE ${schema ? schema + '.' : ''}${tablePrefix}${eventTable}_constraint c
        SET is_deleted = NEW.is_deleted
        WHERE c.${persistenceKey} = NEW.${persistenceKey};

        RETURN NEW;
      END;
      $$;
  `;

  const triggerEncryptFunctionQuery = `
    CREATE OR REPLACE FUNCTION encrypt_${tablePrefix}${eventTable}(data jsonb, annotations jsonb, encryption_key uuid, is_deleted boolean)
      RETURNS JSONB
      LANGUAGE PLPGSQL

      AS

      $$

      DECLARE
        encrypting jsonb;
        _key       text;
        _value     text;
        _current   text[];
        allowed_types CONSTANT text[] := ARRAY[
          ('aes'::text),
          ('sha256'::text),
          ('bcrypt'::text),
          ('bcrypt6'::text),
          ('bcrypt7'::text),
          ('bcrypt8'::text),
          ('md5'::text),
          ('hmac'::text)
        ];
        default_type CONSTANT text := 'aes'::text;

      /*
        encrypting each data key eg: { "my_key": "sha256", "my_nested.key": "aes" }
      */

      BEGIN
        IF NOT is_deleted THEN

          encrypting := COALESCE(
            CASE
              WHEN (annotations #> '{encrypt}') IS NULL then NULL
              ELSE (annotations #> '{encrypt}')
            END,
            '{}'::jsonb
          );

          FOR _key, _value IN
              SELECT * FROM jsonb_each_text(encrypting)
          LOOP

             _current := string_to_array(_key, '.');

             IF data #> _current IS NOT NULL THEN

              IF _value = 'sha256' THEN
                data := jsonb_set(data, _current, to_jsonb(digest((data #>> _current), 'sha256')::text), true);
              ELSIF _value = 'hmac' THEN
                data := jsonb_set(data, _current, to_jsonb(hmac((data #>> _current), encryption_key::text, 'sha256')::text), true);
              ELSIF _value = 'bcrypt' THEN
                data := jsonb_set(data, _current, to_jsonb(crypt((data #>> _current), gen_salt('bf', 5))::text), true);
              ELSIF _value = 'bcrypt6' THEN
                data := jsonb_set(data, _current, to_jsonb(crypt((data #>> _current), gen_salt('bf', 6))::text), true);
              ELSIF _value = 'bcrypt7' THEN
                data := jsonb_set(data, _current, to_jsonb(crypt((data #>> _current), gen_salt('bf', 7))::text), true);
              ELSIF _value = 'bcrypt8' THEN
                data := jsonb_set(data, _current, to_jsonb(crypt((data #>> _current), gen_salt('bf', 8))::text), true);
              ELSIF _value = 'md5' THEN
                data := jsonb_set(data, _current, to_jsonb(crypt((data #>> _current), gen_salt('md5'))::text), true);
              ELSE
                data := jsonb_set(data, _current, to_jsonb(pgp_sym_encrypt((data #>> _current), encryption_key::text, 'compress-algo=0, cipher-algo=aes256')::text), true);
              END IF;

             END IF;
          END LOOP;

        END IF;

        RETURN data;
      END;
      $$;
  `;

  const triggerDecryptFunctionQuery = `
    CREATE OR REPLACE FUNCTION decrypt_${tablePrefix}${eventTable}(data jsonb, annotations jsonb, encryption_key uuid, is_deleted boolean)
      RETURNS JSONB
      LANGUAGE PLPGSQL

      AS

      $$

      DECLARE
        decrypting jsonb;
        _key       text;
        _value     text;
        _current   text[];
        allowed_types CONSTANT text[] := ARRAY[
          ('aes'::text),
          ('sha256'::text),
          ('bcrypt'::text),
          ('bcrypt6'::text),
          ('bcrypt7'::text),
          ('bcrypt8'::text),
          ('md5'::text),
          ('hmac'::text)
        ];
        default_type CONSTANT text := 'aes'::text;

      /*
        decrypting each data key and casting back to type eg: { "my_key": "sha256", "my_nested.key": "aes" }
      */

      BEGIN
        IF NOT is_deleted THEN
          decrypting := COALESCE(
            CASE
              WHEN (annotations #> '{encrypt}') IS NULL THEN NULL
              ELSE (annotations #> '{encrypt}')
            END,
            '{}'::jsonb
          );

          FOR _key, _value IN
            SELECT * FROM jsonb_each_text(decrypting)
          LOOP

             _current := string_to_array(_key, '.');

             IF data #> _current IS NOT NULL THEN

               IF _value = 'sha256' THEN
                 data := data;
               ELSIF _value = 'bcrypt' THEN
                 data := data;
               ELSIF _value = 'bcrypt6' THEN
                 data := data;
               ELSIF _value = 'bcrypt7' THEN
                 data := data;
               ELSIF _value = 'bcrypt8' THEN
                 data := data;
               ELSIF _value = 'md5' THEN
                 data := data;
               ELSIF _value = 'hmac' THEN
                 data := data;
               ELSE
                 data := jsonb_set(data, _current, to_jsonb(pgp_sym_decrypt((data #>> _current)::bytea, encryption_key::text, 'compress-algo=0, cipher-algo=aes256')), true);
               END IF;

             END IF;
          END LOOP;

        END IF;

        RETURN data;
      END;
      $$;
  `;

  const triggerEventGenEncryptQuery = `
    DROP TRIGGER IF EXISTS generate_${tablePrefix}${eventTable}_encryption ON ${schema ? schema + '.' : ''}${tablePrefix}${eventTable} CASCADE;

    CREATE TRIGGER generate_${tablePrefix}${eventTable}_encryption
    BEFORE INSERT ON ${schema ? schema + '.' : ''}${tablePrefix}${eventTable}
    FOR EACH ROW
    EXECUTE PROCEDURE generate_${tablePrefix}${eventTable}_encryption();
  `;

  const triggerEventEvaluateConstraintQuery = `
    DROP TRIGGER IF EXISTS evaluate_${tablePrefix}${eventTable}_constraint ON ${schema ? schema + '.' : ''}${tablePrefix}${eventTable} CASCADE;

    CREATE TRIGGER evaluate_${tablePrefix}${eventTable}_constraint
    BEFORE INSERT ON ${schema ? schema + '.' : ''}${tablePrefix}${eventTable}
    FOR EACH ROW
    EXECUTE PROCEDURE generate_${tablePrefix}${eventTable}_constraint();
  `;

  const triggerEventDropConstraintQuery = `
    DROP TRIGGER IF EXISTS drop_${tablePrefix}${eventTable}_constraint ON ${schema ? schema + '.' : ''}${tablePrefix}${eventTable} CASCADE;

    CREATE TRIGGER drop_${tablePrefix}${eventTable}_constraint
    AFTER UPDATE ON ${schema ? schema + '.' : ''}${tablePrefix}${eventTable}
    FOR EACH ROW
    WHEN (OLD.is_deleted IS DISTINCT FROM NEW.is_deleted)
    EXECUTE PROCEDURE drop_${tablePrefix}${eventTable}_constraint();
  `;

  const triggerSnapshotGenEncryptQuery = `
    DROP TRIGGER IF EXISTS generate_${tablePrefix}${snapshotTable}_encryption ON ${schema ? schema + '.' : ''}${tablePrefix}${snapshotTable} CASCADE;

    CREATE TRIGGER generate_${tablePrefix}${snapshotTable}_encryption
    BEFORE INSERT ON ${schema ? schema + '.' : ''}${tablePrefix}${snapshotTable}
    FOR EACH ROW
    EXECUTE PROCEDURE generate_${tablePrefix}${snapshotTable}_encryption();
  `;

  const schemaQuery = `
    CREATE SCHEMA IF NOT EXISTS ${schema};
  `;

  const eventTableQuery = `
    CREATE TABLE IF NOT EXISTS ${schema ? schema + '.' : ''}${tablePrefix}${eventTable} (
      ordering BIGSERIAL NOT NULL PRIMARY KEY,
      ${persistenceKey} VARCHAR(255) NOT NULL,
      ${sequenceNr} BIGINT NOT NULL,
      created_at BIGINT NOT NULL,
      data JSONB NOT NULL,
      metadata JSONB DEFAULT '{}'::jsonb,
      annotations JSONB DEFAULT '{}'::jsonb,
      is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
      tags TEXT ARRAY DEFAULT ARRAY[]::TEXT[],
      CONSTRAINT ${tablePrefix}${eventTable}_uq UNIQUE (${persistenceKey}, ${sequenceNr})
    );

    CREATE INDEX IF NOT EXISTS ${tablePrefix}${eventTable}_data ON ${schema ? schema + '.' : ''}${tablePrefix}${eventTable} USING GIN (data jsonb_path_ops);
  `;

  const eventTableEncryptionQuery = `
    CREATE TABLE IF NOT EXISTS ${schema ? schema + '.' : ''}${tablePrefix}${eventTable}_encryption (
      ${persistenceKey} VARCHAR(255) NOT NULL,
      encryption_key UUID NOT NULL,
      created_at BIGINT NOT NULL,
      deleted_at BIGINT,
      is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
      tags TEXT ARRAY DEFAULT ARRAY[]::TEXT[],
      CONSTRAINT ${tablePrefix}${eventTable}_encryption_uq UNIQUE (${persistenceKey})
    );
  `;

  const eventTableConstraintQuery = `
    CREATE TABLE IF NOT EXISTS ${schema ? schema + '.' : ''}${tablePrefix}${eventTable}_constraint (
      /* What Record Primary Key that holds the constraint */
      ${persistenceKey} VARCHAR(255) NOT NULL,
      /* The constraint label */
      label VARCHAR(255) NOT NULL,
      /* The record column keys that are constrained */
      keys JSONB NOT NULL DEFAULT '{}'::jsonb,
      /* The record column keys' values that are constrained */
      values JSONB NOT NULL DEFAULT '{}'::jsonb,
      /* When the constraint was locked */
      created_at BIGINT NOT NULL,
      /* If the Record was Deleted */
      is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
      /* Set Foreign Keys to the Rule */
      FOREIGN KEY (label, keys) REFERENCES ${schema ? schema + '.' : ''}${tablePrefix}${eventTable}_constraint_rule (label, keys),
      /* Create a unique constraint for the label, keys, values */
      CONSTRAINT ${tablePrefix}${eventTable}_constraint_uq UNIQUE (label, keys, values)
    );
  `;

  const eventTableConstraintRuleQuery = `
    CREATE TABLE IF NOT EXISTS ${schema ? schema + '.' : ''}${tablePrefix}${eventTable}_constraint_rule (
      /* The constraint label */
      label VARCHAR(255) NOT NULL,
      /* The record columns that are constrained */
      keys JSONB NOT NULL DEFAULT '{}'::jsonb,
      /* When the constraint was created */
      created_at BIGINT NOT NULL,
      /* If the Record was Deleted */
      is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
      /* Set the Primary Keys */
      PRIMARY KEY(label, keys)
      /* CONSTRAINT ${tablePrefix}${eventTable}_constraint_rule_uq UNIQUE (label, keys) */
    );
  `;

  const eventTableViewQuery = `
    CREATE OR REPLACE VIEW ${schema ? schema + '.' : ''}${tablePrefix}${eventTable}_view AS
      SELECT
       v.ordering,
       v.${persistenceKey},
       v.${sequenceNr},
       v.data,
       v.created_at,
       v.tags,
       v.metadata,
       v.annotations,
       v.is_deleted
      FROM (
        SELECT
          vals.ordering,
          vals.${persistenceKey},
          vals.${sequenceNr},
          vals.created_at,
          vals.metadata,
          vals.annotations,
          vals.is_deleted,
          vals.tags,
          decrypt_${tablePrefix}${eventTable}(vals.data, vals.annotations, enc.encryption_key, enc.is_deleted) AS data
        FROM ${schema ? schema + '.' : ''}${tablePrefix}${eventTable} vals
          LEFT OUTER JOIN
            (SELECT
              ${persistenceKey},
              encryption_key,
              is_deleted
            FROM
              ${schema ? schema + '.' : ''}${tablePrefix}${eventTable}_encryption
            ) AS enc
            ON enc.${persistenceKey} = vals.${persistenceKey}
      ) v;
  `;

  const snapshotTableQuery = `
    CREATE TABLE IF NOT EXISTS ${schema ? schema + '.' : ''}${tablePrefix}${snapshotTable} (
      ordering BIGSERIAL NOT NULL PRIMARY KEY,
      ${persistenceKey} VARCHAR(255) NOT NULL,
      ${sequenceNr} BIGINT NOT NULL,
      created_at BIGINT NOT NULL,
      data JSONB NOT NULL,
      is_deleted BOOLEAN NOT NULL DEFAULT FALSE
    );
  `;

  const snapshotTableViewQuery = `
    CREATE OR REPLACE VIEW ${schema ? schema + '.' : ''}${tablePrefix}${snapshotTable}_view AS
      SELECT
        v.ordering,
        v.${persistenceKey},
        v.${sequenceNr},
        v.data,
        v.created_at,
        v.tags,
        v.metadata,
        v.annotations,
        v.is_deleted
      FROM (
        SELECT
          vals.ordering,
          vals.${persistenceKey},
          vals.${sequenceNr},
          vals.created_at,
          evn.tags,
          evn.metadata,
          evn.annotations,
          vals.is_deleted,
          decrypt_${tablePrefix}${eventTable}(vals.data, evn.annotations, enc.encryption_key, enc.is_deleted) AS data
       FROM ${schema ? schema + '.' : ''}${tablePrefix}${snapshotTable} vals
        LEFT OUTER JOIN
          (SELECT
            ${persistenceKey},
            ${sequenceNr},
            tags,
            annotations,
            metadata
          FROM
            ${schema ? schema + '.' : ''}${tablePrefix}${eventTable}
          ) AS evn
        ON evn.${persistenceKey} = vals.${persistenceKey} AND evn.${sequenceNr} = vals.${sequenceNr}
        LEFT OUTER JOIN
          (SELECT
            ${persistenceKey},
            encryption_key,
            is_deleted
          FROM
            ${schema ? schema + '.' : ''}${tablePrefix}${eventTable}_encryption
          ) AS enc
        ON enc.${persistenceKey} = vals.${persistenceKey}
    ) v;
  `;

  return [
    // Schemas
    schema ? schemaQuery : null,

    // Plugins
    crypto,

    // Tables
    eventTableQuery,
    eventTableEncryptionQuery,
    eventTableConstraintRuleQuery,
    eventTableConstraintQuery,
    snapshotTableQuery,

    // Functions
    triggerEncryptFunctionQuery,
    triggerDecryptFunctionQuery,
    triggerEvaluateConstraintFunctionQuery,
    triggerDropConstraintEventFunctionQuery,

    // Event Triggers
    triggerGenEventFunctionQuery,
    triggerEventGenEncryptQuery,
    triggerGenConstraintEventFunctionQuery,
    triggerEventEvaluateConstraintQuery,
    triggerEventDropConstraintQuery,

    // Snapshot Triggers
    triggerGenSnapshotFunctionQuery,
    triggerSnapshotGenEncryptQuery,

    // Views
    eventTableViewQuery,
    snapshotTableViewQuery
  ].filter(n => n).join('\n');
};

module.exports.destroy = (tablePrefix, schema = null, eventTable = 'event_journal', snapshotTable = 'snapshot_store') => {
  const schemaQuery = `
    DROP SCHEMA IF EXISTS ${schema} CASCADE;
  `;

  const eventTableViewQuery = `
    DROP VIEW IF EXISTS ${schema ? schema + '.' : ''}${tablePrefix}${eventTable}_view CASCADE;
  `;
  const snapshotTableViewQuery = `
    DROP VIEW IF EXISTS ${schema ? schema + '.' : ''}${tablePrefix}${snapshotTable}_view CASCADE;
  `;

  const triggerQuery = `
    DROP TRIGGER IF EXISTS generate_${tablePrefix}${eventTable}_encryption ON ${schema ? schema + '.' : ''}${tablePrefix}${eventTable} CASCADE;
    DROP TRIGGER IF EXISTS generate_${tablePrefix}${snapshotTable}_encryption ON ${schema ? schema + '.' : ''}${tablePrefix}${snapshotTable} CASCADE;
    DROP TRIGGER IF EXISTS evaluate_${tablePrefix}${eventTable}_constraint ON ${schema ? schema + '.' : ''}${tablePrefix}${eventTable} CASCADE;
    DROP TRIGGER IF EXISTS drop_${tablePrefix}${eventTable}_constraint ON ${schema ? schema + '.' : ''}${tablePrefix}${eventTable} CASCADE;
    DROP FUNCTION IF EXISTS generate_${tablePrefix}${eventTable}_encryption;
    DROP FUNCTION IF EXISTS generate_${tablePrefix}${snapshotTable}_encryption;
    DROP FUNCTION IF EXISTS evaluate_${tablePrefix}${eventTable}_constraint;
    DROP FUNCTION IF EXISTS drop_${tablePrefix}${eventTable}_constraint;
  `;

  const functionEncryptQuery = `
    DROP FUNCTION IF EXISTS encrypt_${tablePrefix}${eventTable};
  `;

  const functionDecryptQuery = `
    DROP FUNCTION IF EXISTS decrypt_${tablePrefix}${eventTable};
  `;

  const eventTableQuery = `
    DROP TABLE IF EXISTS ${schema ? schema + '.' : ''}${tablePrefix}${eventTable} CASCADE;
  `;

  const eventTableEncryptionQuery = `
    DROP TABLE IF EXISTS ${schema ? schema + '.' : ''}${tablePrefix}${eventTable}_encryption CASCADE;
  `;

  const eventTableConstraintQuery = `
    DROP TABLE IF EXISTS ${schema ? schema + '.' : ''}${tablePrefix}${eventTable}_constraint CASCADE;
  `;

  const eventTableConstraintRuleQuery = `
    DROP TABLE IF EXISTS ${schema ? schema + '.' : ''}${tablePrefix}${eventTable}_constraint_rule CASCADE;
  `;

  const snapshotTableQuery = `
    DROP TABLE IF EXISTS ${schema ? schema + '.' : ''}${tablePrefix}${snapshotTable} CASCADE;
  `;

  // IF the schema is dropped cascade, then it will by default also drop the tables on the schema
  return [
    // Schemas
    schema ? schemaQuery : null,

    // Plugins

    // Views
    eventTableViewQuery,
    snapshotTableViewQuery,

    // Triggers
    triggerQuery,
    functionEncryptQuery,
    functionDecryptQuery,

    // Tables
    eventTableQuery,
    eventTableEncryptionQuery,
    eventTableConstraintQuery,
    eventTableConstraintRuleQuery,
    snapshotTableQuery
  ].filter(n => n).join('\n');
};
