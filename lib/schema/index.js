module.exports.create = (tablePrefix, schema = null, eventTable = 'event_journal', snapshotTable = 'snapshot_store') => {
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
        IF NEW.sequence_nr = 1 THEN

          encryption_key := MD5(random()::text)::uuid;

          INSERT INTO ${schema ? schema + '.' : ''}${tablePrefix}${eventTable}_encryption (
            persistence_key,
            encryption_key,
            created_at
          ) VALUES (
            NEW.persistence_key,
            encryption_key,
            NEW.created_at
          );

        ELSE

          encryption_key := (
            SELECT e.encryption_key FROM ${schema ? schema + '.' : ''}${tablePrefix}${eventTable}_encryption e
            WHERE e.persistence_key = NEW.persistence_key
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
          WHERE e.persistence_key = NEW.persistence_key
          LIMIT 1
        );

        annotations := (
          SELECT e.annotations FROM ${schema ? schema + '.' : ''}${tablePrefix}${eventTable} e
          WHERE e.persistence_key = NEW.persistence_key AND e.sequence_nr = NEW.sequence_nr
          LIMIT 1
        );

        NEW.data := encrypt_${tablePrefix}${eventTable}(NEW.data, annotations, encryption_key, false);

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
          ('jsonb'::text),
          ('text'::text),
          ('boolean'::text),
          ('int'::text),
          ('bigint'::text),
          ('numeric'::text),
          ('double precision'::text),
          ('date'::text)
        ];
        default_type CONSTANT text := 'jsonb'::text;

      /*
        encrypting each data key eg: { "my_key": "jsonb", "my_nested.key": "text" }
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

              data := jsonb_set(data, _current, to_jsonb(pgp_sym_encrypt((data #>> _current), encryption_key::text, 'compress-algo=1, cipher-algo=aes256')::text), true);

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
          ('jsonb'::text),
          ('text'::text),
          ('boolean'::text),
          ('int'::text),
          ('bigint'::text),
          ('numeric'::text),
          ('double precision'::text),
          ('date'::text)
        ];
        default_type CONSTANT text := 'jsonb'::text;

      /*
        decrypting each data key and casting back to type eg: { "my_key": "jsonb", "my_nested.key": "text" }
      */

      BEGIN
        IF NOT is_deleted THEN
          decrypting := COALESCE(
            CASE
              WHEN (annotations #> '{encrypt}') IS NULL then NULL
              ELSE (annotations #> '{encrypt}')
            END,
            '{}'::jsonb
          );

          FOR _key, _value IN
              SELECT * FROM jsonb_each_text(decrypting)
          LOOP

             _current := string_to_array(_key, '.');

             IF data #> _current IS NOT NULL THEN

               data := jsonb_set(data, _current, to_jsonb(pgp_sym_decrypt((data #>> _current)::bytea, encryption_key::text, 'compress-algo=1, cipher-algo=aes256')::text), true);

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
      persistence_key VARCHAR(255) NOT NULL,
      sequence_nr BIGINT NOT NULL,
      created_at BIGINT NOT NULL,
      data JSONB NOT NULL,
      metadata JSONB DEFAULT '{}'::jsonb,
      annotations JSONB DEFAULT '{}'::jsonb,
      is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
      tags TEXT ARRAY DEFAULT ARRAY[]::TEXT[],
      CONSTRAINT ${tablePrefix}${eventTable}_uq UNIQUE (persistence_key, sequence_nr)
    );
  `;

  const eventTableEncryptionQuery = `
    CREATE TABLE IF NOT EXISTS ${schema ? schema + '.' : ''}${tablePrefix}${eventTable}_encryption (
      persistence_key VARCHAR(255) NOT NULL,
      encryption_key UUID NOT NULL,
      created_at BIGINT NOT NULL,
      deleted_at BIGINT,
      is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
      tags TEXT ARRAY DEFAULT ARRAY[]::TEXT[],
      CONSTRAINT ${tablePrefix}${eventTable}_encryption_uq UNIQUE (persistence_key)
    );
  `;

  const eventTableViewQuery = `
    CREATE OR REPLACE VIEW ${schema ? schema + '.' : ''}${tablePrefix}${eventTable}_view AS
      SELECT
       v.ordering,
       v.persistence_key,
       v.sequence_nr,
       v.data,
       v.created_at,
       v.tags,
       v.metadata,
       v.annotations,
       v.is_deleted
      FROM (
        SELECT
          vals.ordering,
          vals.persistence_key,
          vals.sequence_nr,
          vals.created_at,
          vals.metadata,
          vals.annotations,
          vals.is_deleted,
          vals.tags,
          decrypt_${tablePrefix}${eventTable}(vals.data, vals.annotations, enc.encryption_key, enc.is_deleted) AS data
        FROM ${schema ? schema + '.' : ''}${tablePrefix}${eventTable} vals
          LEFT OUTER JOIN
            (SELECT
              persistence_key,
              encryption_key,
              is_deleted
            FROM
              ${schema ? schema + '.' : ''}${tablePrefix}${eventTable}_encryption
            ) AS enc
            ON enc.persistence_key = vals.persistence_key
      ) v;
  `;

  const snapshotTableQuery = `
    CREATE TABLE IF NOT EXISTS ${schema ? schema + '.' : ''}${tablePrefix}${snapshotTable} (
      ordering BIGSERIAL NOT NULL PRIMARY KEY,
      persistence_key VARCHAR(255) NOT NULL,
      sequence_nr BIGINT NOT NULL,
      created_at BIGINT NOT NULL,
      data JSONB NOT NULL,
      is_deleted BOOLEAN NOT NULL DEFAULT FALSE
    );
  `;

  const snapshotTableViewQuery = `
    CREATE OR REPLACE VIEW ${schema ? schema + '.' : ''}${tablePrefix}${snapshotTable}_view AS
      SELECT
        v.ordering,
        v.persistence_key,
        v.sequence_nr,
        v.data,
        v.created_at,
        v.tags,
        v.metadata,
        v.annotations,
        v.is_deleted
      FROM (
        SELECT
          vals.ordering,
          vals.persistence_key,
          vals.sequence_nr,
          vals.created_at,
          evn.tags,
          evn.metadata,
          evn.annotations,
          vals.is_deleted,
          decrypt_${tablePrefix}${eventTable}(vals.data, evn.annotations, enc.encryption_key, enc.is_deleted) AS data
       FROM ${schema ? schema + '.' : ''}${tablePrefix}${snapshotTable} vals
        LEFT OUTER JOIN
          (SELECT
            persistence_key,
            sequence_nr,
            tags,
            annotations,
            metadata
          FROM
            ${schema ? schema + '.' : ''}${tablePrefix}${eventTable}
          ) AS evn
        ON evn.persistence_key = vals.persistence_key AND evn.sequence_nr = vals.sequence_nr
        LEFT OUTER JOIN
          (SELECT
            persistence_key,
            encryption_key,
            is_deleted
          FROM
            ${schema ? schema + '.' : ''}${tablePrefix}${eventTable}_encryption
          ) AS enc
        ON enc.persistence_key = vals.persistence_key
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
    snapshotTableQuery,

    // Functions
    triggerEncryptFunctionQuery,
    triggerDecryptFunctionQuery,

    // Event Triggers
    triggerGenEventFunctionQuery,
    triggerEventGenEncryptQuery,

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
    DROP FUNCTION IF EXISTS generate_${tablePrefix}${eventTable}_encryption;
    DROP FUNCTION IF EXISTS generate_${tablePrefix}${snapshotTable}_encryption;
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
    snapshotTableQuery
  ].filter(n => n).join('\n');
};
