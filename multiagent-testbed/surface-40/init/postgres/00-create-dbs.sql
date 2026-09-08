-- Separate databases so Group 2/3/4 apps can share one Postgres without
-- colliding on schema. Chatwoot needs superuser + vector.
CREATE DATABASE botpress;
CREATE DATABASE typebot;
CREATE DATABASE chatwoot_production;
CREATE DATABASE papercups;
CREATE DATABASE chaskiq;
CREATE DATABASE n8n;
CREATE DATABASE metabase;

\c chatwoot_production
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

\c typebot
CREATE EXTENSION IF NOT EXISTS pgcrypto;

\c papercups
CREATE EXTENSION IF NOT EXISTS pgcrypto;

\c chaskiq
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

\c botpress
CREATE EXTENSION IF NOT EXISTS pgcrypto;
