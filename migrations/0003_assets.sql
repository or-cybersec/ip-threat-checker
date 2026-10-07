create table if not exists assets (
  id serial primary key,
  kind text not null,
  value text not null,
  note text not null,
  created_at timestamptz not null default now(),
  unique (kind, value)
);
