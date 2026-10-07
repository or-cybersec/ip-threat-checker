create table if not exists lookups (
  id serial primary key,
  ip text not null,
  verdict text not null,
  score integer not null,
  summary text not null,
  sources jsonb not null,
  result jsonb not null,
  created_at timestamptz not null default now()
);

create index if not exists lookups_created_idx on lookups (created_at desc);
create index if not exists lookups_ip_idx on lookups (ip);
