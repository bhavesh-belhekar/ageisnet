CREATE CONSTRAINT container_id_unique IF NOT EXISTS
FOR (c:Container) REQUIRE c.id IS UNIQUE;

CREATE CONSTRAINT container_name_unique IF NOT EXISTS
FOR (c:Container) REQUIRE c.name IS UNIQUE;

CREATE INDEX edge_last_seen IF NOT EXISTS
FOR () - [e:CONNECTS_TO] - () ON (e.last_seen);