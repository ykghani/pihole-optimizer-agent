// Neo4j schema initialization for the SOC agent knowledge graph.
//
// Run once after first deployment:
//   cat neo4j/seed_schema.cypher | docker exec -i neo4j cypher-shell -u neo4j -p PASSWORD
//
// MERGE semantics in all agent queries prevent duplicates, but uniqueness
// constraints add a database-level guarantee and improve lookup performance.

// Uniqueness constraints (also create implicit indexes)
CREATE CONSTRAINT device_ip IF NOT EXISTS
  FOR (d:Device) REQUIRE d.ip IS UNIQUE;

CREATE CONSTRAINT domain_name IF NOT EXISTS
  FOR (d:Domain) REQUIRE d.name IS UNIQUE;

CREATE CONSTRAINT ip_address IF NOT EXISTS
  FOR (i:IP) REQUIRE i.address IS UNIQUE;

CREATE CONSTRAINT alert_id IF NOT EXISTS
  FOR (a:Alert) REQUIRE a.alert_id IS UNIQUE;

CREATE CONSTRAINT finding_id IF NOT EXISTS
  FOR (f:Finding) REQUIRE f.finding_id IS UNIQUE;

// Additional indexes for common query patterns
CREATE INDEX alert_signature IF NOT EXISTS
  FOR (a:Alert) ON (a.signature);

CREATE INDEX alert_classification IF NOT EXISTS
  FOR (a:Alert) ON (a.classification);

CREATE INDEX alert_created_at IF NOT EXISTS
  FOR (a:Alert) ON (a.created_at);

CREATE INDEX device_last_seen IF NOT EXISTS
  FOR (d:Device) ON (d.last_seen);

CREATE INDEX finding_classification IF NOT EXISTS
  FOR (f:Finding) ON (f.classification);
