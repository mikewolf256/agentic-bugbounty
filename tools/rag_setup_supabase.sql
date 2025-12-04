-- RAG Vulnerability Knowledge Base Schema for Supabase
-- Run this in your Supabase SQL Editor to set up the database

-- Enable the pgvector extension
CREATE EXTENSION IF NOT EXISTS vector;

-- Create the vulnerability reports table
CREATE TABLE IF NOT EXISTS vuln_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_id TEXT UNIQUE NOT NULL,
    title TEXT NOT NULL,
    vuln_type TEXT,
    severity TEXT,
    cwe TEXT,
    target_technology TEXT[] DEFAULT '{}',
    attack_vector TEXT,
    payload TEXT,
    impact TEXT,
    steps_to_reproduce TEXT,
    source_url TEXT,
    program_name TEXT,
    reporter_username TEXT,
    submitted_at TIMESTAMPTZ,
    disclosed_at TIMESTAMPTZ,
    raw_content TEXT,
    embedding vector(1536),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_vuln_reports_vuln_type ON vuln_reports(vuln_type);
CREATE INDEX IF NOT EXISTS idx_vuln_reports_severity ON vuln_reports(severity);
CREATE INDEX IF NOT EXISTS idx_vuln_reports_cwe ON vuln_reports(cwe);
CREATE INDEX IF NOT EXISTS idx_vuln_reports_program ON vuln_reports(program_name);

-- Create GIN index for array column (technologies)
CREATE INDEX IF NOT EXISTS idx_vuln_reports_tech ON vuln_reports USING GIN(target_technology);

-- Create HNSW index for fast approximate nearest neighbor search on embeddings
-- HNSW is generally faster than IVFFlat for similarity search
CREATE INDEX IF NOT EXISTS idx_vuln_reports_embedding ON vuln_reports 
USING hnsw (embedding vector_cosine_ops)
WITH (m = 16, ef_construction = 64);

-- Create a function to update the updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create trigger to auto-update updated_at
DROP TRIGGER IF EXISTS update_vuln_reports_updated_at ON vuln_reports;
CREATE TRIGGER update_vuln_reports_updated_at
    BEFORE UPDATE ON vuln_reports
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Create a function for semantic similarity search
CREATE OR REPLACE FUNCTION search_similar_vulns(
    query_embedding vector(1536),
    match_threshold FLOAT DEFAULT 0.5,
    match_count INT DEFAULT 5,
    filter_vuln_type TEXT DEFAULT NULL,
    filter_severity TEXT DEFAULT NULL,
    filter_technologies TEXT[] DEFAULT NULL
)
RETURNS TABLE (
    id UUID,
    report_id TEXT,
    title TEXT,
    vuln_type TEXT,
    severity TEXT,
    cwe TEXT,
    target_technology TEXT[],
    attack_vector TEXT,
    payload TEXT,
    impact TEXT,
    source_url TEXT,
    similarity FLOAT
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT
        vr.id,
        vr.report_id,
        vr.title,
        vr.vuln_type,
        vr.severity,
        vr.cwe,
        vr.target_technology,
        vr.attack_vector,
        vr.payload,
        vr.impact,
        vr.source_url,
        1 - (vr.embedding <=> query_embedding) AS similarity
    FROM vuln_reports vr
    WHERE 
        vr.embedding IS NOT NULL
        AND (1 - (vr.embedding <=> query_embedding)) > match_threshold
        AND (filter_vuln_type IS NULL OR vr.vuln_type ILIKE '%' || filter_vuln_type || '%')
        AND (filter_severity IS NULL OR vr.severity ILIKE filter_severity)
        AND (filter_technologies IS NULL OR vr.target_technology && filter_technologies)
    ORDER BY vr.embedding <=> query_embedding
    LIMIT match_count;
END;
$$;

-- Create a function to search by text (for hybrid search)
CREATE OR REPLACE FUNCTION search_vulns_by_text(
    search_query TEXT,
    match_count INT DEFAULT 10
)
RETURNS TABLE (
    id UUID,
    report_id TEXT,
    title TEXT,
    vuln_type TEXT,
    severity TEXT,
    cwe TEXT,
    target_technology TEXT[],
    attack_vector TEXT,
    source_url TEXT,
    rank FLOAT
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT
        vr.id,
        vr.report_id,
        vr.title,
        vr.vuln_type,
        vr.severity,
        vr.cwe,
        vr.target_technology,
        vr.attack_vector,
        vr.source_url,
        ts_rank(
            to_tsvector('english', COALESCE(vr.title, '') || ' ' || COALESCE(vr.attack_vector, '') || ' ' || COALESCE(vr.raw_content, '')),
            plainto_tsquery('english', search_query)
        ) AS rank
    FROM vuln_reports vr
    WHERE 
        to_tsvector('english', COALESCE(vr.title, '') || ' ' || COALESCE(vr.attack_vector, '') || ' ' || COALESCE(vr.raw_content, ''))
        @@ plainto_tsquery('english', search_query)
    ORDER BY rank DESC
    LIMIT match_count;
END;
$$;

-- Create full-text search index for hybrid search
CREATE INDEX IF NOT EXISTS idx_vuln_reports_fts ON vuln_reports 
USING GIN(to_tsvector('english', COALESCE(title, '') || ' ' || COALESCE(attack_vector, '') || ' ' || COALESCE(raw_content, '')));

-- Grant permissions (adjust as needed for your Supabase setup)
-- These are typically handled by Supabase RLS, but included for completeness
GRANT SELECT, INSERT, UPDATE ON vuln_reports TO authenticated;
GRANT SELECT ON vuln_reports TO anon;

-- Row Level Security (optional - enable if you want to restrict access)
-- ALTER TABLE vuln_reports ENABLE ROW LEVEL SECURITY;
-- CREATE POLICY "Allow public read access" ON vuln_reports FOR SELECT USING (true);
-- CREATE POLICY "Allow authenticated insert" ON vuln_reports FOR INSERT WITH CHECK (true);

COMMENT ON TABLE vuln_reports IS 'Stores normalized HackerOne disclosed vulnerability reports with embeddings for RAG search';
COMMENT ON COLUMN vuln_reports.embedding IS 'OpenAI text-embedding-3-small vector (1536 dimensions)';
COMMENT ON COLUMN vuln_reports.vuln_type IS 'Vulnerability class: XSS, SSRF, IDOR, SQLi, ReDoS, etc.';

