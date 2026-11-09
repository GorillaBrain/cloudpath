-- CloudPath PostgreSQL Schema & Row Level Security (RLS)
-- Enforces strict workspace isolation and public read access for the Northstar demo environment.

CREATE TABLE IF NOT EXISTS public.cloudpath_workspaces (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    owner_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    is_demo BOOLEAN NOT NULL DEFAULT FALSE,
    risk_weights JSONB NOT NULL DEFAULT '{"exposure": 0.25, "privilege": 0.25, "sensitivity": 0.20, "reachability": 0.15, "trust": 0.15}'::jsonb,
    retention_days INTEGER NOT NULL DEFAULT 90,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.cloudpath_scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES public.cloudpath_workspaces(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    source_type TEXT NOT NULL,
    provider TEXT NOT NULL DEFAULT 'aws',
    status TEXT NOT NULL DEFAULT 'completed',
    summary_metrics JSONB NOT NULL DEFAULT '{}'::jsonb,
    graph_data JSONB NOT NULL DEFAULT '{}'::jsonb,
    assets_data JSONB NOT NULL DEFAULT '[]'::jsonb,
    findings_data JSONB NOT NULL DEFAULT '[]'::jsonb,
    attack_paths_data JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.cloudpath_audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES public.cloudpath_workspaces(id) ON DELETE CASCADE,
    actor_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cloudpath_scans_workspace ON public.cloudpath_scans(workspace_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_cloudpath_audit_workspace ON public.cloudpath_audit_logs(workspace_id, created_at DESC);

ALTER TABLE public.cloudpath_workspaces ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.cloudpath_scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.cloudpath_audit_logs ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Users can view own or demo workspaces" ON public.cloudpath_workspaces;
CREATE POLICY "Users can view own or demo workspaces"
    ON public.cloudpath_workspaces FOR SELECT
    USING (is_demo = TRUE OR auth.uid() = owner_id);

DROP POLICY IF EXISTS "Users can create own workspaces" ON public.cloudpath_workspaces;
CREATE POLICY "Users can create own workspaces"
    ON public.cloudpath_workspaces FOR INSERT
    WITH CHECK (auth.uid() = owner_id AND is_demo = FALSE);

DROP POLICY IF EXISTS "Users can update own workspaces" ON public.cloudpath_workspaces;
CREATE POLICY "Users can update own workspaces"
    ON public.cloudpath_workspaces FOR UPDATE
    USING (auth.uid() = owner_id AND is_demo = FALSE)
    WITH CHECK (auth.uid() = owner_id AND is_demo = FALSE);

DROP POLICY IF EXISTS "Users can delete own workspaces" ON public.cloudpath_workspaces;
CREATE POLICY "Users can delete own workspaces"
    ON public.cloudpath_workspaces FOR DELETE
    USING (auth.uid() = owner_id AND is_demo = FALSE);

DROP POLICY IF EXISTS "Users can view scans in accessible workspaces" ON public.cloudpath_scans;
CREATE POLICY "Users can view scans in accessible workspaces"
    ON public.cloudpath_scans FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM public.cloudpath_workspaces w
            WHERE w.id = cloudpath_scans.workspace_id
            AND (w.is_demo = TRUE OR w.owner_id = auth.uid())
        )
    );

DROP POLICY IF EXISTS "Users can insert scans in own or demo workspace" ON public.cloudpath_scans;
CREATE POLICY "Users can insert scans in own or demo workspace"
    ON public.cloudpath_scans FOR INSERT
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM public.cloudpath_workspaces w
            WHERE w.id = cloudpath_scans.workspace_id
            AND (w.is_demo = TRUE OR w.owner_id = auth.uid())
        )
    );

DROP POLICY IF EXISTS "Users can delete scans in own workspace" ON public.cloudpath_scans;
CREATE POLICY "Users can delete scans in own workspace"
    ON public.cloudpath_scans FOR DELETE
    USING (
        EXISTS (
            SELECT 1 FROM public.cloudpath_workspaces w
            WHERE w.id = cloudpath_scans.workspace_id
            AND w.owner_id = auth.uid()
        )
    );

DROP POLICY IF EXISTS "Users can view audit logs in own or demo workspace" ON public.cloudpath_audit_logs;
CREATE POLICY "Users can view audit logs in own or demo workspace"
    ON public.cloudpath_audit_logs FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM public.cloudpath_workspaces w
            WHERE w.id = cloudpath_audit_logs.workspace_id
            AND (w.is_demo = TRUE OR w.owner_id = auth.uid())
        )
    );

DROP POLICY IF EXISTS "Users can insert audit logs in own or demo workspace" ON public.cloudpath_audit_logs;
CREATE POLICY "Users can insert audit logs in own or demo workspace"
    ON public.cloudpath_audit_logs FOR INSERT
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM public.cloudpath_workspaces w
            WHERE w.id = cloudpath_audit_logs.workspace_id
            AND (w.is_demo = TRUE OR w.owner_id = auth.uid())
        )
    );

INSERT INTO public.cloudpath_workspaces (id, name, slug, is_demo)
VALUES ('00000000-0000-0000-0000-000000000001', 'Northstar Financial Technologies (Demo)', 'northstar-fin-demo', TRUE)
ON CONFLICT (slug) DO NOTHING;
