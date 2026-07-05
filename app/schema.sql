PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS source_papers (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    paper_code      TEXT NOT NULL UNIQUE,
    title           TEXT NOT NULL,
    year            INTEGER,
    subject         TEXT NOT NULL DEFAULT '数学',
    language_code   TEXT NOT NULL DEFAULT 'zh-CN',
    source_path     TEXT NOT NULL,
    page_count      INTEGER,
    import_mode     TEXT NOT NULL DEFAULT 'manual',
    meta_json       TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (year IS NULL OR year BETWEEN 1900 AND 2100),
    CHECK (page_count IS NULL OR page_count >= 0),
    CHECK (json_valid(meta_json)),
    CHECK (source_path NOT LIKE '%:%'),
    CHECK (source_path NOT LIKE '/%'),
    CHECK (source_path NOT LIKE '\%')
);

CREATE TABLE IF NOT EXISTS questions (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    qid              TEXT NOT NULL UNIQUE,
    source_paper_id  INTEGER NOT NULL REFERENCES source_papers(id) ON DELETE CASCADE,
    language_code    TEXT NOT NULL DEFAULT 'zh-CN',
    subject          TEXT NOT NULL DEFAULT '数学',
    year             INTEGER,
    region           TEXT,
    stream           TEXT,
    paper_name       TEXT,
    question_no      TEXT NOT NULL,
    question_type    TEXT,
    stem_latex       TEXT NOT NULL,
    stem_text        TEXT NOT NULL,
    answer_text      TEXT,
    analysis_latex   TEXT,
    difficulty       INTEGER CHECK (difficulty IS NULL OR difficulty BETWEEN 1 AND 5),
    tags_json        TEXT NOT NULL DEFAULT '[]',
    image_refs_json  TEXT NOT NULL DEFAULT '[]',
    raw_crop_path    TEXT,
    page_range       TEXT,
    bbox_json        TEXT NOT NULL DEFAULT '{}',
    ocr_confidence   REAL,
    review_status    TEXT NOT NULL DEFAULT 'pending'
        CHECK (review_status IN ('pending', 'reviewed', 'approved', 'rejected')),
    meta_json        TEXT NOT NULL DEFAULT '{}',
    content_hash     TEXT NOT NULL,
    created_at       TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (year IS NULL OR year BETWEEN 1900 AND 2100),
    CHECK (json_valid(tags_json)),
    CHECK (json_valid(image_refs_json)),
    CHECK (json_valid(bbox_json)),
    CHECK (json_valid(meta_json)),
    CHECK (raw_crop_path IS NULL OR raw_crop_path NOT LIKE '%:%'),
    CHECK (raw_crop_path IS NULL OR raw_crop_path NOT LIKE '/%'),
    CHECK (raw_crop_path IS NULL OR raw_crop_path NOT LIKE '\%')
);

CREATE INDEX IF NOT EXISTS idx_questions_source ON questions(source_paper_id);
CREATE INDEX IF NOT EXISTS idx_questions_year ON questions(year);
CREATE INDEX IF NOT EXISTS idx_questions_paper_name ON questions(paper_name);
CREATE INDEX IF NOT EXISTS idx_questions_question_type ON questions(question_type);
CREATE INDEX IF NOT EXISTS idx_questions_review_status ON questions(review_status);
CREATE INDEX IF NOT EXISTS idx_questions_content_hash ON questions(content_hash);

CREATE TABLE IF NOT EXISTS question_assets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    question_id     INTEGER NOT NULL REFERENCES questions(id) ON DELETE CASCADE,
    asset_kind      TEXT NOT NULL CHECK (asset_kind IN ('raw_crop', 'figure', 'thumbnail', 'page_image', 'other')),
    relative_path   TEXT NOT NULL,
    page_no         INTEGER,
    bbox_json       TEXT NOT NULL DEFAULT '{}',
    meta_json       TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (page_no IS NULL OR page_no > 0),
    CHECK (json_valid(bbox_json)),
    CHECK (json_valid(meta_json)),
    CHECK (relative_path NOT LIKE '%:%'),
    CHECK (relative_path NOT LIKE '/%'),
    CHECK (relative_path NOT LIKE '\%')
);

CREATE INDEX IF NOT EXISTS idx_question_assets_question ON question_assets(question_id);
CREATE INDEX IF NOT EXISTS idx_question_assets_kind ON question_assets(asset_kind);
CREATE UNIQUE INDEX IF NOT EXISTS idx_question_assets_unique_raw_crop
    ON question_assets(question_id)
    WHERE asset_kind = 'raw_crop';

CREATE TABLE IF NOT EXISTS question_review_events (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    question_id    INTEGER NOT NULL REFERENCES questions(id) ON DELETE CASCADE,
    event_type     TEXT NOT NULL,
    source         TEXT NOT NULL DEFAULT 'web',
    before_json    TEXT NOT NULL DEFAULT '{}',
    after_json     TEXT NOT NULL DEFAULT '{}',
    diff_json      TEXT NOT NULL DEFAULT '{}',
    created_at     TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (json_valid(before_json)),
    CHECK (json_valid(after_json)),
    CHECK (json_valid(diff_json))
);

CREATE INDEX IF NOT EXISTS idx_question_review_events_question
    ON question_review_events(question_id);
CREATE INDEX IF NOT EXISTS idx_question_review_events_type
    ON question_review_events(event_type);
CREATE INDEX IF NOT EXISTS idx_question_review_events_created
    ON question_review_events(created_at);

CREATE TABLE IF NOT EXISTS question_ai_suggestions (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    question_id      INTEGER NOT NULL REFERENCES questions(id) ON DELETE CASCADE,
    suggestion_type  TEXT NOT NULL,
    input_summary    TEXT NOT NULL DEFAULT '{}',
    suggestion_json  TEXT NOT NULL DEFAULT '{}',
    model_name       TEXT NOT NULL,
    prompt_version   TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'accepted', 'rejected')),
    created_at       TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    reviewed_at      TEXT,
    CHECK (json_valid(input_summary)),
    CHECK (json_valid(suggestion_json))
);

CREATE INDEX IF NOT EXISTS idx_question_ai_suggestions_question
    ON question_ai_suggestions(question_id);
CREATE INDEX IF NOT EXISTS idx_question_ai_suggestions_status
    ON question_ai_suggestions(status);
CREATE INDEX IF NOT EXISTS idx_question_ai_suggestions_type
    ON question_ai_suggestions(suggestion_type);

CREATE TABLE IF NOT EXISTS question_structured_contents (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    question_id           INTEGER NOT NULL UNIQUE REFERENCES questions(id) ON DELETE CASCADE,
    source_text           TEXT NOT NULL DEFAULT '',
    source_latex          TEXT NOT NULL DEFAULT '',
    normalized_type       TEXT NOT NULL DEFAULT 'unknown'
        CHECK (normalized_type IN ('choice', 'multiple_choice', 'blank', 'solution', 'unknown')),
    stem_latex            TEXT NOT NULL DEFAULT '',
    options_json          TEXT NOT NULL DEFAULT '[]',
    blanks_json           TEXT NOT NULL DEFAULT '[]',
    subquestions_json     TEXT NOT NULL DEFAULT '[]',
    answer_latex          TEXT,
    analysis_latex        TEXT,
    ai_status             TEXT NOT NULL DEFAULT 'unprocessed'
        CHECK (ai_status IN (
            'unprocessed',
            'ai_draft',
            'ai_verified',
            'needs_review',
            'failed',
            'human_reviewed'
        )),
    quality_flags_json    TEXT NOT NULL DEFAULT '[]',
    confidence            REAL,
    model_info            TEXT NOT NULL DEFAULT '{}',
    created_at            TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at            TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (json_valid(options_json)),
    CHECK (json_valid(blanks_json)),
    CHECK (json_valid(subquestions_json)),
    CHECK (json_valid(quality_flags_json)),
    CHECK (json_valid(model_info)),
    CHECK (confidence IS NULL OR (confidence >= 0 AND confidence <= 1))
);

CREATE INDEX IF NOT EXISTS idx_question_structured_contents_question
    ON question_structured_contents(question_id);
CREATE INDEX IF NOT EXISTS idx_question_structured_contents_status
    ON question_structured_contents(ai_status);
CREATE INDEX IF NOT EXISTS idx_question_structured_contents_type
    ON question_structured_contents(normalized_type);

CREATE TABLE IF NOT EXISTS stage10_baseline_questions (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    question_id            INTEGER NOT NULL UNIQUE REFERENCES questions(id) ON DELETE CASCADE,
    qid                    TEXT NOT NULL,
    source_page            INTEGER,
    normalized_type        TEXT NOT NULL DEFAULT 'unknown'
        CHECK (normalized_type IN ('choice', 'multiple_choice', 'blank', 'solution', 'unknown')),
    risk_group             TEXT NOT NULL DEFAULT 'normal'
        CHECK (risk_group IN ('normal', 'high_risk', 'duplicate_anchor', 'protected')),
    reason_json            TEXT NOT NULL DEFAULT '[]',
    created_at             TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at             TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (source_page IS NULL OR source_page > 0),
    CHECK (json_valid(reason_json))
);

CREATE INDEX IF NOT EXISTS idx_stage10_baseline_page
    ON stage10_baseline_questions(source_page);
CREATE INDEX IF NOT EXISTS idx_stage10_baseline_type
    ON stage10_baseline_questions(normalized_type);
CREATE INDEX IF NOT EXISTS idx_stage10_baseline_risk
    ON stage10_baseline_questions(risk_group);

CREATE TABLE IF NOT EXISTS stage10_page_isolations (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    source_paper_id          INTEGER REFERENCES source_papers(id) ON DELETE SET NULL,
    page_no                  INTEGER NOT NULL,
    candidate_count          INTEGER NOT NULL DEFAULT 0,
    db_question_count        INTEGER NOT NULL DEFAULT 0,
    duplicate_anchor_count   INTEGER NOT NULL DEFAULT 0,
    warning_candidates       INTEGER NOT NULL DEFAULT 0,
    isolated_count           INTEGER NOT NULL DEFAULT 0,
    reviewable_count         INTEGER NOT NULL DEFAULT 0,
    status                   TEXT NOT NULL DEFAULT 'needs_review'
        CHECK (status IN ('needs_review', 'reviewed', 'resolved')),
    flags_json               TEXT NOT NULL DEFAULT '[]',
    meta_json                TEXT NOT NULL DEFAULT '{}',
    created_at               TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at               TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(source_paper_id, page_no),
    CHECK (page_no > 0),
    CHECK (candidate_count >= 0),
    CHECK (db_question_count >= 0),
    CHECK (duplicate_anchor_count >= 0),
    CHECK (warning_candidates >= 0),
    CHECK (isolated_count >= 0),
    CHECK (reviewable_count >= 0),
    CHECK (json_valid(flags_json)),
    CHECK (json_valid(meta_json))
);

CREATE INDEX IF NOT EXISTS idx_stage10_page_isolations_page
    ON stage10_page_isolations(page_no);
CREATE INDEX IF NOT EXISTS idx_stage10_page_isolations_status
    ON stage10_page_isolations(status);

CREATE TABLE IF NOT EXISTS question_usability_states (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    question_id              INTEGER NOT NULL UNIQUE REFERENCES questions(id) ON DELETE CASCADE,
    usability_status         TEXT NOT NULL
        CHECK (usability_status IN (
            'strict_structured',
            'visual_fallback',
            'needs_formula_repair',
            'needs_blank_repair',
            'needs_type_review',
            'needs_recut',
            'failed',
            'protected'
        )),
    render_mode              TEXT NOT NULL
        CHECK (render_mode IN ('structured_html', 'raw_crop_image', 'candidate_preview', 'none')),
    primary_issue            TEXT NOT NULL DEFAULT '',
    issue_flags_json         TEXT NOT NULL DEFAULT '[]',
    export_eligible          INTEGER NOT NULL DEFAULT 0 CHECK (export_eligible IN (0, 1)),
    classification_version   TEXT NOT NULL,
    classified_at            TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    meta_json                TEXT NOT NULL DEFAULT '{}',
    created_at               TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at               TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (json_valid(issue_flags_json)),
    CHECK (json_valid(meta_json))
);

CREATE INDEX IF NOT EXISTS idx_question_usability_states_question
    ON question_usability_states(question_id);
CREATE INDEX IF NOT EXISTS idx_question_usability_states_status
    ON question_usability_states(usability_status);
CREATE INDEX IF NOT EXISTS idx_question_usability_states_render_mode
    ON question_usability_states(render_mode);
CREATE INDEX IF NOT EXISTS idx_question_usability_states_export_eligible
    ON question_usability_states(export_eligible);
CREATE INDEX IF NOT EXISTS idx_question_usability_states_primary_issue
    ON question_usability_states(primary_issue);

CREATE TABLE IF NOT EXISTS question_export_quality (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    question_id              INTEGER NOT NULL UNIQUE REFERENCES questions(id) ON DELETE CASCADE,
    export_quality_status    TEXT NOT NULL
        CHECK (export_quality_status IN (
            'export_ready_structured',
            'export_ready_visual',
            'export_candidate',
            'export_blocked'
        )),
    render_mode              TEXT NOT NULL
        CHECK (render_mode IN ('structured_html', 'raw_crop_image', 'candidate_preview', 'none')),
    source_usability_status  TEXT NOT NULL DEFAULT '',
    export_eligible          INTEGER NOT NULL DEFAULT 0 CHECK (export_eligible IN (0, 1)),
    blocking_reasons_json    TEXT NOT NULL DEFAULT '[]',
    quality_flags_json       TEXT NOT NULL DEFAULT '[]',
    classification_version   TEXT NOT NULL,
    classified_at            TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    meta_json                TEXT NOT NULL DEFAULT '{}',
    created_at               TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at               TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (json_valid(blocking_reasons_json)),
    CHECK (json_valid(quality_flags_json)),
    CHECK (json_valid(meta_json))
);

CREATE INDEX IF NOT EXISTS idx_question_export_quality_question
    ON question_export_quality(question_id);
CREATE INDEX IF NOT EXISTS idx_question_export_quality_status
    ON question_export_quality(export_quality_status);
CREATE INDEX IF NOT EXISTS idx_question_export_quality_render_mode
    ON question_export_quality(render_mode);
CREATE INDEX IF NOT EXISTS idx_question_export_quality_export_eligible
    ON question_export_quality(export_eligible);
CREATE INDEX IF NOT EXISTS idx_question_export_quality_source_usability
    ON question_export_quality(source_usability_status);

CREATE TABLE IF NOT EXISTS question_source_attributions (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    question_id              INTEGER NOT NULL UNIQUE REFERENCES questions(id) ON DELETE CASCADE,
    source_year              INTEGER,
    source_paper_name        TEXT,
    source_region            TEXT,
    source_stream            TEXT,
    source_question_no       TEXT,
    source_page              INTEGER,
    source_label             TEXT NOT NULL,
    confidence               TEXT NOT NULL DEFAULT 'unknown'
        CHECK (confidence IN ('exact', 'inferred', 'unknown')),
    attribution_flags_json   TEXT NOT NULL DEFAULT '[]',
    source_text              TEXT,
    attribution_version      TEXT NOT NULL,
    created_at               TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at               TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (source_year IS NULL OR source_year BETWEEN 1900 AND 2100),
    CHECK (source_page IS NULL OR source_page > 0),
    CHECK (json_valid(attribution_flags_json))
);

CREATE INDEX IF NOT EXISTS idx_question_source_attributions_question
    ON question_source_attributions(question_id);
CREATE INDEX IF NOT EXISTS idx_question_source_attributions_year
    ON question_source_attributions(source_year);
CREATE INDEX IF NOT EXISTS idx_question_source_attributions_confidence
    ON question_source_attributions(confidence);
CREATE INDEX IF NOT EXISTS idx_question_source_attributions_source_page
    ON question_source_attributions(source_page);
CREATE INDEX IF NOT EXISTS idx_question_source_attributions_paper_name
    ON question_source_attributions(source_paper_name);
CREATE INDEX IF NOT EXISTS idx_question_source_attributions_question_no
    ON question_source_attributions(source_question_no);

CREATE TABLE IF NOT EXISTS stage14_quality_queue (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    question_id              INTEGER NOT NULL UNIQUE REFERENCES questions(id) ON DELETE CASCADE,
    qid                      TEXT NOT NULL,
    queue_name               TEXT NOT NULL
        CHECK (queue_name IN (
            'export_ready',
            'recut',
            'visual_repair',
            'structured_repair',
            'type_review',
            'source_inferred_audit',
            'export_blocked',
            'protected'
        )),
    queue_tags_json          TEXT NOT NULL DEFAULT '[]',
    severity                 INTEGER NOT NULL DEFAULT 0 CHECK (severity BETWEEN 0 AND 100),
    primary_reason           TEXT NOT NULL DEFAULT '',
    suggested_action         TEXT NOT NULL DEFAULT '',
    export_quality_status    TEXT NOT NULL DEFAULT '',
    usability_status         TEXT NOT NULL DEFAULT '',
    structured_status        TEXT NOT NULL DEFAULT '',
    normalized_type          TEXT NOT NULL DEFAULT 'unknown',
    review_status            TEXT NOT NULL DEFAULT '',
    source_page              INTEGER,
    source_confidence        TEXT NOT NULL DEFAULT '',
    source_label             TEXT NOT NULL DEFAULT '',
    flags_json               TEXT NOT NULL DEFAULT '[]',
    meta_json                TEXT NOT NULL DEFAULT '{}',
    stage_version            TEXT NOT NULL,
    classified_at            TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at               TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at               TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (source_page IS NULL OR source_page > 0),
    CHECK (json_valid(queue_tags_json)),
    CHECK (json_valid(flags_json)),
    CHECK (json_valid(meta_json))
);

CREATE INDEX IF NOT EXISTS idx_stage14_quality_queue_question
    ON stage14_quality_queue(question_id);
CREATE INDEX IF NOT EXISTS idx_stage14_quality_queue_name
    ON stage14_quality_queue(queue_name);
CREATE INDEX IF NOT EXISTS idx_stage14_quality_queue_page
    ON stage14_quality_queue(source_page);
CREATE INDEX IF NOT EXISTS idx_stage14_quality_queue_severity
    ON stage14_quality_queue(severity);
CREATE INDEX IF NOT EXISTS idx_stage14_quality_queue_source_confidence
    ON stage14_quality_queue(source_confidence);
CREATE INDEX IF NOT EXISTS idx_stage14_quality_queue_export_quality
    ON stage14_quality_queue(export_quality_status);

CREATE TABLE IF NOT EXISTS stage14_page_recut_audits (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    source_paper_id          INTEGER REFERENCES source_papers(id) ON DELETE SET NULL,
    page_no                  INTEGER NOT NULL,
    candidate_count          INTEGER NOT NULL DEFAULT 0,
    db_question_count        INTEGER NOT NULL DEFAULT 0,
    duplicate_anchor_count   INTEGER NOT NULL DEFAULT 0,
    warning_candidates       INTEGER NOT NULL DEFAULT 0,
    page_flags_json          TEXT NOT NULL DEFAULT '[]',
    audit_status             TEXT NOT NULL
        CHECK (audit_status IN (
            'blocked_needs_manual_recut',
            'candidate_recoverable',
            'resolved',
            'scan_failed'
        )),
    recovery_action          TEXT NOT NULL DEFAULT '',
    error_json               TEXT NOT NULL DEFAULT '{}',
    meta_json                TEXT NOT NULL DEFAULT '{}',
    stage_version            TEXT NOT NULL,
    audited_at               TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at               TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at               TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(source_paper_id, page_no, stage_version),
    CHECK (page_no > 0),
    CHECK (candidate_count >= 0),
    CHECK (db_question_count >= 0),
    CHECK (duplicate_anchor_count >= 0),
    CHECK (warning_candidates >= 0),
    CHECK (json_valid(page_flags_json)),
    CHECK (json_valid(error_json)),
    CHECK (json_valid(meta_json))
);

CREATE INDEX IF NOT EXISTS idx_stage14_page_recut_audits_page
    ON stage14_page_recut_audits(page_no);
CREATE INDEX IF NOT EXISTS idx_stage14_page_recut_audits_status
    ON stage14_page_recut_audits(audit_status);
CREATE INDEX IF NOT EXISTS idx_stage14_page_recut_audits_source
    ON stage14_page_recut_audits(source_paper_id);

CREATE TABLE IF NOT EXISTS stage14_visual_repair_candidates (
    id                            INTEGER PRIMARY KEY AUTOINCREMENT,
    question_id                   INTEGER NOT NULL UNIQUE REFERENCES questions(id) ON DELETE CASCADE,
    original_asset_id             INTEGER REFERENCES question_assets(id) ON DELETE SET NULL,
    original_relative_path        TEXT NOT NULL DEFAULT '',
    candidate_asset_id            INTEGER REFERENCES question_assets(id) ON DELETE SET NULL,
    candidate_relative_path       TEXT,
    repair_status                 TEXT NOT NULL
        CHECK (repair_status IN (
            'not_needed',
            'candidate_generated',
            'candidate_passed_visual_check',
            'candidate_failed_visual_check',
            'failed',
            'skipped'
        )),
    source_blocking_reasons_json  TEXT NOT NULL DEFAULT '[]',
    source_metrics_json           TEXT NOT NULL DEFAULT '{}',
    candidate_metrics_json        TEXT NOT NULL DEFAULT '{}',
    error_json                    TEXT NOT NULL DEFAULT '{}',
    stage_version                 TEXT NOT NULL,
    attempted_at                  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at                    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at                    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (candidate_relative_path IS NULL OR candidate_relative_path NOT LIKE '%:%'),
    CHECK (candidate_relative_path IS NULL OR candidate_relative_path NOT LIKE '/%'),
    CHECK (candidate_relative_path IS NULL OR candidate_relative_path NOT LIKE '\%'),
    CHECK (json_valid(source_blocking_reasons_json)),
    CHECK (json_valid(source_metrics_json)),
    CHECK (json_valid(candidate_metrics_json)),
    CHECK (json_valid(error_json))
);

CREATE INDEX IF NOT EXISTS idx_stage14_visual_repair_question
    ON stage14_visual_repair_candidates(question_id);
CREATE INDEX IF NOT EXISTS idx_stage14_visual_repair_status
    ON stage14_visual_repair_candidates(repair_status);

CREATE TABLE IF NOT EXISTS stage14_source_audits (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    question_id              INTEGER NOT NULL UNIQUE REFERENCES questions(id) ON DELETE CASCADE,
    source_page              INTEGER,
    source_confidence        TEXT NOT NULL DEFAULT '',
    source_label             TEXT NOT NULL DEFAULT '',
    audit_status             TEXT NOT NULL
        CHECK (audit_status IN (
            'consistent_previous_header',
            'needs_manual_source_review',
            'not_inferred',
            'not_checked'
        )),
    flags_json               TEXT NOT NULL DEFAULT '[]',
    meta_json                TEXT NOT NULL DEFAULT '{}',
    stage_version            TEXT NOT NULL,
    audited_at               TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at               TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at               TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (source_page IS NULL OR source_page > 0),
    CHECK (json_valid(flags_json)),
    CHECK (json_valid(meta_json))
);

CREATE INDEX IF NOT EXISTS idx_stage14_source_audits_question
    ON stage14_source_audits(question_id);
CREATE INDEX IF NOT EXISTS idx_stage14_source_audits_status
    ON stage14_source_audits(audit_status);
CREATE INDEX IF NOT EXISTS idx_stage14_source_audits_page
    ON stage14_source_audits(source_page);

CREATE TABLE IF NOT EXISTS import_batches (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_code           TEXT NOT NULL UNIQUE,
    name                 TEXT NOT NULL UNIQUE,
    batch_kind           TEXT NOT NULL DEFAULT 'expansion'
        CHECK (batch_kind IN ('baseline', 'expansion')),
    source_paper_id      INTEGER REFERENCES source_papers(id) ON DELETE SET NULL,
    page_spec            TEXT NOT NULL,
    page_count           INTEGER NOT NULL DEFAULT 0,
    algorithm_version    TEXT NOT NULL DEFAULT '',
    status               TEXT NOT NULL DEFAULT 'planned'
        CHECK (status IN ('planned', 'running', 'done', 'failed')),
    backup_path          TEXT,
    scan_summary_json    TEXT NOT NULL DEFAULT '{}',
    import_summary_json  TEXT NOT NULL DEFAULT '{}',
    split_summary_json   TEXT NOT NULL DEFAULT '{}',
    crop_summary_json    TEXT NOT NULL DEFAULT '{}',
    error_json           TEXT NOT NULL DEFAULT '{}',
    notes                TEXT,
    started_at           TEXT,
    completed_at         TEXT,
    duration_ms          INTEGER,
    created_at           TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at           TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (page_count >= 0),
    CHECK (duration_ms IS NULL OR duration_ms >= 0),
    CHECK (json_valid(scan_summary_json)),
    CHECK (json_valid(import_summary_json)),
    CHECK (json_valid(split_summary_json)),
    CHECK (json_valid(crop_summary_json)),
    CHECK (json_valid(error_json)),
    CHECK (backup_path IS NULL OR backup_path NOT LIKE '%:%'),
    CHECK (backup_path IS NULL OR backup_path NOT LIKE '/%'),
    CHECK (backup_path IS NULL OR backup_path NOT LIKE '\%')
);

CREATE INDEX IF NOT EXISTS idx_import_batches_status ON import_batches(status);
CREATE INDEX IF NOT EXISTS idx_import_batches_kind ON import_batches(batch_kind);
CREATE INDEX IF NOT EXISTS idx_import_batches_source ON import_batches(source_paper_id);

CREATE TABLE IF NOT EXISTS import_batch_pages (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id                 INTEGER NOT NULL REFERENCES import_batches(id) ON DELETE CASCADE,
    source_paper_id          INTEGER REFERENCES source_papers(id) ON DELETE SET NULL,
    page_no                  INTEGER NOT NULL,
    status                   TEXT NOT NULL DEFAULT 'planned'
        CHECK (status IN ('planned', 'done', 'failed')),
    text_length              INTEGER NOT NULL DEFAULT 0,
    block_count              INTEGER NOT NULL DEFAULT 0,
    anchor_count             INTEGER NOT NULL DEFAULT 0,
    duplicate_anchor_count   INTEGER NOT NULL DEFAULT 0,
    candidate_count          INTEGER NOT NULL DEFAULT 0,
    db_question_count        INTEGER NOT NULL DEFAULT 0,
    warning_candidates       INTEGER NOT NULL DEFAULT 0,
    skipped_reviewed         INTEGER NOT NULL DEFAULT 0,
    page_flags_json          TEXT NOT NULL DEFAULT '[]',
    warning_reasons_json     TEXT NOT NULL DEFAULT '[]',
    scan_json                TEXT NOT NULL DEFAULT '{}',
    import_json              TEXT NOT NULL DEFAULT '{}',
    split_json               TEXT NOT NULL DEFAULT '{}',
    crop_json                TEXT NOT NULL DEFAULT '{}',
    error_json               TEXT NOT NULL DEFAULT '{}',
    duration_ms              INTEGER,
    created_at               TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at               TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(batch_id, page_no),
    CHECK (page_no > 0),
    CHECK (text_length >= 0),
    CHECK (block_count >= 0),
    CHECK (anchor_count >= 0),
    CHECK (duplicate_anchor_count >= 0),
    CHECK (candidate_count >= 0),
    CHECK (db_question_count >= 0),
    CHECK (warning_candidates >= 0),
    CHECK (skipped_reviewed >= 0),
    CHECK (duration_ms IS NULL OR duration_ms >= 0),
    CHECK (json_valid(page_flags_json)),
    CHECK (json_valid(warning_reasons_json)),
    CHECK (json_valid(scan_json)),
    CHECK (json_valid(import_json)),
    CHECK (json_valid(split_json)),
    CHECK (json_valid(crop_json)),
    CHECK (json_valid(error_json))
);

CREATE INDEX IF NOT EXISTS idx_import_batch_pages_batch
    ON import_batch_pages(batch_id);
CREATE INDEX IF NOT EXISTS idx_import_batch_pages_page
    ON import_batch_pages(page_no);
CREATE INDEX IF NOT EXISTS idx_import_batch_pages_status
    ON import_batch_pages(status);

CREATE TABLE IF NOT EXISTS source_paper_assets (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    source_paper_id  INTEGER NOT NULL REFERENCES source_papers(id) ON DELETE CASCADE,
    asset_kind       TEXT NOT NULL CHECK (asset_kind = 'page_image'),
    relative_path    TEXT NOT NULL,
    page_no          INTEGER NOT NULL,
    bbox_json        TEXT NOT NULL DEFAULT '{}',
    meta_json        TEXT NOT NULL DEFAULT '{}',
    created_at       TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (page_no > 0),
    CHECK (json_valid(bbox_json)),
    CHECK (json_valid(meta_json)),
    CHECK (relative_path NOT LIKE '%:%'),
    CHECK (relative_path NOT LIKE '/%'),
    CHECK (relative_path NOT LIKE '\%')
);

CREATE INDEX IF NOT EXISTS idx_source_paper_assets_source ON source_paper_assets(source_paper_id);
CREATE INDEX IF NOT EXISTS idx_source_paper_assets_kind ON source_paper_assets(asset_kind);
CREATE INDEX IF NOT EXISTS idx_source_paper_assets_page ON source_paper_assets(page_no);
CREATE UNIQUE INDEX IF NOT EXISTS idx_source_paper_assets_unique_page
    ON source_paper_assets(source_paper_id, asset_kind, page_no);

CREATE TABLE IF NOT EXISTS question_search_content (
    question_id      INTEGER PRIMARY KEY REFERENCES questions(id) ON DELETE CASCADE,
    qid              TEXT NOT NULL,
    year_text        TEXT NOT NULL DEFAULT '',
    paper_name       TEXT NOT NULL DEFAULT '',
    question_type    TEXT NOT NULL DEFAULT '',
    tags_text        TEXT NOT NULL DEFAULT '',
    stem_text        TEXT NOT NULL DEFAULT '',
    answer_text      TEXT NOT NULL DEFAULT '',
    analysis_text    TEXT NOT NULL DEFAULT ''
);

CREATE VIRTUAL TABLE IF NOT EXISTS question_fts USING fts5(
    qid UNINDEXED,
    year_text UNINDEXED,
    paper_name,
    question_type,
    tags_text,
    stem_text,
    answer_text,
    analysis_text,
    content='question_search_content',
    content_rowid='question_id',
    prefix='2 3 4'
);

CREATE TRIGGER IF NOT EXISTS trg_questions_ai
AFTER INSERT ON questions
BEGIN
    INSERT INTO question_search_content (
        question_id,
        qid,
        year_text,
        paper_name,
        question_type,
        tags_text,
        stem_text,
        answer_text,
        analysis_text
    )
    VALUES (
        NEW.id,
        NEW.qid,
        COALESCE(CAST(NEW.year AS TEXT), ''),
        COALESCE(NEW.paper_name, ''),
        COALESCE(NEW.question_type, ''),
        COALESCE(NEW.tags_json, '[]'),
        COALESCE(NEW.stem_text, ''),
        COALESCE(NEW.answer_text, ''),
        COALESCE(NEW.analysis_latex, '')
    );

    INSERT INTO question_fts(
        rowid,
        qid,
        year_text,
        paper_name,
        question_type,
        tags_text,
        stem_text,
        answer_text,
        analysis_text
    )
    VALUES (
        NEW.id,
        NEW.qid,
        COALESCE(CAST(NEW.year AS TEXT), ''),
        COALESCE(NEW.paper_name, ''),
        COALESCE(NEW.question_type, ''),
        COALESCE(NEW.tags_json, '[]'),
        COALESCE(NEW.stem_text, ''),
        COALESCE(NEW.answer_text, ''),
        COALESCE(NEW.analysis_latex, '')
    );
END;

CREATE TRIGGER IF NOT EXISTS trg_questions_ad
AFTER DELETE ON questions
BEGIN
    INSERT INTO question_fts(
        question_fts,
        rowid,
        qid,
        year_text,
        paper_name,
        question_type,
        tags_text,
        stem_text,
        answer_text,
        analysis_text
    )
    VALUES (
        'delete',
        OLD.id,
        OLD.qid,
        COALESCE(CAST(OLD.year AS TEXT), ''),
        COALESCE(OLD.paper_name, ''),
        COALESCE(OLD.question_type, ''),
        COALESCE(OLD.tags_json, '[]'),
        COALESCE(OLD.stem_text, ''),
        COALESCE(OLD.answer_text, ''),
        COALESCE(OLD.analysis_latex, '')
    );

    DELETE FROM question_search_content WHERE question_id = OLD.id;
END;

CREATE TRIGGER IF NOT EXISTS trg_questions_au
AFTER UPDATE ON questions
BEGIN
    INSERT INTO question_fts(
        question_fts,
        rowid,
        qid,
        year_text,
        paper_name,
        question_type,
        tags_text,
        stem_text,
        answer_text,
        analysis_text
    )
    VALUES (
        'delete',
        OLD.id,
        OLD.qid,
        COALESCE(CAST(OLD.year AS TEXT), ''),
        COALESCE(OLD.paper_name, ''),
        COALESCE(OLD.question_type, ''),
        COALESCE(OLD.tags_json, '[]'),
        COALESCE(OLD.stem_text, ''),
        COALESCE(OLD.answer_text, ''),
        COALESCE(OLD.analysis_latex, '')
    );

    UPDATE question_search_content
       SET qid = NEW.qid,
           year_text = COALESCE(CAST(NEW.year AS TEXT), ''),
           paper_name = COALESCE(NEW.paper_name, ''),
           question_type = COALESCE(NEW.question_type, ''),
           tags_text = COALESCE(NEW.tags_json, '[]'),
           stem_text = COALESCE(NEW.stem_text, ''),
           answer_text = COALESCE(NEW.answer_text, ''),
           analysis_text = COALESCE(NEW.analysis_latex, '')
     WHERE question_id = NEW.id;

    INSERT INTO question_fts(
        rowid,
        qid,
        year_text,
        paper_name,
        question_type,
        tags_text,
        stem_text,
        answer_text,
        analysis_text
    )
    VALUES (
        NEW.id,
        NEW.qid,
        COALESCE(CAST(NEW.year AS TEXT), ''),
        COALESCE(NEW.paper_name, ''),
        COALESCE(NEW.question_type, ''),
        COALESCE(NEW.tags_json, '[]'),
        COALESCE(NEW.stem_text, ''),
        COALESCE(NEW.answer_text, ''),
        COALESCE(NEW.analysis_latex, '')
    );
END;
