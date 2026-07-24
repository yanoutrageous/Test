from __future__ import annotations

import ast
import hashlib
import json
import re
from collections import Counter, defaultdict, deque
from dataclasses import asdict, dataclass, replace
from enum import StrEnum
from pathlib import Path
from typing import Any, Iterable, Iterator

from app.config import PROJECT_ROOT
from app.project_root import PROJECT_ROOT as _VERIFIED_PROJECT_ROOT


SCANNER_VERSION = "M0-S3-STATIC-AUDIT-V16"
PRODUCTION_ROOTS = ("app", "scripts")
SOURCE_SUFFIXES = (".py", ".sql")
SOURCE_BYTE_NORMALIZATION = "UTF8_LF_V1"
ENTRY_CHUNK_SIZE = 25

# Indexed receivers lose their concrete type in this small AST analysis.  Only
# exact repository callsites that were manually reviewed as in-memory/read-only
# are suppressed.  A new or changed callsite therefore becomes UNKNOWN instead
# of inheriting a globally safe-looking method name such as ``get`` or
# ``resolve``.  Sink-shaped methods are classified before this table is used.
_AUDITED_INDEXED_CALLS = frozenset(
    {
        ("app/codex_structure.py", "app.codex_structure._extract_subquestions", "5d696616fed58ea711bb2f29ca183415c5f1e01fb3141173844d22532a3d954a"),
        ("app/codex_structure.py", "app.codex_structure._split_options", "6bbcc55d9f54b6026e2874e6b35eac1854e1437245667404e34d2639a9a57bcc"),
        ("app/codex_structure.py", "app.codex_structure._split_options", "99342fe48f8acb91372d8433584c8dcd1d45989fba0a77bb24beeddc232c0403"),
        ("app/codex_structure.py", "app.codex_structure.run_codex_structure_batch", "ebd6facba6ebaa9a5b0a749c238e4ad564856552820e1b84ac0884dea26bdb2a"),
        ("app/config.py", "app.config.find_unique_target_pdf", "c8826b2017d8b2011090ccfb484159adf9d8b424f3bc48ebf63690ed20a288f2"),
        ("app/export_quality.py", "app.export_quality._render_stage12_report", "3585d9395fde7249ada143ccc279b9d15390a9bdc8d3b09eab21dcc2df8a520f"),
        ("app/export_quality.py", "app.export_quality._render_stage12_report", "4795090d0b5fc39492946cdb4a5ecf36a86fdf6760b1f45d1318b1540296ae3b"),
        ("app/export_quality.py", "app.export_quality._render_stage12_report", "542987264d37611c7ccdee8e1a81525098f8d50666d6247590ed1a165c12b2d6"),
        ("app/export_quality.py", "app.export_quality._render_stage12_report", "a04e02570adeb3db19b2556212d08e6082eb2feef991b6d165926a41c1823d09"),
        ("app/export_quality.py", "app.export_quality._render_stage12_report", "c8ed9a43925d451f0b5579a270b8ba82b1783037b2a9d341f450e87b9eefbdb8"),
        ("app/export_quality.py", "app.export_quality._render_stage12_report", "e3425abfab8c3a52c0f751a3b1d63a21984b48dea3a310ad2bf54d29bffeeb55"),
        ("app/health.py", "app.health.check_sqlite", "69fff54d09cbb7d3929c377db944c875cffd0c105fb53679760bbb9f6462374c"),
        ("app/pdf_import.py", "app.pdf_import.build_paper_code", "8d49edced4935578aaad294e6558fd2044c7603f2eefd2c9f10f8f69f953f6b6"),
        ("app/pdf_import.py", "app.pdf_import.render_pdf_pages", "ca9b3303b86d492168981dc7d9d34210b4f45d9e732280fcca469d8657573f01"),
        ("app/question_assets.py", "app.question_assets.crop_question_assets", "43569ee06df8a7fc8875ec3f15a3cb2d3d0583ae4941fb94e72b99eac9f8171a"),
        ("app/question_split.py", "app.question_split.extract_page_text_blocks", "1aef377320dac5bfadb0aac1281fdacb17d8c36ac214ddcd92ed1e69aa05edc3"),
        ("app/safety/audit_events.py", "app.safety.audit_events.audit_hmac_key_id", "c78ca38e66dbcf5cb8df482b19dead92b2a003dd04d5b48bc239e6d3d3606cda"),
        ("app/safety/copy_operation.py", "app.safety.copy_operation._TestLocalCopyOperation._require_worst_case_publish_budget", "5df82d08868214f698faeae1893fcb2fb04455b44bd2c2d9f42067355fba434d"),
        ("app/safety/copy_operation.py", "app.safety.copy_operation._TestLocalCopyOperation._target_evidence", "1f31e4f650e22f2186a41f544e55ad25849db6455f5ffb0cf0ec4f8cefe60590"),
        ("app/safety/copy_operation.py", "app.safety.copy_operation._TestLocalCopyOperation._target_evidence", "2901297b0933a43a0f713b401b16d15e3158125724dd3de02ca91e48ee0e83f2"),
        ("app/safety/copy_operation.py", "app.safety.copy_operation._TestLocalCopyOperation._target_evidence", "72250afb55a1eeef9b5ef86f6b42e39f7e3056a1fed2ca15bad34fe6935c520d"),
        ("app/safety/copy_operation.py", "app.safety.copy_operation._TestLocalCopyOperation._target_evidence", "be075eb99ec6e8d00342c9f0dace1800549a67700e315750c0a0ddba32731d54"),
        ("app/safety/external_source.py", "app.safety.external_source._ReferenceReadApi.require_default_stream", "4bc9a8375287dea4dd2cf015cce3e07c9364c810d2b8063f15ba4c52127e6de5"),
        ("app/safety/external_source.py", "app.safety.external_source._validated_source_name", "ebb841a115a85b101e0ad764729df612b93a2b547e6abf5210722f0ccdddd1e4"),
        ("app/safety/production_guard.py", "app.safety.production_guard._create_test_boundary", "c74c3f6c1d132b896ac4b6ac0a6da4f83e6615421cee5858697dd38d5ce975d6"),
        ("app/safety/static_audit.py", "app.safety.static_audit._guard_findings", "4ed428eb19f4dfc1f1d6ed3319e6d60c2386f7c074192cdf710cbf48e4fbbb08"),
        ("app/safety/static_audit.py", "app.safety.static_audit._SinkVisitor.visit_Global", "addd2d256c10ae286feedeedb6b0ecd310c6d9eafc4b429f7a54cdf1f5a21a56"),
        ("app/safety/static_audit.py", "app.safety.static_audit._SinkVisitor.visit_Global", "ecacb8e1ecbe79b62f74dc0dc6885b5f1b269854da13461baf3572b7b28de490"),
        ("app/safety/static_audit.py", "app.safety.static_audit._SinkVisitor.visit_Global", "f323ea157bced7c5a1ad1886625e0797582641ab0e7681bfd28fbfe4eb2b12e3"),
        ("app/safety/static_audit.py", "app.safety.static_audit._build_call_graph", "18dcb3736c328b8e1e8a31ef5f8dc1d657dd350f47d40b40ee97c26d13af41f6"),
        ("app/safety/static_audit.py", "app.safety.static_audit._enrich_entries", "4ac8662fbdb63066e027975e837fc53bbc8dca18dbcc35fa7ffd77235c9be50a"),
        ("app/safety/static_audit.py", "app.safety.static_audit._enrich_entries", "cffa030ff7a8a3fddcf11639e26b92ac4bd4f1e2fdb69909ca82a22181c3a283"),
        ("app/safety/static_audit.py", "app.safety.static_audit._looks_like_archive_receiver", "059deb25070485d5b51b6cf7e1ea8d2e366ad1a7613452bf8281e0a916965ef4"),
        ("app/safety/static_audit.py", "app.safety.static_audit._looks_like_path_receiver", "059deb25070485d5b51b6cf7e1ea8d2e366ad1a7613452bf8281e0a916965ef4"),
        ("app/safety/static_audit.py", "app.safety.static_audit._looks_like_path_receiver", "860a78c752c4f7a5534593cdd7b5577dee88be8b0aa2ac93783c95cb0af7215f"),
        ("app/safety/static_audit.py", "app.safety.static_audit._looks_like_path_receiver", "8d9664d4bc9274a8c1dbe02c2522e099c040d9b5b23274481e44fd4528aed811"),
        ("app/safety/static_audit.py", "app.safety.static_audit._resolve_import_module", "797054c5fce90fcfeac97951fb5df588a649e82230605a92d6c174903ca1a967"),
        ("app/safety/static_audit.py", "app.safety.static_audit._root_ids", "fae67c1b67f348de7a2602636941a1f4d55b8b0f37cad7388b63e49dc1615b3a"),
        ("app/source_attribution.py", "app.source_attribution._find_previous_header", "e23cbd304697341859f0f6725b92a684b565d084c4efc700c719367ff06a5ef2"),
        ("app/source_attribution.py", "app.source_attribution._load_headers_for_rows", "184edec26d0fd915e5eceb6ab4fc7a6dcd5b05f21b2c2a5a3a7bd55dd325493e"),
        ("app/source_attribution.py", "app.source_attribution._load_headers_for_rows", "1b15b27f234a11c6888d061e89703732ef423d5ff1fd5b9c285bd697b31d3cd4"),
        ("app/source_attribution.py", "app.source_attribution._render_report_markdown", "9d0713e662e8a5726f025bf7694010807cf59bb5f4109a4f2eedcad54d748644"),
        ("app/source_attribution.py", "app.source_attribution._render_report_markdown", "c89bcb0c81ea5a4aba6469cc094c5cb4c1384804f6edbb8a65e6076a4a95ccb0"),
        ("app/source_attribution.py", "app.source_attribution._render_report_markdown", "e231b2ac9653afaa9018aabd02b3d4d87d23ab6cc9a5ed7e9baf1a23920c6a96"),
        ("app/stage10.py", "app.stage10._extract_subquestions", "5d696616fed58ea711bb2f29ca183415c5f1e01fb3141173844d22532a3d954a"),
        ("app/stage10.py", "app.stage10._render_stage10_report", "130a6f05c1c473057734b3c1ca44b04753c8ddead6f52605f67e6e11a1f55bd0"),
        ("app/stage10.py", "app.stage10._render_stage10_report", "6c0522b6580a099a9c4dffd6a9c846648be242d2b5208fd0222b8a8469ca88cb"),
        ("app/stage10.py", "app.stage10._render_stage10_report", "81dab40a921cf215cb545ac24e4e080cba90127887f2ff8e101de3121d6a8815"),
        ("app/stage10.py", "app.stage10._render_stage10_report", "888a3981d64bd5ecb328936d0a42e0aeb25374706f624dc3b49ba16c48a18e42"),
        ("app/stage10.py", "app.stage10._render_stage10_report", "8f1520a8d7f78796297180083b6baa8eca6b5bb68a009eb492d955e6a6d53ee8"),
        ("app/stage10.py", "app.stage10._render_stage10_report", "a5f02b29265136ecca94f2c47c9d569d3ec367e5afcfc45d1e18a92438152eee"),
        ("app/stage10.py", "app.stage10._select_baseline_rows.add", "ab1df94f59890c70f23a453d282060f7caf2b210a63c2763ad6ed59da378d1fb"),
        ("app/stage10.py", "app.stage10._split_options", "6bbcc55d9f54b6026e2874e6b35eac1854e1437245667404e34d2639a9a57bcc"),
        ("app/stage10.py", "app.stage10._split_options", "99342fe48f8acb91372d8433584c8dcd1d45989fba0a77bb24beeddc232c0403"),
        ("app/stage11.py", "app.stage11._render_stage11_report", "10b6e76de9ce8e8b0a87a95fc69fee81a26b2bc049a93d73b5fcd22c12fc20c4"),
        ("app/stage11.py", "app.stage11._render_stage11_report", "19bb361eb3d842776732e11f03bc757a5f3a21bf09b51d9f00d5aec026b90c04"),
        ("app/stage11.py", "app.stage11._render_stage11_report", "58b515614b6129152b60eb4fd73f7d31984f36368472ba97f17d5065d76f6824"),
        ("app/stage11.py", "app.stage11._render_stage11_report", "6c0522b6580a099a9c4dffd6a9c846648be242d2b5208fd0222b8a8469ca88cb"),
        ("app/stage11.py", "app.stage11._render_stage11_report", "bfa80573cc0c34b60cbb107134f55c4d237f3394c07d3d0636759d34aca85a40"),
        ("app/stage11.py", "app.stage11._render_stage11_report", "c818bed85cf2507efebe74715d250eca6438c6d3b0a75822d2228aa685403308"),
        ("app/stage14.py", "app.stage14.Stage14QualityService._audit_inferred_source_group", "184edec26d0fd915e5eceb6ab4fc7a6dcd5b05f21b2c2a5a3a7bd55dd325493e"),
        ("app/stage14.py", "app.stage14.Stage14QualityService.audit_inferred_sources", "ecdbe07e5bd9a03f071abe682871c9bd143f4ffd07e74531eb445097ab9e423e"),
        ("app/stage9_report.py", "app.stage9_report._render_report_v2", "9b6773289ff82312f8dde9df4fb678db2f4dba67cce6cf847148529493a94b45"),
        ("app/stage9_report.py", "app.stage9_report._render_report_v2", "b139a081c198d0f700aad7f28a5aaeae3f2599f43530663783e8e9877fd922fb"),
        ("app/stage9_report.py", "app.stage9_report._render_report_v2", "d21fe8a51c3f0353a8b734f31eb9271407c21587fe6ebfa22b7815b8f15d1f65"),
        ("app/structured_ai.py", "app.structured_ai._parse_provider_json_content", "9e0718357d7a03b61e184e52d3f1069445e4243df937fc4f8c7f8d270a063a17"),
        ("app/structured_ai.py", "app.structured_ai._parse_provider_json_content", "b856a360605aab5df22cfa221d145129961fa395b74ff0dad2bf1971da300835"),
        ("app/structured_render.py", "app.structured_render.build_paper_sections", "add654e0974bad72d73f1af46dc9b543a3619f0085f028daace34744ff8805bf"),
        ("app/workspace_guard.py", "app.workspace_guard._validate_lexical", "e504908ef3a59bd463559472b05fe46da547b630c375ffd0fd665b462d3bf23d"),
        ("scripts/run_safe_pytest.py", "scripts.run_safe_pytest._protected_tree_snapshot", "e1d3bd62adce6c525c264f4d980a76bfda2c42d6aecd83285afa0a7be53f6b06"),
    }
)

# S3-F builds fixed, code-identity-keyed exception vaults so public failures do
# not retain source paths or authority objects in traceback frames.  The
# implementation necessarily uses ``globals`` and ``FunctionType`` plus fixed
# closure dispatch.  Only these exact reviewed AST callsites are suppressed,
# only during the full production scan; any edit or synthetic copy fails closed.
_AUDITED_DYNAMIC_CALLS = frozenset(
    {
        ("app/safety/copy_operation.py", "app.safety.copy_operation._create_copy_boundary_runtime", "84963364438461c87cb2d800531560a4935c054671e7e6f459bc6a8006de3023"),
        ("app/safety/copy_operation.py", "app.safety.copy_operation._create_copy_boundary_runtime.dispatch", "0981a87d3f527cf303f3af144738a521c17abe64eb335150dab923e26a7f54db"),
        ("app/safety/copy_operation.py", "app.safety.copy_operation._create_copy_boundary_runtime.register", "0796ac13589259764060920f990341d81a312580b5b41fe58090ffd90cfe67da"),
        ("app/safety/copy_operation.py", "app.safety.copy_operation._path_free_exception_boundary", "ba525b52ec1b7c45e1f4deb769d4a1653f972eb7e440070ef48810b89b1ce8bd"),
        ("app/safety/copy_operation.py", "<module>", "c28646b37fd6e3553087860fbb0883ce0897ccd04f37a31c82150a3ab105a05a"),
        ("app/safety/external_source.py", "app.safety.external_source._create_external_boundary_runtime", "84963364438461c87cb2d800531560a4935c054671e7e6f459bc6a8006de3023"),
        ("app/safety/external_source.py", "app.safety.external_source._create_external_boundary_runtime.dispatch", "0981a87d3f527cf303f3af144738a521c17abe64eb335150dab923e26a7f54db"),
        ("app/safety/external_source.py", "app.safety.external_source._create_external_boundary_runtime.register", "0796ac13589259764060920f990341d81a312580b5b41fe58090ffd90cfe67da"),
        ("app/safety/external_source.py", "app.safety.external_source._path_free_exception_boundary", "60e6db54225f8451fc300f252c4119249980927c95390f9ea0946e89ad9f2923"),
        ("app/safety/external_source.py", "<module>", "b4bd3fa56b9d29cde5a2a176b9aef6833a5197556488435a68afb3e7c0d68bed"),
    }
)

# The safe launcher deliberately keeps the already-audited ``ctypes`` module on
# three private runtime objects.  Suppression is exact (file/function/AST), is
# active only for the full production scan, and drifts closed.
_AUDITED_CAPABILITY_STORES = frozenset(
    {
        (
            "app/safety/external_source.py",
            "app.safety.external_source._ReferenceReadApi.__init__",
            "1064e62ff455ab4e526ee266e65442b586377a9afcb413cf134f45a72c0186e4",
        ),
        (
            "app/safety/external_source.py",
            "app.safety.external_source._ReferenceReadApi.__init__",
            "3311159ac8f03231b502403042e5b095ec7d3e163b0d670ea664bcfc2974dbb2",
        ),
        (
            "app/safety/external_source.py",
            "app.safety.external_source._ReferenceReadApi.__init__",
            "3c714b0ff80069aad944e767d3a6000ce135a8ef90bbd8a3faa9b8ca8c2391e9",
        ),
        (
            "app/safety/external_source.py",
            "app.safety.external_source._ReferenceReadApi.__init__",
            "4008610d09f8470cd00a0ea4fb59ead369274e83c633e00e1146e29fbe55b2b5",
        ),
        (
            "app/safety/external_source.py",
            "app.safety.external_source._ReferenceReadApi.__init__",
            "5830c8bffc003a1e01d8310f7affca6f2a5a09c34971891080a88f59d1a43b84",
        ),
        (
            "app/safety/external_source.py",
            "app.safety.external_source._ReferenceReadApi.__init__",
            "5bf7a081c452334d1249142ecb9b07924cf64475f225296653c9076fb44b6069",
        ),
        (
            "app/safety/external_source.py",
            "app.safety.external_source._ReferenceReadApi.__init__",
            "760a336c7462cd06d401dd823bb142d6262e1b361e5fcb13ce34a0d01395fa3d",
        ),
        (
            "app/safety/external_source.py",
            "app.safety.external_source._ReferenceReadApi.__init__",
            "9cc738a82ad72278e6b38ee186221f967ec947da264ceaa3a1a73ffe32a0bbd7",
        ),
        (
            "app/safety/external_source.py",
            "app.safety.external_source._ReferenceReadApi.__init__",
            "9cec56da79759d0ebaefa0a2f901d6c2c08c30b727c1ac9cc6fd370fa15b1acf",
        ),
        (
            "app/safety/external_source.py",
            "app.safety.external_source._ReferenceReadApi.__init__",
            "ae91a2a14d1565edc3e370b7ccc61841e3dd42beb21d6335e4b8b2a0ed3044f6",
        ),
        (
            "app/safety/external_source.py",
            "app.safety.external_source._ReferenceReadApi.__init__",
            "af05300fe9760e8a920ac4d5325139c73cd2183e85d70969e2213c413b6de5b0",
        ),
        (
            "app/safety/external_source.py",
            "app.safety.external_source._ReferenceReadApi.__init__",
            "e1ba4d940ade6409e828ff8d219ee0ae173e0078badce9c6dc7e1bf774a49909",
        ),
        (
            "app/safety/external_source.py",
            "app.safety.external_source._ReferenceReadApi.__init__",
            "f0f8cc5aaa988b104300f95988b6cecd4f5a04553c914e135aaa4ef6b49fc808",
        ),
        (
            "app/safety/external_source.py",
            "app.safety.external_source._ReferenceReadApi.__init__",
            "f17f2ed660d0f15d9bac556b9817ccf29b519d5727208d8187eceac382a7fda2",
        ),
        (
            "scripts/run_safe_pytest.py",
            "scripts.run_safe_pytest._WindowsJob.__init__",
            "1ec34eda97bf6ad3947c2bf5a28eb52cd40a296993306f0934c9154141532999",
        ),
        (
            "scripts/run_safe_pytest.py",
            "scripts.run_safe_pytest._WindowsJob.__init__",
            "6ed7dd636bfe9445014bdb262584b96b6e77837c4edc2fce0cc139138ec65459",
        ),
        (
            "scripts/run_safe_pytest.py",
            "scripts.run_safe_pytest._WindowsProtectedTreeWatcher.__init__",
            "1ec34eda97bf6ad3947c2bf5a28eb52cd40a296993306f0934c9154141532999",
        ),
        (
            "scripts/run_safe_pytest.py",
            "scripts.run_safe_pytest._WindowsProtectedTreeWatcher.__init__",
            "6ed7dd636bfe9445014bdb262584b96b6e77837c4edc2fce0cc139138ec65459",
        ),
        (
            "scripts/run_safe_pytest.py",
            "scripts.run_safe_pytest._WindowsProtectedTreeFence.__init__",
            "1ec34eda97bf6ad3947c2bf5a28eb52cd40a296993306f0934c9154141532999",
        ),
        (
            "scripts/run_safe_pytest.py",
            "scripts.run_safe_pytest._WindowsProtectedTreeFence.__init__",
            "6ed7dd636bfe9445014bdb262584b96b6e77837c4edc2fce0cc139138ec65459",
        ),
        (
            "scripts/run_safe_pytest.py",
            "scripts.run_safe_pytest._WindowsStreamInspector.__init__",
            "1ec34eda97bf6ad3947c2bf5a28eb52cd40a296993306f0934c9154141532999",
        ),
        (
            "scripts/run_safe_pytest.py",
            "scripts.run_safe_pytest._WindowsStreamInspector.__init__",
            "6ed7dd636bfe9445014bdb262584b96b6e77837c4edc2fce0cc139138ec65459",
        ),
        (
            "app/safety/windows_handle_writer.py",
            "app.safety.windows_handle_writer._WindowsApi.__init__",
            "1a90fc25128313c62ba27ce7660514bd10838aba2738abe18b8b8354101706d8",
        ),
        (
            "app/safety/windows_handle_writer.py",
            "app.safety.windows_handle_writer._WindowsApi.__init__",
            "a856503201dd5a75dad5a452ae8012c3a94153e99ebbaed33d00c9218fd499e3",
        ),
        (
            "app/safety/windows_handle_writer.py",
            "app.safety.windows_handle_writer._WindowsApi._nt_create_relative",
            "7e4245ccc046bda73f46877c2f5023f39ecdb9925772c8cd50eee4789b1eeae5",
        ),
    }
)

_AUDITED_PARAMETER_CALLS = frozenset(
    {
        ("app/workspace_guard.py", "app.workspace_guard._coerce_path", "1fd0cd7c0f714054724e7666ad0930fe334dc10a1397ad8384ebd1b251ead795"),
        ("app/workspace_guard.py", "app.workspace_guard._coerce_path", "e1bd4ec60fd3b48342eb2295dd720a68b477d2b22f08640bb0007adc247706c9"),
        ("app/workspace_guard.py", "app.workspace_guard._validate_lexical.reject", "63515c16a802b7c25d990824e3aa49c8b9f2fcf81e6fc30f2864fedfe53c9ed2"),
        ("app/workspace_guard.py", "app.workspace_guard.WorkspaceGuard._inspect_full_existing_chain", "73189e10223cc3a87708653d5f3b65dfdb064a951f8698aec5eafb4e753d5068"),
        ("app/workspace_guard.py", "app.workspace_guard.WorkspaceGuard._inspect_full_existing_chain", "d26a053480615eaf5f3b7d2fee74cae90d2245d45234a5bca23238ccce151142"),
        ("app/workspace_guard.py", "app.workspace_guard.WorkspaceGuard._inspect_chain", "8e66ca6d98bd7348addbaea9af144320eb739076627f2ee875f9687897334b19"),
        ("app/workspace_guard.py", "app.workspace_guard.WorkspaceGuard._inspect_chain", "222bd609306b0358686091d9dc1c91a0c79335d1f83bfabc43c2291777e342c2"),
        ("app/workspace_guard.py", "app.workspace_guard.WorkspaceGuard._inspect_chain", "dfb5411a2bab8161053e452dc77d098be911412f135b9f2d882e4a24d8c9ce69"),
        ("app/workspace_guard.py", "app.workspace_guard.WorkspaceGuard._inspect_chain", "1150c523cd34258d9c28a929b0d20b2ca17f7f9b3e2bf47d7a8b41103f3ec4ed"),
        ("app/workspace_guard.py", "app.workspace_guard.WorkspaceGuard._reject_reparse", "27768fb2aee52302ad06038c73ea430b9632e481ef45c6536392d4d171fb9063"),
        ("app/safety/production_guard.py", "app.safety.production_guard.BoundaryFailure.from_exception", "281cd909029b239d78f1776a73450528042ee436730003e4de90232753ee2610"),
        ("app/safety/production_guard.py", "app.safety.production_guard.BoundaryFailure.from_exception", "c79a7efb8c986f3aad47d6e52803500aaeb3a8b29dd16eda839578ff442f6edc"),
        ("app/safety/production_guard.py", "app.safety.production_guard.BoundaryResult.success", "ce30e78555b675881df160a49c04f15b00fa763d383541d867fdafb4399101c5"),
        ("app/safety/production_guard.py", "app.safety.production_guard.BoundaryResult.failed", "8ba1a3a0d7db083f0416e6d6e782e667be0582bb136ba65a0b1c8800d9746411"),
        ("app/safety/production_guard.py", "app.safety.production_guard._BoundaryCore._record_audit_factory", "732a4cffe97798d2d7168ac628c0b44418f5d7aa59d2b01a2c4e0bed5d6e8f95"),
        ("app/safety/segment_ledger.py", "app.safety.segment_ledger.DurableAuditLedger.append_built_audit_batch", "cb759496c5a56f3ed8542517b7238a8f92e04a30717532b214115fceaad2d2fb"),
        ("app/safety/segment_ledger.py", "app.safety.segment_ledger.DurableAuditLedger._append_with_factory", "2849fb89cafd0e4a3cf746128c483671a03e1e3dbfc33bab25e78916ff4afe08"),
        ("app/safety/segment_ledger.py", "app.safety.segment_ledger.DurableAuditLedger._append_built_audit_batch_under_existing_mutex", "9c11d8c09fa20e5aa7fa271b709fdd1b960705d79bce59f636a4d446e8c696d9"),
    }
)

_RISKY_CAPABILITY_REFERENCES = frozenset(
    {
        "builtins.eval",
        "builtins.exec",
        "eval",
        "exec",
        "os.remove",
        "os.removedirs",
        "os.rename",
        "os.replace",
        "os.rmdir",
        "os.system",
        "os.unlink",
        "shutil.copy",
        "shutil.copy2",
        "shutil.copyfile",
        "shutil.copytree",
        "shutil.move",
        "shutil.rmtree",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.popen",
        "subprocess.run",
    }
)
_NATIVE_CAPABILITY_PREFIXES = (
    "_ctypes.",
    "ctypes.cdll",
    "ctypes.libraryloader",
    "ctypes.oledll",
    "ctypes.pydll",
    "ctypes.pythonapi",
    "ctypes.windll",
)
_CAPABILITY_NAMESPACE_REFERENCES = frozenset(
    {
        "_ctypes",
        "builtins",
        "cffi",
        "ctypes",
        "httpx",
        "importlib",
        "io",
        "mmap",
        "os",
        "requests",
        "shutil",
        "socket",
        "subprocess",
        "tempfile",
        "urllib.request",
    }
)
_NATIVE_ESCAPING_RESULTS = frozenset(
    {
        "ctypes.cdll()",
        "ctypes.libraryloader()",
        "ctypes.oledll()",
        "ctypes.pydll()",
        "ctypes.windll()",
        "ctypes.cast()",
    }
)


class WritePrimitiveKind(StrEnum):
    FILESYSTEM_DIRECTORY_CREATE = "FILESYSTEM_DIRECTORY_CREATE"
    FILESYSTEM_FILE_WRITE = "FILESYSTEM_FILE_WRITE"
    FILESYSTEM_COPY = "FILESYSTEM_COPY"
    FILESYSTEM_MOVE_OR_REPLACE = "FILESYSTEM_MOVE_OR_REPLACE"
    FILESYSTEM_DELETE = "FILESYSTEM_DELETE"
    FILESYSTEM_LINK = "FILESYSTEM_LINK"
    FILESYSTEM_METADATA = "FILESYSTEM_METADATA"
    TEMPORARY_RESOURCE = "TEMPORARY_RESOURCE"
    ARCHIVE_WRITE = "ARCHIVE_WRITE"
    ARCHIVE_EXTRACT = "ARCHIVE_EXTRACT"
    SQLITE_RAW_CONNECT = "SQLITE_RAW_CONNECT"
    DATABASE_GATEWAY = "DATABASE_GATEWAY"
    DURABLE_LEDGER_GATEWAY = "DURABLE_LEDGER_GATEWAY"
    DATABASE_IMPLICIT_INITIALIZER = "DATABASE_IMPLICIT_INITIALIZER"
    SQLITE_MUTATION = "SQLITE_MUTATION"
    SQLITE_DYNAMIC_SQL = "SQLITE_DYNAMIC_SQL"
    SQLITE_TRANSACTION = "SQLITE_TRANSACTION"
    SQLITE_BACKUP_OR_EXTENSION = "SQLITE_BACKUP_OR_EXTENSION"
    SQLITE_SCHEMA_MUTATION = "SQLITE_SCHEMA_MUTATION"
    EXTERNAL_PROCESS = "EXTERNAL_PROCESS"
    NETWORK_REQUEST = "NETWORK_REQUEST"
    SYSTEM_STATE = "SYSTEM_STATE"
    RUNTIME_SYNCHRONIZATION = "RUNTIME_SYNCHRONIZATION"
    NATIVE_API_BINDING = "NATIVE_API_BINDING"
    UNKNOWN_DYNAMIC_CAPABILITY = "UNKNOWN_DYNAMIC_CAPABILITY"


class ResolutionConfidence(StrEnum):
    EXACT = "EXACT"
    ALIAS_RESOLVED = "ALIAS_RESOLVED"
    CONSERVATIVE = "CONSERVATIVE"
    DYNAMIC = "DYNAMIC"


class MigrationStatus(StrEnum):
    UNMIGRATED_BLOCKED = "UNMIGRATED_BLOCKED"
    ACCEPTED_MEMORY_ONLY = "ACCEPTED_MEMORY_ONLY"


class RiskLevel(StrEnum):
    P0 = "P0"
    P1 = "P1"


@dataclass(frozen=True, slots=True)
class WriteEntry:
    entry_id: str
    file: str
    source_sha256: str
    line: int
    column: int
    end_line: int
    end_column: int
    function: str
    kind: WritePrimitiveKind
    callee: str
    resolution: ResolutionConfidence
    statement_fingerprint: str
    owner: str
    target_namespace: str
    required_control: str
    migration_status: MigrationStatus
    input_source: str
    risk: RiskLevel
    root_ids: tuple[str, ...]
    call_chain: tuple[str, ...]
    detail: str

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        for name in ("kind", "resolution", "migration_status", "risk"):
            payload[name] = getattr(self, name).value
        payload["root_ids"] = list(self.root_ids)
        payload["call_chain"] = list(self.call_chain)
        return payload


@dataclass(frozen=True, slots=True)
class _RawEntry:
    file: str
    source_sha256: str
    line: int
    column: int
    end_line: int
    end_column: int
    function: str
    kind: WritePrimitiveKind
    callee: str
    resolution: ResolutionConfidence
    statement_fingerprint: str
    detail: str


@dataclass(frozen=True, slots=True)
class _FunctionFact:
    canonical: str
    file: str
    node: ast.FunctionDef | ast.AsyncFunctionDef
    root_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _ModuleFacts:
    file: str
    module: str
    source_sha256: str
    tree: ast.Module
    parents: dict[ast.AST, ast.AST]
    imports: dict[str, str]
    functions: dict[str, _FunctionFact]


_SQL_MUTATION = frozenset(
    {
        "INSERT",
        "UPDATE",
        "DELETE",
        "REPLACE",
        "CREATE",
        "ALTER",
        "DROP",
        "VACUUM",
        "ATTACH",
        "DETACH",
        "REINDEX",
        "ANALYZE",
        "PRAGMA",
    }
)
_SQL_TRANSACTION = frozenset(
    {"BEGIN", "COMMIT", "END", "ROLLBACK", "SAVEPOINT", "RELEASE"}
)
_SQL_PREFIX = re.compile(
    r"\b(SELECT|WITH|INSERT|UPDATE|DELETE|REPLACE|CREATE|ALTER|DROP|VACUUM|ATTACH|DETACH|REINDEX|ANALYZE|PRAGMA|BEGIN|COMMIT|END|ROLLBACK|SAVEPOINT|RELEASE|EXPLAIN)\b",
    re.IGNORECASE,
)
_SQL_COMMENTS = re.compile(r"(?:--[^\n]*(?:\n|$)|/\*.*?\*/)", re.DOTALL)


def scan_production_write_entries() -> tuple[WriteEntry, ...]:
    root = _verified_project_root()
    snapshot = _production_source_snapshot(root)
    return _scan_production_snapshot(root, snapshot)


def _scan_production_snapshot(
    root: Path,
    snapshot: tuple[tuple[Path, bytes], ...],
) -> tuple[WriteEntry, ...]:
    facts = _load_module_facts(root, snapshot)
    raw_entries: list[_RawEntry] = []
    audited_indexed_hits: Counter[tuple[str, str, str]] = Counter()
    for module in facts.values():
        raw_entries.extend(
            _scan_module(module, audited_indexed_hits=audited_indexed_hits)
        )
    _assert_audited_indexed_hits(audited_indexed_hits)
    raw_entries.extend(_scan_sql_files(root, snapshot))
    graph, roots = _build_call_graph(facts)
    entries = _enrich_entries(raw_entries, graph, roots)
    return tuple(
        sorted(
            entries,
            key=lambda item: (
                item.file,
                item.line,
                item.column,
                item.kind.value,
                item.entry_id,
            ),
        )
    )


def _assert_audited_indexed_hits(
    hits: Counter[tuple[str, str, str]],
) -> None:
    drift = {
        callsite: hits.get(callsite, 0)
        for callsite in _AUDITED_INDEXED_CALLS
        if hits.get(callsite, 0) != 1
    }
    if drift:
        raise RuntimeError(
            "audited indexed callsite suppression drifted: "
            + "; ".join(
                f"{file}:{function}:{fingerprint}={count}"
                for (file, function, fingerprint), count in sorted(drift.items())
            )
        )
    dynamic_drift = {
        callsite: hits.get(callsite, 0)
        for callsite in _AUDITED_DYNAMIC_CALLS
        if hits.get(callsite, 0) != 1
    }
    if dynamic_drift:
        raise RuntimeError(
            "audited dynamic callsite suppression drifted: "
            + "; ".join(
                f"{file}:{function}:{fingerprint}={count}"
                for (file, function, fingerprint), count in sorted(dynamic_drift.items())
            )
        )
    store_drift = {
        callsite: hits.get(callsite, 0)
        for callsite in _AUDITED_CAPABILITY_STORES
        if hits.get(callsite, 0) != 1
    }
    if store_drift:
        raise RuntimeError(
            "audited capability-store suppression drifted: "
            + "; ".join(
                f"{file}:{function}:{fingerprint}={count}"
                for (file, function, fingerprint), count in sorted(store_drift.items())
            )
        )
    parameter_drift = {
        callsite: hits.get(callsite, 0)
        for callsite in _AUDITED_PARAMETER_CALLS
        if hits.get(callsite, 0) != 1
    }
    if parameter_drift:
        raise RuntimeError(
            "audited parameter-call suppression drifted: "
            + "; ".join(
                f"{file}:{function}:{fingerprint}={count}"
                for (file, function, fingerprint), count in sorted(parameter_drift.items())
            )
        )


def scan_python_source(source: str, *, file: str = "synthetic.py") -> tuple[WriteEntry, ...]:
    """Scan a synthetic fixture without importing or executing it."""

    module = _module_facts_from_text(source, file=file)
    raw = _scan_module(module)
    graph, roots = _build_call_graph({module.module: module})
    return tuple(_enrich_entries(raw, graph, roots))


def scan_unauthorized_guard_construction() -> tuple[tuple[str, int, str], ...]:
    findings: list[tuple[str, int, str]] = []
    for module in _load_module_facts(_verified_project_root()).values():
        findings.extend(_guard_findings(module))
    return tuple(sorted(set(findings)))


def scan_unauthorized_guard_source(
    source: str,
    *,
    file: str = "app/synthetic.py",
) -> tuple[tuple[str, int, str], ...]:
    return tuple(sorted(set(_guard_findings(_module_facts_from_text(source, file=file)))))


def _guard_findings(module: _ModuleFacts) -> list[tuple[str, int, str]]:
    findings: list[tuple[str, int, str]] = []
    allowed_file = "app/safety/production_guard.py"
    ledger_file = "app/safety/segment_ledger.py"
    job_file = "app/safety/job_operation.py"
    operation_file = "app/safety/operation_ledger.py"
    writer_file = "app/safety/windows_handle_writer.py"
    copy_ledger_file = "app/safety/copy_ledger.py"
    copy_operation_file = "app/safety/copy_operation.py"
    external_source_file = "app/safety/external_source.py"
    project_root_file = "app/project_root.py"
    safety_module_prefixes = (
        "app.safety.production_guard",
        "app.safety.namespace_policy",
        "app.safety.windows_handle_writer",
        "app.safety.segment_ledger",
        "app.safety.job_operation",
        "app.safety.operation_ledger",
        "app.safety.copy_ledger",
        "app.safety.copy_operation",
        "app.safety.external_source",
    )
    assignments_by_scope: dict[str, list[tuple[list[ast.expr], ast.expr]]] = defaultdict(list)
    for candidate in ast.walk(module.tree):
        if isinstance(candidate, ast.Assign):
            targets = list(candidate.targets)
            value = candidate.value
        elif isinstance(candidate, ast.AnnAssign) and candidate.value is not None:
            targets = [candidate.target]
            value = candidate.value
        else:
            continue
        assignments_by_scope[
            _enclosing_function_qualname(candidate, module.parents)
        ].append((targets, value))

    def resolve_scope_aliases(
        initial: dict[str, str],
        assignments: list[tuple[list[ast.expr], ast.expr]],
    ) -> dict[str, str]:
        aliases = dict(initial)
        for _ in range(8):
            changed = False
            for targets, value in assignments:
                resolved, _confidence = _resolve_callee(value, aliases)
                for target in targets:
                    if (
                        isinstance(target, ast.Name)
                        and aliases.get(target.id) != resolved
                    ):
                        aliases[target.id] = resolved
                        changed = True
            if not changed:
                break
        return aliases

    module_aliases = resolve_scope_aliases(
        dict(module.imports),
        assignments_by_scope.get("<module>", []),
    )
    aliases_by_scope = {
        scope: resolve_scope_aliases(module_aliases, assignments)
        for scope, assignments in assignments_by_scope.items()
        if scope != "<module>"
    }
    aliases_by_scope["<module>"] = module_aliases

    def aliases_for(node: ast.AST) -> dict[str, str]:
        scope = _enclosing_function_qualname(node, module.parents)
        return aliases_by_scope.get(scope, module_aliases)

    forbidden_constructors = {
        "WorkspaceGuard",
        "ProductionWorkspaceBoundary",
        "_TestWorkspaceBoundary",
        "_create_test_boundary",
        "_BoundaryCore",
        "_BoundaryNamespacePolicy",
        "NamespacePolicy",
        "_WindowsHandleWriter",
        "_WindowsApi",
        "_create_test_handle_writer",
        "AuditKeyRevisionStore",
        "DurableAuditLedger",
        "DurableAuditSink",
        "DurableOperationLedger",
        "_AuditAuthority",
        "_TestDurableBoundaryBundle",
        "_create_test_durable_boundary",
        "_TestJobRuntime",
        "_build_test_job_runtime",
        "_JOB_RUNTIME_CONSTRUCTOR",
        "_ImmutableFileLease",
        "_IMMUTABLE_FILE_LEASE_CONSTRUCTOR",
        "_JobContextPin",
        "_JOB_CONTEXT_PIN_CONSTRUCTOR",
        "_OPERATION_LEDGER_CONSTRUCTOR",
        "_resolve_reviewed_operation_epochs_under_existing_mutex",
        "_ReservedPairLease",
        "_PAIR_RESERVATION_CONSTRUCTOR",
        "_DirectoryPublishJournalPermit",
        "_DIRECTORY_PUBLISH_PERMIT_CONSTRUCTOR",
        "HandleObjectIdentityMaterial",
        "HandleTreeIdentityMaterial",
        "_IDENTITY_MATERIAL_CONSTRUCTOR",
        "_AUDIT_AUTHORITY_CONSTRUCTOR",
        "_LEDGER_CONSTRUCTOR",
        "_HANDLE_WRITER_CONSTRUCTOR",
        "_TOKEN_CONSTRUCTOR",
        "_PAIR_CLAIM_CONSTRUCTOR",
        "DurableCopyLedgers",
        "_COPY_LEDGERS_CONSTRUCTOR",
        "_AuthenticatedCopyAncestors",
        "_AUTHENTICATED_COPY_ANCESTORS_CONSTRUCTOR",
        "_TestLocalCopyOperation",
        "_COPY_OPERATION_CONSTRUCTOR",
        "_ReferenceReadApi",
        "_READ_API_CONSTRUCTOR",
        "SyntheticReferenceReadPolicy",
        "_POLICY_CONSTRUCTOR",
        "_SyntheticReferenceLease",
        "_LEASE_CONSTRUCTOR",
        "_CopyExecutionPermit",
        "_COPY_EXECUTION_PERMIT_CONSTRUCTOR",
        "_create_synthetic_reference_read_policy",
        "_copy_execution_scope_sha256",
        "_copy_execution_binding_sha256",
        "_require_copy_execution_authorities",
        "_issue_copy_execution_permit",
        "_check_copy_execution_permit",
        "_validate_copy_execution_permit",
        "_consume_copy_execution_permit",
        "_create_test_copy_ledgers",
        "_create_test_copy_operation",
        "_RestrictedRecoveryLocatorRecord",
        "_RestrictedRecoveryLocatorCapability",
        "_RECOVERY_LOCATOR_CONSTRUCTOR",
        "CopyProvenanceMaterial",
        "build_copy_provenance_material",
        "COPY_PROVENANCE_FILE_NAME",
    }
    forbidden_private_imports = {
        "_BoundaryCore",
        "_create_test_boundary",
        "_TestWorkspaceBoundary",
        "_TOKEN_CONSTRUCTOR",
        "_PAIR_CLAIM_CONSTRUCTOR",
        "_PairPolicyClaim",
        "_authorize_pair_for_boundary",
        "_BoundaryNamespacePolicy",
        "_HANDLE_WRITER_CONSTRUCTOR",
        "_WindowsHandleWriter",
        "_WindowsApi",
        "_create_test_handle_writer",
        "_AUDIT_AUTHORITY_CONSTRUCTOR",
        "_LEDGER_CONSTRUCTOR",
        "_AuditAuthority",
        "_TestDurableBoundaryBundle",
        "_create_test_durable_boundary",
        "_LedgerStorage",
        "_TestJobRuntime",
        "_build_test_job_runtime",
        "_JOB_RUNTIME_CONSTRUCTOR",
        "_ImmutableFileLease",
        "_IMMUTABLE_FILE_LEASE_CONSTRUCTOR",
        "_JobContextPin",
        "_JOB_CONTEXT_PIN_CONSTRUCTOR",
        "_OPERATION_LEDGER_CONSTRUCTOR",
        "_resolve_reviewed_operation_epochs_under_existing_mutex",
        "_ReservedPairLease",
        "_PAIR_RESERVATION_CONSTRUCTOR",
        "_DirectoryPublishJournalPermit",
        "_DIRECTORY_PUBLISH_PERMIT_CONSTRUCTOR",
        "_IDENTITY_MATERIAL_CONSTRUCTOR",
        "_COPY_LEDGERS_CONSTRUCTOR",
        "_AuthenticatedCopyAncestors",
        "_AUTHENTICATED_COPY_ANCESTORS_CONSTRUCTOR",
        "_TestLocalCopyOperation",
        "_COPY_OPERATION_CONSTRUCTOR",
        "_ReferenceReadApi",
        "_READ_API_CONSTRUCTOR",
        "SyntheticReferenceReadPolicy",
        "_POLICY_CONSTRUCTOR",
        "_SyntheticReferenceLease",
        "_LEASE_CONSTRUCTOR",
        "_CopyExecutionPermit",
        "_COPY_EXECUTION_PERMIT_CONSTRUCTOR",
        "_create_synthetic_reference_read_policy",
        "_copy_execution_scope_sha256",
        "_copy_execution_binding_sha256",
        "_require_copy_execution_authorities",
        "_issue_copy_execution_permit",
        "_check_copy_execution_permit",
        "_validate_copy_execution_permit",
        "_consume_copy_execution_permit",
        "_create_test_copy_ledgers",
        "_create_test_copy_operation",
        "_RestrictedRecoveryLocatorRecord",
        "_RestrictedRecoveryLocatorCapability",
        "_RECOVERY_LOCATOR_CONSTRUCTOR",
        "CopyProvenanceMaterial",
        "build_copy_provenance_material",
        "COPY_PROVENANCE_FILE_NAME",
    }
    sensitive_assignments = {
        "CONTRACT_PROJECT_ROOT",
        "PROJECT_ROOT",
        "_contract_root",
        "_PRODUCTION_BOUNDARY_CONSTRUCTOR",
        "_TOKEN_CONSTRUCTOR",
        "_PAIR_CLAIM_CONSTRUCTOR",
        "_guard",
        "_policy",
        "__guard",
        "__policy",
        "__core",
        "_rules",
        "_digest",
        "_pair_claim_key",
        "_pair_authority",
        "__pair_authority",
        "__pair_policy_authority",
        "_HANDLE_WRITER_CONSTRUCTOR",
        "_path_authority",
        "_AUDIT_AUTHORITY_CONSTRUCTOR",
        "_storage",
        "_key_store",
        "_ledger",
        "_sealed_code",
        "_segments",
        "_revisions",
        "_batches",
        "_record_ids",
        "_head",
        "_total_segment_bytes",
        "_fresh_revision_ids",
        "_epoch_id",
        "_initial_revision_id",
        "_master_key",
        "_KEY_ROOT",
        "_SEGMENT_ROOT",
        "_mutex_name",
        "_ACTIVE_MUTEX_NAMES",
        "_LEDGER_CONSTRUCTOR",
        "_JOB_RUNTIME_CONSTRUCTOR",
        "_IMMUTABLE_FILE_LEASE_CONSTRUCTOR",
        "_JOB_CONTEXT_PIN_CONSTRUCTOR",
        "_OPERATION_LEDGER_CONSTRUCTOR",
        "_PAIR_RESERVATION_CONSTRUCTOR",
        "_DIRECTORY_PUBLISH_PERMIT_CONSTRUCTOR",
        "_IDENTITY_MATERIAL_CONSTRUCTOR",
        "__frame",
        "__rows",
        "_COPY_LEDGERS_CONSTRUCTOR",
        "_AUTHENTICATED_COPY_ANCESTORS_CONSTRUCTOR",
        "_COPY_OPERATION_CONSTRUCTOR",
        "_READ_API_CONSTRUCTOR",
        "_POLICY_CONSTRUCTOR",
        "_LEASE_CONSTRUCTOR",
        "_COPY_EXECUTION_PERMIT_CONSTRUCTOR",
        "_RECOVERY_LOCATOR_CONSTRUCTOR",
        "_publish_terminal_binding_sha256s",
        "_copy_cross_reference_sha256",
        "_runtime",
        "_writer",
        "_operation_ledger",
        "_workspace_root",
        "_ledgers",
        "_source_policy",
        "_source_chain",
        "_copy_chain",
        "_revision",
        "_run_scope_id",
        "_run_scope_hmac_sha256",
        "_known_revisions",
        "_requested_revision_id",
        "_append_enabled",
        "_api",
        "_locator_key",
        "_digest_key",
        "auth_key",
        "POLICY_ID",
        "POLICY_VERSION",
        "POLICY_DIGEST",
        "EXPECTED_POLICY_DIGEST",
    }
    symbol_definition_files = {
        "WorkspaceGuard": {"app/workspace_guard.py", allowed_file},
        "NamespacePolicy": {"app/safety/namespace_policy.py", allowed_file},
        "ProductionWorkspaceBoundary": {allowed_file},
        "_TestWorkspaceBoundary": {allowed_file},
        "_create_test_boundary": {allowed_file},
        "_BoundaryCore": {allowed_file},
        "_BoundaryNamespacePolicy": {
            allowed_file,
            "app/safety/namespace_policy.py",
        },
        "_WindowsHandleWriter": {
            allowed_file,
            job_file,
            operation_file,
            copy_ledger_file,
            "app/safety/windows_handle_writer.py",
        },
        "_WindowsApi": {
            allowed_file,
            job_file,
            "app/safety/windows_handle_writer.py",
        },
        "_create_test_handle_writer": {allowed_file},
        "AuditKeyRevisionStore": {allowed_file, ledger_file},
        "DurableAuditLedger": {
            allowed_file,
            ledger_file,
            job_file,
            copy_ledger_file,
        },
        "DurableAuditSink": {allowed_file, ledger_file},
        "DurableOperationLedger": {
            allowed_file,
            job_file,
            operation_file,
            copy_operation_file,
            copy_ledger_file,
        },
        "_AuditAuthority": {allowed_file},
        "_TestDurableBoundaryBundle": {allowed_file},
        "_create_test_durable_boundary": {allowed_file},
        "_TestJobRuntime": {allowed_file, job_file, copy_operation_file},
        "_build_test_job_runtime": {allowed_file, job_file},
        "_JOB_RUNTIME_CONSTRUCTOR": {allowed_file, job_file},
        "_ImmutableFileLease": {
            job_file,
            "app/safety/windows_handle_writer.py",
        },
        "_IMMUTABLE_FILE_LEASE_CONSTRUCTOR": {
            "app/safety/windows_handle_writer.py",
        },
        "_JobContextPin": {allowed_file},
        "_JOB_CONTEXT_PIN_CONSTRUCTOR": {allowed_file},
        "_OPERATION_LEDGER_CONSTRUCTOR": {allowed_file, operation_file},
        "_resolve_reviewed_operation_epochs_under_existing_mutex": {
            allowed_file,
            operation_file,
        },
        "_ReservedPairLease": {allowed_file},
        "_PAIR_RESERVATION_CONSTRUCTOR": {allowed_file},
        "_DirectoryPublishJournalPermit": {job_file, writer_file},
        "_DIRECTORY_PUBLISH_PERMIT_CONSTRUCTOR": {writer_file},
        "HandleObjectIdentityMaterial": {writer_file, operation_file},
        "HandleTreeIdentityMaterial": {writer_file, operation_file},
        "_IDENTITY_MATERIAL_CONSTRUCTOR": {writer_file},
        "_AUDIT_AUTHORITY_CONSTRUCTOR": {allowed_file},
        "_LEDGER_CONSTRUCTOR": {allowed_file, ledger_file},
        "_HANDLE_WRITER_CONSTRUCTOR": {
            allowed_file,
            "app/safety/windows_handle_writer.py",
        },
        "_TOKEN_CONSTRUCTOR": {allowed_file},
        "_PAIR_CLAIM_CONSTRUCTOR": {
            allowed_file,
            "app/safety/namespace_policy.py",
        },
        "DurableCopyLedgers": {
            allowed_file,
            copy_ledger_file,
            copy_operation_file,
        },
        "_COPY_LEDGERS_CONSTRUCTOR": {allowed_file, copy_ledger_file},
        "_AuthenticatedCopyAncestors": {copy_ledger_file},
        "_AUTHENTICATED_COPY_ANCESTORS_CONSTRUCTOR": {copy_ledger_file},
        "_TestLocalCopyOperation": {allowed_file, copy_operation_file},
        "_COPY_OPERATION_CONSTRUCTOR": {allowed_file, copy_operation_file},
        "_ReferenceReadApi": {external_source_file},
        "_READ_API_CONSTRUCTOR": {external_source_file},
        "SyntheticReferenceReadPolicy": {
            external_source_file,
            copy_operation_file,
        },
        "_POLICY_CONSTRUCTOR": {external_source_file},
        "_SyntheticReferenceLease": {
            external_source_file,
            copy_operation_file,
        },
        "_LEASE_CONSTRUCTOR": {external_source_file},
        "_CopyExecutionPermit": {
            external_source_file,
            copy_operation_file,
        },
        "_COPY_EXECUTION_PERMIT_CONSTRUCTOR": {external_source_file},
        "_create_synthetic_reference_read_policy": {
            allowed_file,
            external_source_file,
        },
        "_copy_execution_scope_sha256": {external_source_file},
        "_copy_execution_binding_sha256": {external_source_file},
        "_require_copy_execution_authorities": {external_source_file},
        "_issue_copy_execution_permit": {
            external_source_file,
            copy_operation_file,
        },
        "_check_copy_execution_permit": {external_source_file},
        "_validate_copy_execution_permit": {
            external_source_file,
            copy_operation_file,
        },
        "_consume_copy_execution_permit": {
            external_source_file,
            copy_operation_file,
        },
        "_create_test_copy_ledgers": {allowed_file},
        "_create_test_copy_operation": {allowed_file},
        "_RestrictedRecoveryLocatorRecord": {allowed_file},
        "_RestrictedRecoveryLocatorCapability": {allowed_file},
        "_RECOVERY_LOCATOR_CONSTRUCTOR": {allowed_file},
        "CopyProvenanceMaterial": {copy_ledger_file, copy_operation_file},
        "build_copy_provenance_material": {copy_ledger_file, copy_operation_file},
        "COPY_PROVENANCE_FILE_NAME": {copy_ledger_file, copy_operation_file},
    }
    restricted_private_calls: dict[str, set[tuple[str, str]]] = {
        "_operation_hmac_sha256": {
            (operation_file, "DurableOperationLedger.durable_object_identity_digest"),
            (operation_file, "DurableOperationLedger.durable_tree_identity_digest"),
            (
                operation_file,
                "DurableOperationLedger.durable_tree_evidence_identity_digest",
            ),
        },
        "_issue_directory_publish_journal_permit": {
            (job_file, "_OperationLease.execute_publish_pair"),
            (job_file, "_OperationLease.execute_quarantine_pair"),
        },
        "_publish_observed_directory_no_replace": {
            (job_file, "_OperationLease.execute_publish_pair"),
            (job_file, "_OperationLease.execute_quarantine_pair"),
        },
        "_observe_existing_tree_snapshot": {
            (allowed_file, "_reconcile_test_publish_operation.observe_once"),
        },
        "_require_directory_target_absent_under_existing_mutex": {
            (
                copy_operation_file,
                "_TestLocalCopyOperation._require_target_absent_twice",
            ),
        },
        "_after_directory_target_absence_first_observation": {
            (
                writer_file,
                "_WindowsHandleWriter._require_directory_target_absent_under_existing_mutex",
            ),
        },
        "_append_transition_under_existing_mutex": {
            (job_file, "_PublishOperationJournal._append"),
            (allowed_file, "_reconcile_test_publish_operation"),
            (copy_operation_file, "_TestLocalCopyOperation._execute_new"),
            (copy_operation_file, "_TestLocalCopyOperation._append_failure_fact"),
            (
                copy_operation_file,
                "_TestLocalCopyOperation._reconcile_committed_publish",
            ),
            (
                copy_operation_file,
                "_TestLocalCopyOperation._reconcile_absent_publish",
            ),
            (
                copy_operation_file,
                "_TestLocalCopyOperation._reconcile_source_only_abort",
            ),
        },
        "transaction_result_under_existing_mutex": {
            (allowed_file, "_reconcile_test_publish_operation"),
            (job_file, "_OperationLease.execute_publish_pair"),
            (job_file, "_OperationLease.execute_quarantine_pair"),
            (copy_operation_file, "_TestLocalCopyOperation._try_replay"),
            (
                copy_operation_file,
                "_TestLocalCopyOperation._reconcile_consumed_source",
            ),
            (
                copy_operation_file,
                "_TestLocalCopyOperation._validate_ledgers_for_new_operation",
            ),
            (copy_operation_file, "_TestLocalCopyOperation._append_failure_fact"),
            (
                copy_operation_file,
                "_TestLocalCopyOperation._validate_authenticated_publish_result",
            ),
            (
                copy_operation_file,
                "_TestLocalCopyOperation._reconcile_committed_publish",
            ),
            (
                copy_operation_file,
                "_TestLocalCopyOperation._reconcile_absent_publish",
            ),
            (
                copy_operation_file,
                "_TestLocalCopyOperation._reconcile_source_only_abort",
            ),
            (
                copy_ledger_file,
                "DurableCopyLedgers._authenticated_publish_terminal_bindings_for_epochs_under_existing_mutex",
            ),
        },
        "operation_result_under_existing_mutex": {
            (job_file, "_TestJobRuntime.replay_committed_publish"),
            (job_file, "_TestJobRuntime.replay_committed_quarantine"),
            (job_file, "_TestJobRuntime.begin_operation"),
            (copy_operation_file, "_TestLocalCopyOperation._append_failure_fact"),
            (
                copy_operation_file,
                "_TestLocalCopyOperation._reconcile_consumed_source",
            ),
        },
        "_rescan_under_existing_mutex": {
            (job_file, "_TestJobRuntime.replay_committed_publish"),
            (job_file, "_TestJobRuntime.replay_committed_quarantine"),
            (job_file, "_TestJobRuntime.begin_operation"),
            (job_file, "_OperationLease.observe_quarantine_source"),
            (job_file, "_OperationLease.prepare_retained_restore"),
            (job_file, "_OperationLease.authorize_publish"),
            (job_file, "_OperationLease.authorize_quarantine"),
            (job_file, "_OperationLease.execute_publish_pair"),
            (job_file, "_OperationLease.execute_quarantine_pair"),
            (job_file, "_JobStagingLease.seal_and_observe"),
            (job_file, "_ObservedJobTreeLease.revalidate"),
            (job_file, "_ObservedQuarantineTreeLease.revalidate"),
            (operation_file, "DurableOperationLedger.unresolved_under_existing_mutex"),
            (operation_file, "DurableOperationLedger.operation_result_under_existing_mutex"),
            (operation_file, "DurableOperationLedger.transaction_result_under_existing_mutex"),
            (operation_file, "DurableOperationLedger.bound_audit_heads_under_existing_mutex"),
            (operation_file, "DurableOperationLedger.authenticated_segment_sha256s_under_existing_mutex"),
            (
                operation_file,
                "_resolve_reviewed_operation_epochs_under_existing_mutex",
            ),
            (allowed_file, "_create_test_operation_ledger"),
            (allowed_file, "_create_test_copy_ledgers"),
            (allowed_file, "_reconcile_test_publish_operation"),
            (allowed_file, "_BoundaryCore._attest_copy_ledger_read"),
            (ledger_file, "DurableAuditLedger._contains_segment_sha256_under_existing_mutex"),
            (ledger_file, "DurableAuditLedger._contains_all_segment_sha256_under_existing_mutex"),
            (ledger_file, "DurableAuditLedger._activated_revision_ids_under_existing_mutex"),
            (ledger_file, "DurableAuditLedger.authenticated_segment_sha256s_under_existing_mutex"),
            (copy_ledger_file, "DurableCopyLedgers.source_result_under_existing_mutex"),
            (
                copy_ledger_file,
                "DurableCopyLedgers.transaction_source_result_under_existing_mutex",
            ),
            (copy_ledger_file, "DurableCopyLedgers.transaction_result_under_existing_mutex"),
            (copy_ledger_file, "DurableCopyLedgers.bound_audit_ancestors_under_existing_mutex"),
            (copy_ledger_file, "DurableCopyLedgers.bound_publish_terminals_under_existing_mutex"),
            (
                copy_ledger_file,
                "DurableCopyLedgers._authenticated_publish_terminal_bindings_under_existing_mutex",
            ),
            (
                copy_ledger_file,
                "DurableCopyLedgers._authenticated_publish_terminal_bindings_for_epochs_under_existing_mutex",
            ),
            (
                copy_ledger_file,
                "DurableCopyLedgers._validate_full_dag_with_operation_epochs_under_existing_mutex",
            ),
            (
                copy_ledger_file,
                "DurableCopyLedgers._append_revision_is_current_under_existing_mutex",
            ),
            (
                copy_ledger_file,
                "DurableCopyLedgers._issue_operation_absence_witness_under_existing_mutex",
            ),
            (copy_operation_file, "_TestLocalCopyOperation._try_replay"),
            (
                copy_operation_file,
                "_TestLocalCopyOperation._prepare_source_for_execute",
            ),
            (
                copy_operation_file,
                "_TestLocalCopyOperation._load_source_for_recovery",
            ),
            (copy_operation_file, "_TestLocalCopyOperation._validate_ledgers_for_new_operation"),
            (
                copy_operation_file,
                "_TestLocalCopyOperation._reconcile_consumed_source",
            ),
        },
        "bound_audit_heads_under_existing_mutex": {
            (job_file, "_TestJobRuntime._validate_operation_audit_bindings"),
            (allowed_file, "_create_test_operation_ledger"),
            (allowed_file, "_create_test_copy_ledgers"),
            (
                copy_ledger_file,
                "DurableCopyLedgers._validate_full_dag_with_operation_epochs_under_existing_mutex",
            ),
        },
        "_contains_all_segment_sha256_under_existing_mutex": {
            (job_file, "_TestJobRuntime._validate_operation_audit_bindings"),
            (allowed_file, "_create_test_operation_ledger"),
            (ledger_file, "DurableAuditLedger._contains_segment_sha256_under_existing_mutex"),
            (copy_operation_file, "_TestLocalCopyOperation._verify_all_ancestors"),
        },
        "_activated_revision_ids_under_existing_mutex": {
            (allowed_file, "_create_test_operation_ledger"),
            (allowed_file, "_create_test_copy_ledgers"),
            (allowed_file, "_BoundaryCore._attest_copy_ledger_read"),
            (
                copy_ledger_file,
                "DurableCopyLedgers._append_revision_is_current_under_existing_mutex",
            ),
        },
        "_seal_cross_ledger_contradiction": {
            (job_file, "_TestJobRuntime._validate_operation_audit_bindings"),
            (allowed_file, "_create_test_operation_ledger"),
            (allowed_file, "_create_test_copy_ledgers"),
        },
        "_build_recovery_observation_receipt_sha256": {
            (operation_file, "DurableOperationLedger._validate_next_transition"),
            (operation_file, "DurableOperationLedger._scan_under_mutex"),
            (allowed_file, "_reconcile_test_publish_operation"),
        },
        "_record_factory_under_existing_mutex": {
            (allowed_file, "_BoundaryCore._record_audit_factory"),
        },
        "_append_built_audit_batch_under_existing_mutex": {
            (ledger_file, "DurableAuditSink._record_factory_under_existing_mutex"),
        },
        "_contains_segment_sha256_under_existing_mutex": {
            (allowed_file, "_reconcile_test_publish_operation"),
        },
        "_issue_publish_pair_for_job": {
            (job_file, "_OperationLease.authorize_publish"),
        },
        "_reserve_publish_pair_for_job": {
            (job_file, "_OperationLease.authorize_publish"),
        },
        "_finish_reserved_pair_for_job": {
            (job_file, "_OperationLease.authorize_publish"),
            (job_file, "_OperationLease.authorize_quarantine"),
            (job_file, "_OperationLease.execute_publish_pair"),
            (job_file, "_OperationLease.execute_quarantine_pair"),
            (job_file, "_OperationLease.close"),
        },
        "_validate_reserved_pair_for_job": {
            (job_file, "_OperationLease.execute_publish_pair"),
            (job_file, "_OperationLease.execute_quarantine_pair"),
        },
        "_seal_recovery_contradiction": {
            (allowed_file, "_reconcile_test_publish_operation"),
            (allowed_file, "_reconcile_test_publish_operation.observe_once"),
            (allowed_file, "_reconcile_test_publish_operation.observe_pair"),
        },
        "_ReservedPairLease": {
            (allowed_file, "_BoundaryCore._reserve_pair"),
        },
        "_DirectoryPublishJournalPermit": {
            (writer_file, "_WindowsHandleWriter._issue_directory_publish_journal_permit"),
        },
        "DurableCopyLedgers": {
            (allowed_file, "_create_test_copy_ledgers"),
            (
                copy_ledger_file,
                "DurableCopyLedgers._preflight_new_epoch_under_existing_mutex",
            ),
        },
        "_AuthenticatedCopyAncestors": {
            (copy_ledger_file, "DurableCopyLedgers._issue_authenticated_ancestors_under_existing_mutex"),
        },
        "_TestLocalCopyOperation": {
            (allowed_file, "_create_test_copy_operation"),
        },
        "_ReferenceReadApi": {
            (external_source_file, "_create_synthetic_reference_read_policy"),
        },
        "SyntheticReferenceReadPolicy": {
            (external_source_file, "_create_synthetic_reference_read_policy"),
        },
        "_SyntheticReferenceLease": {
            (external_source_file, "SyntheticReferenceReadPolicy.open_reference"),
        },
        "_CopyExecutionPermit": {
            (external_source_file, "_issue_copy_execution_permit"),
        },
        "CopyProvenanceMaterial": {
            (copy_ledger_file, "build_copy_provenance_material"),
        },
        "build_copy_provenance_material": {
            (copy_ledger_file, "DurableCopyLedgers._validate_source_cross_reference"),
            (
                copy_ledger_file,
                "DurableCopyLedgers._authenticate_persisted_publish_plan",
            ),
            (copy_operation_file, "_TestLocalCopyOperation._copy_provenance_material"),
        },
        "publish_operation_binding": {
            (
                copy_ledger_file,
                "DurableCopyLedgers._issue_operation_absence_witness_under_existing_mutex",
            ),
            (copy_operation_file, "_TestLocalCopyOperation._publish_operation_binding"),
        },
        "_authenticated_publish_terminal_bindings_under_existing_mutex": {
            (
                copy_ledger_file,
                "DurableCopyLedgers._issue_authenticated_ancestors_under_existing_mutex",
            ),
            (
                copy_ledger_file,
                "DurableCopyLedgers._verify_external_ancestors_under_existing_mutex",
            ),
        },
        "_authenticated_publish_terminal_bindings_for_epochs_under_existing_mutex": {
            (
                copy_ledger_file,
                "DurableCopyLedgers._authenticated_publish_terminal_bindings_under_existing_mutex",
            ),
            (
                copy_ledger_file,
                "DurableCopyLedgers._validate_full_dag_with_operation_epochs_under_existing_mutex",
            ),
        },
        "_validate_full_dag_with_operation_epochs_under_existing_mutex": {
            (
                copy_ledger_file,
                "DurableCopyLedgers._preflight_new_epoch_under_existing_mutex",
            ),
            (allowed_file, "_create_test_copy_ledgers"),
        },
        "_verify_operation_absence_witness_under_existing_mutex": {
            (
                copy_ledger_file,
                "DurableCopyLedgers._authenticated_publish_terminal_bindings_for_epochs_under_existing_mutex",
            ),
        },
        "_resolve_reviewed_operation_epochs_under_existing_mutex": {
            (allowed_file, "_create_test_copy_ledgers"),
        },
        "_create_synthetic_reference_read_policy": {
            (allowed_file, "_create_test_copy_operation"),
        },
        "_copy_execution_scope_sha256": {
            (external_source_file, "_require_copy_execution_authorities"),
        },
        "_copy_execution_binding_sha256": {
            (external_source_file, "_issue_copy_execution_permit"),
            (external_source_file, "_check_copy_execution_permit"),
        },
        "_require_copy_execution_authorities": {
            (external_source_file, "_issue_copy_execution_permit"),
            (external_source_file, "_check_copy_execution_permit"),
        },
        "_issue_copy_execution_permit": {
            (copy_operation_file, "_TestLocalCopyOperation._issue_execution_permit"),
        },
        "_check_copy_execution_permit": {
            (external_source_file, "_validate_copy_execution_permit"),
            (external_source_file, "_consume_copy_execution_permit"),
        },
        "_validate_copy_execution_permit": {
            (copy_operation_file, "_TestLocalCopyOperation._validate_execution_permit"),
        },
        "_consume_copy_execution_permit": {
            (copy_operation_file, "_TestLocalCopyOperation._consume_execution_permit"),
        },
        "_append_source_under_existing_mutex": {
            (copy_operation_file, "_TestLocalCopyOperation._execute_new"),
            (
                copy_operation_file,
                "_TestLocalCopyOperation._prepare_source_for_execute",
            ),
        },
        "source_result_under_existing_mutex": {
            (copy_operation_file, "_TestLocalCopyOperation._try_replay"),
            (
                copy_operation_file,
                "_TestLocalCopyOperation._reconcile_consumed_source",
            ),
        },
        "transaction_source_result_under_existing_mutex": {
            (
                copy_operation_file,
                "_TestLocalCopyOperation._reconcile_consumed_source",
            ),
            (
                copy_operation_file,
                "_TestLocalCopyOperation._prepare_source_for_execute",
            ),
            (
                copy_operation_file,
                "_TestLocalCopyOperation._load_source_for_recovery",
            ),
            (
                copy_operation_file,
                "_TestLocalCopyOperation._validate_ledgers_for_new_operation",
            ),
        },
        "open_reference": {
            (copy_operation_file, "_TestLocalCopyOperation.execute"),
            (copy_operation_file, "_TestLocalCopyOperation.reconcile"),
        },
        "read_once": {
            (copy_operation_file, "_TestLocalCopyOperation.execute"),
            (copy_operation_file, "_TestLocalCopyOperation.reconcile"),
        },
        "operation_reference": {
            (job_file, "_TestJobRuntime.replay_committed_publish"),
            (job_file, "_TestJobRuntime.replay_committed_quarantine"),
            (job_file, "_TestJobRuntime.begin_operation"),
            (job_file, "_PublishOperationJournal._append"),
            (
                copy_operation_file,
                "_TestLocalCopyOperation._reconcile_consumed_source",
            ),
            (
                copy_operation_file,
                "_TestLocalCopyOperation._validate_recovery_publish_binding",
            ),
            (copy_operation_file, "_TestLocalCopyOperation._append_failure_fact"),
            (
                copy_operation_file,
                "_TestLocalCopyOperation._execution_operation_identity_sha256",
            ),
            (
                copy_operation_file,
                "_TestLocalCopyOperation._publish_operation_binding",
            ),
            (
                copy_operation_file,
                "_TestLocalCopyOperation._unstarted_publish_plan",
            ),
            (
                copy_operation_file,
                "_TestLocalCopyOperation._reserved_publish_plan",
            ),
            (
                copy_operation_file,
                "_TestLocalCopyOperation._issue_operation_absence_witness",
            ),
        },
        "_copy_recovery_result": {
            (
                copy_operation_file,
                "_TestLocalCopyOperation._reconcile_consumed_source",
            ),
        },
        "_validate_recovery_binding": {
            (
                copy_operation_file,
                "_TestLocalCopyOperation._reconcile_consumed_source",
            ),
        },
        "_validate_recovery_publish_binding": {
            (
                copy_operation_file,
                "_TestLocalCopyOperation._reconcile_consumed_source",
            ),
            (
                copy_operation_file,
                "_TestLocalCopyOperation._validate_authenticated_publish_result",
            ),
        },
        "_recovered_transition": {
            (
                copy_operation_file,
                "_TestLocalCopyOperation._reconcile_committed_publish",
            ),
            (
                copy_operation_file,
                "_TestLocalCopyOperation._reconcile_absent_publish",
            ),
        },
        "_source_only_recovered_abort_transition": {
            (
                copy_operation_file,
                "_TestLocalCopyOperation._reconcile_source_only_abort",
            ),
        },
        "_reconcile_source_only_abort": {
            (
                copy_operation_file,
                "_TestLocalCopyOperation._reconcile_consumed_source",
            ),
        },
        "_reconcile_committed_publish": {
            (
                copy_operation_file,
                "_TestLocalCopyOperation._reconcile_consumed_source",
            ),
        },
        "_reconcile_absent_publish": {
            (
                copy_operation_file,
                "_TestLocalCopyOperation._reconcile_consumed_source",
            ),
        },
        "_validate_source_only_recovery_binding": {
            (
                copy_operation_file,
                "_TestLocalCopyOperation._reconcile_consumed_source",
            ),
            (
                copy_operation_file,
                "_TestLocalCopyOperation._prepare_source_for_execute",
            ),
            (
                copy_operation_file,
                "_TestLocalCopyOperation._load_source_for_recovery",
            ),
        },
        "_target_evidence": {
            (copy_operation_file, "_TestLocalCopyOperation._execute_new"),
            (copy_operation_file, "_TestLocalCopyOperation._try_replay"),
            (
                copy_operation_file,
                "_TestLocalCopyOperation._reconcile_committed_publish",
            ),
        },
        "_require_target_absent_twice": {
            (
                copy_operation_file,
                "_TestLocalCopyOperation._reconcile_source_only_abort",
            ),
            (
                copy_operation_file,
                "_TestLocalCopyOperation._reconcile_absent_publish",
            ),
        },
        "verify_unchanged": {
            (copy_operation_file, "_TestLocalCopyOperation._execute_new"),
            (copy_operation_file, "_TestLocalCopyOperation._try_replay"),
            (
                copy_operation_file,
                "_TestLocalCopyOperation._reconcile_committed_publish",
            ),
            (
                copy_operation_file,
                "_TestLocalCopyOperation._reconcile_absent_publish",
            ),
            (
                copy_operation_file,
                "_TestLocalCopyOperation._reconcile_source_only_abort",
            ),
        },
        "_issue_execution_permit": {
            (copy_operation_file, "_TestLocalCopyOperation.execute"),
            (copy_operation_file, "_TestLocalCopyOperation.reconcile"),
        },
        "_validate_execution_permit": {
            (copy_operation_file, "_TestLocalCopyOperation._try_replay"),
        },
        "_consume_execution_permit": {
            (copy_operation_file, "_TestLocalCopyOperation.reconcile"),
            (copy_operation_file, "_TestLocalCopyOperation._execute_new"),
            (copy_operation_file, "_TestLocalCopyOperation._try_replay"),
        },
        "_raise_recovery_contradiction": {
            (copy_operation_file, "_TestLocalCopyOperation.reconcile"),
            (
                copy_operation_file,
                "_TestLocalCopyOperation._load_source_for_recovery",
            ),
            (
                copy_operation_file,
                "_TestLocalCopyOperation._reconcile_consumed_source",
            ),
            (
                copy_operation_file,
                "_TestLocalCopyOperation._copy_recovery_result",
            ),
            (
                copy_operation_file,
                "_TestLocalCopyOperation._reconcile_committed_publish",
            ),
            (
                copy_operation_file,
                "_TestLocalCopyOperation._reconcile_absent_publish",
            ),
            (
                copy_operation_file,
                "_TestLocalCopyOperation._reconcile_source_only_abort",
            ),
            (
                copy_operation_file,
                "_TestLocalCopyOperation._validate_recovery_binding",
            ),
            (
                copy_operation_file,
                "_TestLocalCopyOperation._validate_recovery_publish_binding",
            ),
            (
                copy_operation_file,
                "_TestLocalCopyOperation._validate_source_only_recovery_binding",
            ),
            (
                copy_operation_file,
                "_TestLocalCopyOperation._recovered_transition",
            ),
            (
                copy_operation_file,
                "_TestLocalCopyOperation._require_target_absent_twice",
            ),
            (
                copy_operation_file,
                "_TestLocalCopyOperation._authoritative_publish_relative_paths",
            ),
            (
                copy_operation_file,
                "_TestLocalCopyOperation._unstarted_publish_plan",
            ),
            (
                copy_operation_file,
                "_TestLocalCopyOperation._issue_operation_absence_witness",
            ),
        },
        "bound_audit_ancestors_under_existing_mutex": {
            (copy_ledger_file, "DurableCopyLedgers._verify_external_ancestors_under_existing_mutex"),
            (
                copy_ledger_file,
                "DurableCopyLedgers._validate_full_dag_with_operation_epochs_under_existing_mutex",
            ),
        },
        "bound_publish_terminals_under_existing_mutex": {
            (copy_ledger_file, "DurableCopyLedgers._verify_external_ancestors_under_existing_mutex"),
            (
                copy_ledger_file,
                "DurableCopyLedgers._validate_full_dag_with_operation_epochs_under_existing_mutex",
            ),
        },
        "_issue_authenticated_ancestors_under_existing_mutex": {
            (allowed_file, "_create_test_copy_ledgers"),
            (copy_operation_file, "_TestLocalCopyOperation._verify_all_ancestors"),
        },
        "_verify_external_ancestors_under_existing_mutex": {
            (allowed_file, "_create_test_copy_ledgers"),
            (copy_operation_file, "_TestLocalCopyOperation._verify_all_ancestors"),
        },
        "authenticated_segment_sha256s_under_existing_mutex": {
            (allowed_file, "_create_test_copy_ledgers"),
            (copy_ledger_file, "DurableCopyLedgers._issue_authenticated_ancestors_under_existing_mutex"),
            (copy_ledger_file, "DurableCopyLedgers._verify_external_ancestors_under_existing_mutex"),
            (
                copy_ledger_file,
                "DurableCopyLedgers._issue_operation_absence_witness_under_existing_mutex",
            ),
            (
                copy_ledger_file,
                "DurableCopyLedgers._authenticated_publish_terminal_bindings_under_existing_mutex",
            ),
            (
                copy_ledger_file,
                "DurableCopyLedgers._authenticated_publish_terminal_bindings_for_epochs_under_existing_mutex",
            ),
            (
                copy_ledger_file,
                "DurableCopyLedgers._validate_full_dag_with_operation_epochs_under_existing_mutex",
            ),
        },
        "_create_test_copy_ledgers": set(),
        "_create_test_copy_operation": set(),
        "_derive_copy_ledger_epoch_id": {
            (copy_ledger_file, "DurableCopyLedgers.__init__"),
            (copy_ledger_file, "DurableCopyLedgers.matches_run_scope"),
            (
                copy_ledger_file,
                "DurableCopyLedgers._preflight_new_epoch_under_existing_mutex",
            ),
            (allowed_file, "_BoundaryCore._attest_copy_ledger_read"),
        },
        "_derive_run_scope_hmac": {
            (copy_ledger_file, "DurableCopyLedgers.__init__"),
            (
                copy_ledger_file,
                "DurableCopyLedgers._select_persisted_revision_under_mutex",
            ),
        },
        "_require_append_revision_current": {
            (
                copy_ledger_file,
                "DurableCopyLedgers._append_source_under_existing_mutex",
            ),
        },
        "_require_transition_append_allowed": {
            (
                copy_ledger_file,
                "DurableCopyLedgers._append_transition_under_existing_mutex",
            ),
        },
        "matches_run_scope": {
            (allowed_file, "_create_test_copy_operation"),
            (copy_operation_file, "_TestLocalCopyOperation.__init__"),
        },
        "transaction_binding": {
            (copy_operation_file, "_TestLocalCopyOperation._stable_bindings"),
        },
        "copy_object_binding": {
            (copy_operation_file, "_TestLocalCopyOperation._stable_bindings"),
        },
        "target_locator": {
            (copy_operation_file, "_TestLocalCopyOperation._copy_target_locator"),
            (copy_ledger_file, "DurableCopyLedgers.publish_operation_binding"),
            (
                copy_ledger_file,
                "DurableCopyLedgers._authenticated_publish_terminal_bindings_for_epochs_under_existing_mutex",
            ),
        },
        "_RestrictedRecoveryLocatorRecord": {
            (allowed_file, "_BoundaryCore.issue_restricted_recovery_locator"),
        },
        "_RestrictedRecoveryLocatorCapability": {
            (allowed_file, "_BoundaryCore.issue_restricted_recovery_locator"),
        },
        "issue_restricted_recovery_locator": {
            (allowed_file, "_TestWorkspaceBoundary._issue_restricted_recovery_locator"),
            (allowed_file, "_BoundaryCore.issue_restricted_copy_recovery_locator"),
        },
        "consume_restricted_recovery_locator": {
            (allowed_file, "_TestWorkspaceBoundary._consume_restricted_recovery_locator"),
            (allowed_file, "_BoundaryCore.consume_restricted_copy_recovery_locator"),
        },
        "issue_restricted_copy_recovery_locator": {
            (
                allowed_file,
                "_TestWorkspaceBoundary._issue_restricted_copy_recovery_locator",
            ),
        },
        "consume_restricted_copy_recovery_locator": {
            (
                allowed_file,
                "_TestWorkspaceBoundary._consume_restricted_copy_recovery_locator",
            ),
        },
        "_issue_restricted_recovery_locator": set(),
        "_consume_restricted_recovery_locator": {
            (allowed_file, "_reconcile_test_publish_operation"),
        },
        "_issue_restricted_copy_recovery_locator": set(),
        "_consume_restricted_copy_recovery_locator": {
            (
                copy_operation_file,
                "_TestLocalCopyOperation.reconcile",
            ),
        },
        "_restricted_copy_recovery_binding_id": {
            (allowed_file, "_BoundaryCore.issue_restricted_copy_recovery_locator"),
            (allowed_file, "_BoundaryCore.consume_restricted_copy_recovery_locator"),
            (allowed_file, "_BoundaryCore.consume_restricted_recovery_locator"),
        },
        "_derive_restricted_recovery_paths": {
            (allowed_file, "_BoundaryCore.issue_restricted_recovery_locator"),
            (allowed_file, "_BoundaryCore.consume_restricted_recovery_locator"),
        },
        "_restricted_recovery_locator_binding": {
            (allowed_file, "_BoundaryCore.issue_restricted_recovery_locator"),
            (allowed_file, "_BoundaryCore.consume_restricted_recovery_locator"),
        },
        "_restricted_recovery_owner_thread_object_binding": {
            (allowed_file, "_BoundaryCore.issue_restricted_recovery_locator"),
            (allowed_file, "_BoundaryCore.consume_restricted_recovery_locator"),
            (allowed_file, "_BoundaryCore._assert_invariants"),
        },
        "_restricted_recovery_capability_authenticator": {
            (allowed_file, "_BoundaryCore.issue_restricted_recovery_locator"),
            (allowed_file, "_BoundaryCore.consume_restricted_recovery_locator"),
        },
        "_revoke_restricted_recovery_records": {
            (allowed_file, "_BoundaryCore.release_test_context"),
            (allowed_file, "_BoundaryCore.finish_test_job_context"),
        },
    }
    restricted_symbol_scopes: dict[str, set[tuple[str, str]]] = {
        "_PAIR_RESERVATION_CONSTRUCTOR": {
            (allowed_file, "<module>"),
            (allowed_file, "_ReservedPairLease.__init__"),
            (allowed_file, "_BoundaryCore._reserve_pair"),
        },
        "_DIRECTORY_PUBLISH_PERMIT_CONSTRUCTOR": {
            (writer_file, "<module>"),
            (writer_file, "_DirectoryPublishJournalPermit.__init__"),
            (writer_file, "_WindowsHandleWriter._issue_directory_publish_journal_permit"),
        },
        "_IDENTITY_MATERIAL_CONSTRUCTOR": {
            (writer_file, "<module>"),
            (writer_file, "HandleObjectIdentityMaterial.__init__"),
            (writer_file, "HandleTreeIdentityMaterial.__init__"),
            (writer_file, "_WindowsHandleWriter._read_flat_directory_impl"),
            (writer_file, "_WindowsHandleWriter._build_tree_snapshot"),
            (writer_file, "_WindowsHandleWriter._identity_material"),
        },
        "_COPY_LEDGERS_CONSTRUCTOR": {
            (copy_ledger_file, "<module>"),
            (copy_ledger_file, "DurableCopyLedgers.__init__"),
            (allowed_file, "_create_test_copy_ledgers"),
        },
        "_AUTHENTICATED_COPY_ANCESTORS_CONSTRUCTOR": {
            (copy_ledger_file, "<module>"),
            (copy_ledger_file, "_AuthenticatedCopyAncestors.__init__"),
            (copy_ledger_file, "DurableCopyLedgers._issue_authenticated_ancestors_under_existing_mutex"),
        },
        "_COPY_OPERATION_CONSTRUCTOR": {
            (copy_operation_file, "<module>"),
            (copy_operation_file, "_TestLocalCopyOperation.__init__"),
            (allowed_file, "_create_test_copy_operation"),
        },
        "_READ_API_CONSTRUCTOR": {
            (external_source_file, "<module>"),
            (external_source_file, "_ReferenceReadApi.__init__"),
            (external_source_file, "_create_synthetic_reference_read_policy"),
        },
        "_POLICY_CONSTRUCTOR": {
            (external_source_file, "<module>"),
            (external_source_file, "SyntheticReferenceReadPolicy.__init__"),
            (external_source_file, "_create_synthetic_reference_read_policy"),
        },
        "_LEASE_CONSTRUCTOR": {
            (external_source_file, "<module>"),
            (external_source_file, "_SyntheticReferenceLease.__init__"),
            (external_source_file, "SyntheticReferenceReadPolicy.open_reference"),
        },
        "_COPY_EXECUTION_PERMIT_CONSTRUCTOR": {
            (external_source_file, "<module>"),
            (external_source_file, "_CopyExecutionPermit.__init__"),
            (external_source_file, "_issue_copy_execution_permit"),
        },
        "_RECOVERY_LOCATOR_CONSTRUCTOR": {
            (allowed_file, "<module>"),
            (allowed_file, "_RestrictedRecoveryLocatorCapability.__init__"),
            (allowed_file, "_RestrictedRecoveryLocatorCapability._read"),
            (allowed_file, "_BoundaryCore.issue_restricted_recovery_locator"),
            (allowed_file, "_BoundaryCore.consume_restricted_recovery_locator"),
        },
    }
    restricted_recovery_registry_attributes = frozenset(
        {
            "__restricted_recovery_records",
            "_BoundaryCore__restricted_recovery_records",
            "_restricted_recovery_records",
            "__restricted_recovery_registry",
            "_BoundaryCore__restricted_recovery_registry",
        }
    )
    restricted_recovery_capability_attributes = frozenset(
        {
            "_read",
            "__locator_id",
            "_RestrictedRecoveryLocatorCapability__locator_id",
            "_locator_id",
            "locator_id",
            "__authenticator",
            "_RestrictedRecoveryLocatorCapability__authenticator",
            "_authenticator",
            "authenticator",
            "_token",
            "token",
            "_opaque_token",
            "opaque_token",
            "_binding",
            "binding",
            "_binding_sha256",
            "binding_sha256",
            "__dict__",
            "owner_thread",
            "lifecycle",
            "consumed",
            "source_relative_path",
            "target_relative_path",
        }
    )
    restricted_recovery_record_attributes = frozenset(
        {
            "locator_id",
            "core_instance_id",
            "purpose",
            "context",
            "context_digest",
            "context_ticket_id",
            "transaction_id",
            "owner_thread",
            "owner_thread_object",
            "owner_thread_object_binding_sha256",
            "source_relative_path",
            "target_relative_path",
            "policy_version",
            "policy_digest",
            "binding_sha256",
            "capability_authenticator",
            "__dict__",
            "lifecycle",
            "consumed",
        }
    )
    restricted_recovery_registry_scopes = {
        (allowed_file, "_BoundaryCore.__init__"),
        (allowed_file, "_BoundaryCore.issue_restricted_recovery_locator"),
        (allowed_file, "_BoundaryCore.consume_restricted_recovery_locator"),
        (allowed_file, "_BoundaryCore._revoke_restricted_recovery_records"),
        (allowed_file, "_BoundaryCore._assert_invariants"),
    }
    restricted_recovery_record_scopes = {
        (allowed_file, "_RestrictedRecoveryLocatorRecord.__repr__"),
        (allowed_file, "_BoundaryCore.consume_restricted_recovery_locator"),
        (allowed_file, "_BoundaryCore._revoke_restricted_recovery_records"),
        (allowed_file, "_BoundaryCore._assert_invariants"),
    }
    restricted_recovery_capability_scopes = {
        (allowed_file, "_RestrictedRecoveryLocatorCapability.__init__"),
        (allowed_file, "_RestrictedRecoveryLocatorCapability._read"),
        (allowed_file, "_BoundaryCore.consume_restricted_recovery_locator"),
    }
    sensitive_authority_attributes = {
        "_api",
        "_audit_ledger",
        "_audit_segment_sha256s",
        "_copy_chain",
        "_copy_ledgers",
        "_digest_key",
        "_key_store",
        "_ledger",
        "_ledgers",
        "_locator_key",
        "_operation_ledger",
        "_policy",
        "_publish_terminal_binding_sha256s",
        "_copy_cross_reference_sha256",
        "_publish_segment_sha256s",
        "_revision",
        "_run_scope_id",
        "_run_scope_hmac_sha256",
        "_known_revisions",
        "_requested_revision_id",
        "_append_enabled",
        "_runtime",
        "_source_chain",
        "_source_policy",
        "_storage",
        "_workspace_root",
        "_writer",
        "auth_key",
        "__frame",
        "__rows",
        "_HandleObjectIdentityMaterial__frame",
        "identity_material",
        "root_identity_material",
        "tree_identity_material",
        "storage_epoch_id",
    }
    authority_access_scope_prefixes: dict[str, tuple[str, ...]] = {
        writer_file: (
            "HandleObjectIdentityMaterial.",
            "HandleTreeIdentityMaterial.",
            "RuntimeMutexLease.",
            "DirectoryHandleLease.",
            "_ImmutableFileLease.",
            "_ObservedTreeLease.",
            "_DirectoryPublishJournalPermit.",
            "_WindowsHandleWriter.",
        ),
        ledger_file: (
            "AuditKeyRevisionStore.",
            "DurableAuditLedger.",
            "DurableAuditSink.",
        ),
        operation_file: ("DurableOperationLedger.",),
        job_file: (
            "_TestJobRuntime.",
            "_OperationLease.",
            "_JobStagingLease.",
            "_ObservedJobTreeLease.",
            "_PublishOperationJournal.",
        ),
        copy_ledger_file: (
            "_CopyChain.",
            "_AuthenticatedCopyAncestors.",
            "DurableCopyLedgers.",
        ),
        copy_operation_file: ("_TestLocalCopyOperation.",),
        external_source_file: (
            "_ReferenceReadApi.",
            "SyntheticReferenceReadPolicy.",
            "_SyntheticReferenceLease.",
            "_CopyExecutionPermit.",
        ),
    }
    authority_access_exact_scopes: set[tuple[str, str]] = {
        (external_source_file, "_copy_execution_scope_sha256"),
        (external_source_file, "_copy_execution_binding_sha256"),
        (external_source_file, "_require_copy_execution_authorities"),
        (external_source_file, "_issue_copy_execution_permit"),
        (external_source_file, "_check_copy_execution_permit"),
        (external_source_file, "_validate_copy_execution_permit"),
        (external_source_file, "_consume_copy_execution_permit"),
        (external_source_file, "_create_synthetic_reference_read_policy"),
        (copy_ledger_file, "_derive_copy_ledger_epoch_id"),
        (copy_ledger_file, "_copy_epoch_pair_presence.present"),
        (operation_file, "_operation_epoch_catalog"),
        (
            operation_file,
            "_resolve_reviewed_operation_epochs_under_existing_mutex",
        ),
        (allowed_file, "_AuditAuthority.__post_init__"),
        (allowed_file, "_create_test_job_runtime"),
        (allowed_file, "_create_test_copy_ledgers"),
        (allowed_file, "_create_test_copy_operation"),
        (allowed_file, "_reconcile_test_publish_operation"),
        (allowed_file, "_reconcile_test_publish_operation.observe_once"),
        (allowed_file, "_BoundaryCore.issue_restricted_recovery_locator"),
        (allowed_file, "_BoundaryCore.consume_restricted_recovery_locator"),
        (allowed_file, "_BoundaryCore.issue_restricted_copy_recovery_locator"),
        (allowed_file, "_BoundaryCore.consume_restricted_copy_recovery_locator"),
        (allowed_file, "_BoundaryCore._restricted_copy_recovery_binding_id"),
        (allowed_file, "_TestWorkspaceBoundary._issue_restricted_recovery_locator"),
        (allowed_file, "_TestWorkspaceBoundary._consume_restricted_recovery_locator"),
        (allowed_file, "_TestWorkspaceBoundary._issue_restricted_copy_recovery_locator"),
        (allowed_file, "_TestWorkspaceBoundary._consume_restricted_copy_recovery_locator"),
        (job_file, "_ObservedQuarantineTreeLease.revalidate"),
        (job_file, "_RetainedRestoreSourceLease.operation_tree_evidence"),
    }

    def authority_attribute_access_allowed(enclosing: str) -> bool:
        if (module.file, enclosing) in authority_access_exact_scopes:
            return True
        return enclosing.startswith(
            authority_access_scope_prefixes.get(module.file, ())
        )

    def enclosing_function_node(node: ast.AST) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
        current = module.parents.get(node)
        while current is not None:
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return current
            current = module.parents.get(current)
        return None

    def annotation_restricted_recovery_kind(annotation: ast.AST | None) -> str | None:
        if annotation is None:
            return None
        leaves = {
            (
                candidate.id
                if isinstance(candidate, ast.Name)
                else candidate.attr
            )
            for candidate in ast.walk(annotation)
            if isinstance(candidate, (ast.Name, ast.Attribute))
        }
        if "_RestrictedRecoveryLocatorCapability" in leaves:
            return "capability"
        if "_RestrictedRecoveryLocatorRecord" in leaves:
            return "record"
        return "other"

    def annotated_restricted_recovery_kind(name: str, node: ast.AST) -> str | None:
        function = enclosing_function_node(node)
        if function is None:
            return None
        arguments = (
            *function.args.posonlyargs,
            *function.args.args,
            *function.args.kwonlyargs,
        )
        for argument in arguments:
            if argument.arg == name:
                return annotation_restricted_recovery_kind(argument.annotation)
        for argument in (function.args.vararg, function.args.kwarg):
            if argument is not None and argument.arg == name:
                return annotation_restricted_recovery_kind(argument.annotation)
        return None

    def restricted_recovery_receiver_kind(
        receiver: ast.AST,
        enclosing: str,
    ) -> str | None:
        resolved, _ = _resolve_callee(receiver, aliases_for(receiver))
        lowered = resolved.lower()
        if "restrictedrecoverylocatorcapability" in lowered or (
            "restricted_recovery" in lowered and "capability" in lowered
        ):
            return "capability"
        if "restrictedrecoverylocatorrecord" in lowered or (
            "restricted_recovery" in lowered and "record" in lowered
        ):
            return "record"
        terminal = ""
        if isinstance(receiver, ast.Name):
            terminal = receiver.id
            annotated = annotated_restricted_recovery_kind(terminal, receiver)
            if annotated is not None:
                return annotated
        elif isinstance(receiver, ast.Attribute):
            terminal = receiver.attr
        lowered_terminal = terminal.lower()
        if lowered_terminal == "self":
            if enclosing.startswith("_RestrictedRecoveryLocatorCapability."):
                return "capability"
            if enclosing.startswith("_RestrictedRecoveryLocatorRecord."):
                return "record"
        if "capability" in lowered_terminal and (
            "recovery" in lowered_terminal
            or "locator" in lowered_terminal
            or lowered_terminal == "capability"
        ):
            return "capability"
        if "record" in lowered_terminal and (
            "recovery" in lowered_terminal or "locator" in lowered_terminal
        ):
            return "record"
        if lowered_terminal in {"record", "removed"} and (
            module.file != allowed_file
            or (module.file, enclosing) in restricted_recovery_record_scopes
        ):
            return "record"
        return None

    def restricted_recovery_registry_access_allowed(
        node: ast.Attribute,
        enclosing: str,
    ) -> bool:
        scope = (module.file, enclosing)
        if scope in restricted_recovery_registry_scopes:
            if scope == (allowed_file, "_BoundaryCore.__init__"):
                return isinstance(node.ctx, ast.Store)
            return True
        if scope != (allowed_file, "_BoundaryCore.diagnostic_registry_counts"):
            return False
        parent = module.parents.get(node)
        if not isinstance(parent, ast.Call) or not parent.args or parent.args[0] is not node:
            return False
        callee, _ = _resolve_callee(parent.func, aliases_for(parent))
        return callee in {"len", "builtins.len"} and len(parent.args) == 1

    def restricted_recovery_capability_access_allowed(
        attribute: str,
        enclosing: str,
    ) -> bool:
        allowed_by_scope = {
            (
                allowed_file,
                "_RestrictedRecoveryLocatorCapability.__init__",
            ): {
                "__locator_id",
                "__authenticator",
            },
            (
                allowed_file,
                "_RestrictedRecoveryLocatorCapability._read",
            ): {
                "__locator_id",
                "__authenticator",
            },
            (
                allowed_file,
                "_BoundaryCore.consume_restricted_recovery_locator",
            ): {"_read"},
        }
        return attribute in allowed_by_scope.get((module.file, enclosing), set())

    def restricted_recovery_record_access_allowed(
        node: ast.Attribute,
        enclosing: str,
    ) -> bool:
        attribute = node.attr
        allowed_by_scope = {
            (
                allowed_file,
                "_RestrictedRecoveryLocatorRecord.__repr__",
            ): {"lifecycle"},
            (
                allowed_file,
                "_BoundaryCore.consume_restricted_recovery_locator",
            ): set(restricted_recovery_record_attributes) - {"consumed"},
            (
                allowed_file,
                "_BoundaryCore._revoke_restricted_recovery_records",
            ): {"context_ticket_id"},
            (
                allowed_file,
                "_BoundaryCore._assert_invariants",
            ): {
                "locator_id",
                "lifecycle",
                "context_ticket_id",
                "context",
                "owner_thread",
                "owner_thread_object",
                "owner_thread_object_binding_sha256",
                "source_relative_path",
                "target_relative_path",
            },
        }
        allowed = attribute in allowed_by_scope.get((module.file, enclosing), set())
        if (
            allowed
            and enclosing == "_BoundaryCore.consume_restricted_recovery_locator"
            and attribute in {"source_relative_path", "target_relative_path"}
        ):
            expected_name = (
                "expected_source"
                if attribute == "source_relative_path"
                else "expected_target"
            )
            parent = module.parents.get(node)
            type_compare = (
                module.parents.get(parent)
                if isinstance(parent, ast.Call)
                else None
            )
            type_other: ast.AST | None = None
            if (
                isinstance(type_compare, ast.Compare)
                and len(type_compare.ops) == 1
                and isinstance(type_compare.ops[0], ast.Is)
                and len(type_compare.comparators) == 1
            ):
                if type_compare.left is parent:
                    type_other = type_compare.comparators[0]
                elif type_compare.comparators[0] is parent:
                    type_other = type_compare.left
            exact_type_check = (
                isinstance(parent, ast.Call)
                and isinstance(parent.func, ast.Name)
                and parent.func.id == "type"
                and len(parent.args) == 1
                and parent.args[0] is node
                and not parent.keywords
                and isinstance(type_other, ast.Call)
                and isinstance(type_other.func, ast.Name)
                and type_other.func.id == "type"
                and len(type_other.args) == 1
                and isinstance(type_other.args[0], ast.Name)
                and type_other.args[0].id == expected_name
                and not type_other.keywords
            )
            canonical_call = (
                module.parents.get(parent)
                if isinstance(parent, ast.Attribute)
                else None
            )
            canonical_compare_node = (
                module.parents.get(canonical_call)
                if isinstance(canonical_call, ast.Call)
                else None
            )
            canonical_other: ast.AST | None = None
            if (
                isinstance(canonical_compare_node, ast.Compare)
                and len(canonical_compare_node.ops) == 1
                and isinstance(canonical_compare_node.ops[0], ast.Eq)
                and len(canonical_compare_node.comparators) == 1
            ):
                if canonical_compare_node.left is canonical_call:
                    canonical_other = canonical_compare_node.comparators[0]
                elif canonical_compare_node.comparators[0] is canonical_call:
                    canonical_other = canonical_compare_node.left
            canonical_compare = (
                isinstance(parent, ast.Attribute)
                and parent.value is node
                and parent.attr == "as_posix"
                and isinstance(canonical_call, ast.Call)
                and canonical_call.func is parent
                and not canonical_call.args
                and not canonical_call.keywords
                and isinstance(canonical_other, ast.Call)
                and isinstance(canonical_other.func, ast.Attribute)
                and isinstance(canonical_other.func.value, ast.Name)
                and canonical_other.func.value.id == expected_name
                and canonical_other.func.attr == "as_posix"
                and not canonical_other.args
                and not canonical_other.keywords
            )
            quarantine_name = parent
            quarantine_choice = (
                module.parents.get(quarantine_name)
                if isinstance(quarantine_name, ast.Attribute)
                else None
            )
            quarantine_assignment = (
                module.parents.get(quarantine_choice)
                if isinstance(quarantine_choice, ast.IfExp)
                else None
            )
            quarantine_test = (
                quarantine_choice.test
                if isinstance(quarantine_choice, ast.IfExp)
                else None
            )
            exact_quarantine_pair_id_derivation = (
                attribute == "target_relative_path"
                and isinstance(node.value, ast.Name)
                and node.value.id == "record"
                and isinstance(quarantine_name, ast.Attribute)
                and quarantine_name.value is node
                and quarantine_name.attr == "name"
                and isinstance(quarantine_choice, ast.IfExp)
                and quarantine_choice.body is quarantine_name
                and isinstance(quarantine_choice.orelse, ast.Constant)
                and quarantine_choice.orelse.value is None
                and isinstance(quarantine_test, ast.Compare)
                and isinstance(quarantine_test.left, ast.Attribute)
                and quarantine_test.left.attr == "purpose"
                and isinstance(quarantine_test.left.value, ast.Attribute)
                and quarantine_test.left.value.attr == "context"
                and isinstance(quarantine_test.left.value.value, ast.Name)
                and quarantine_test.left.value.value.id == "record"
                and len(quarantine_test.ops) == 1
                and isinstance(quarantine_test.ops[0], ast.Is)
                and len(quarantine_test.comparators) == 1
                and isinstance(quarantine_test.comparators[0], ast.Attribute)
                and isinstance(quarantine_test.comparators[0].value, ast.Name)
                and quarantine_test.comparators[0].value.id == "Purpose"
                and quarantine_test.comparators[0].attr == "QUARANTINE"
                and (
                    (
                        isinstance(quarantine_assignment, ast.Assign)
                        and len(quarantine_assignment.targets) == 1
                        and isinstance(quarantine_assignment.targets[0], ast.Name)
                        and quarantine_assignment.targets[0].id
                        == "quarantine_pair_id"
                    )
                    or (
                        isinstance(quarantine_assignment, ast.AnnAssign)
                        and isinstance(quarantine_assignment.target, ast.Name)
                        and quarantine_assignment.target.id == "quarantine_pair_id"
                    )
                )
            )
            return (
                exact_type_check
                or canonical_compare
                or exact_quarantine_pair_id_derivation
            )
        return allowed

    def assigned_local_name(call: ast.Call) -> str | None:
        parent = module.parents.get(call)
        if isinstance(parent, ast.Assign) and parent.value is call:
            if len(parent.targets) == 1 and isinstance(parent.targets[0], ast.Name):
                return parent.targets[0].id
        if (
            isinstance(parent, ast.AnnAssign)
            and parent.value is call
            and isinstance(parent.target, ast.Name)
        ):
            return parent.target.id
        return None

    def call_receiver_shape(call: ast.Call) -> str | None:
        if not isinstance(call.func, ast.Attribute):
            return None
        return ast.dump(call.func.value, annotate_fields=True, include_attributes=False)

    def call_leaf(call: ast.Call) -> str:
        resolved, _ = _resolve_callee(call.func, aliases_for(call))
        return resolved.rsplit(".", 1)[-1]

    def same_expression(left: ast.expr, right: ast.expr) -> bool:
        return ast.dump(
            left,
            annotate_fields=True,
            include_attributes=False,
        ) == ast.dump(
            right,
            annotate_fields=True,
            include_attributes=False,
        )

    def assigns_name(node: ast.AST, name: str) -> bool:
        targets: tuple[ast.expr, ...] = ()
        if isinstance(node, ast.Assign):
            targets = tuple(node.targets)
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
            targets = (node.target,)
        return any(
            isinstance(item, ast.Name) and item.id == name
            for target in targets
            for item in ast.walk(target)
        )

    def ancestor_issue_is_well_formed(call: ast.Call) -> bool:
        if (
            call_leaf(call)
            != "_issue_authenticated_ancestors_under_existing_mutex"
            or len(call.args) != 3
            or call.keywords
            or assigned_local_name(call) is None
            or call_receiver_shape(call) is None
        ):
            return False
        # The issuer accepts exact ledger authorities, never caller-supplied
        # digest inventories or other literal stand-ins.
        return not any(
            isinstance(argument, (ast.Tuple, ast.List, ast.Set, ast.Dict, ast.Constant))
            for argument in call.args[1:]
        )

    def exact_issue_for_verify(call: ast.Call) -> ast.Call | None:
        if (
            call_leaf(call)
            != "_verify_external_ancestors_under_existing_mutex"
            or len(call.args) != 2
            or call.keywords
            or not isinstance(call.args[1], ast.Name)
            or call_receiver_shape(call) is None
        ):
            return None
        function = enclosing_function_node(call)
        if function is None:
            return None
        capability_name = call.args[1].id
        candidates: list[ast.Call] = []
        for item in ast.walk(function):
            if (
                not isinstance(item, ast.Call)
                or enclosing_function_node(item) is not function
                or not ancestor_issue_is_well_formed(item)
                or assigned_local_name(item) != capability_name
                or item.lineno >= call.lineno
                or call_receiver_shape(item) != call_receiver_shape(call)
                or not same_expression(item.args[0], call.args[0])
            ):
                continue
            candidates.append(item)
        if len(candidates) != 1:
            return None
        issue = candidates[0]
        issue_assignment = module.parents.get(issue)
        for item in ast.walk(function):
            if (
                item is issue_assignment
                or enclosing_function_node(item) is not function
                or not assigns_name(item, capability_name)
            ):
                continue
            item_line = getattr(item, "lineno", 0)
            if issue.lineno < item_line <= call.lineno:
                return None
        matching_verifies = [
            item
            for item in ast.walk(function)
            if isinstance(item, ast.Call)
            and enclosing_function_node(item) is function
            and call_leaf(item)
            == "_verify_external_ancestors_under_existing_mutex"
            and len(item.args) == 2
            and not item.keywords
            and isinstance(item.args[1], ast.Name)
            and item.args[1].id == capability_name
        ]
        return issue if matching_verifies == [call] else None

    def ancestor_issue_has_exact_verify(call: ast.Call) -> bool:
        if not ancestor_issue_is_well_formed(call):
            return False
        function = enclosing_function_node(call)
        capability_name = assigned_local_name(call)
        if function is None or capability_name is None:
            return False
        verifies = [
            item
            for item in ast.walk(function)
            if isinstance(item, ast.Call)
            and enclosing_function_node(item) is function
            and call_leaf(item)
            == "_verify_external_ancestors_under_existing_mutex"
            and len(item.args) == 2
            and not item.keywords
            and isinstance(item.args[1], ast.Name)
            and item.args[1].id == capability_name
        ]
        return len(verifies) == 1 and exact_issue_for_verify(verifies[0]) is call

    for node in ast.walk(module.tree):
        node_aliases = aliases_for(node)
        if isinstance(node, ast.ImportFrom):
            base = _resolve_import_module(module.module, node.module, node.level)
            for alias in node.names:
                job_kernel_import = (
                    module.file == job_file
                    and base
                    in {
                        "app.safety.segment_ledger",
                        "app.safety.windows_handle_writer",
                        "app.safety.operation_ledger",
                    }
                    and alias.name
                    in {
                        "DurableAuditLedger",
                        "DurableOperationLedger",
                        "LedgerHead",
                        "DirectoryHandleLease",
                        "HandleWriterCode",
                        "HandleWriterError",
                        "TreeEntryKind",
                        "TreeScanBudget",
                        "_ObservedTreeLease",
                        "_ObservedHandle",
                        "_TreeLogicalRow",
                        "_TreeSnapshot",
                        "_ImmutableFileLease",
                        "_WindowsApi",
                        "_WindowsHandleWriter",
                        "_DirectoryPublishJournalPermit",
                    }
                )
                operation_kernel_import = (
                    module.file == operation_file
                    and base == "app.safety.windows_handle_writer"
                    and alias.name
                    in {
                        "HandleObjectIdentityMaterial",
                        "HandleTreeIdentityMaterial",
                        "_WindowsHandleWriter",
                    }
                )
                copy_ledger_kernel_import = (
                    module.file == copy_ledger_file
                    and alias.name
                    in {
                        "app.safety.operation_ledger": {
                            "DurableOperationLedger",
                        },
                        "app.safety.segment_ledger": {
                            "DurableAuditLedger",
                        },
                        "app.safety.windows_handle_writer": {
                            "_WindowsHandleWriter",
                        },
                    }.get(base, set())
                )
                copy_operation_kernel_import = (
                    module.file == copy_operation_file
                    and alias.name
                    in {
                        "app.safety.copy_ledger": {
                            "COPY_PROVENANCE_FILE_NAME",
                            "CopyProvenanceMaterial",
                            "DurableCopyLedgers",
                            "build_copy_provenance_material",
                        },
                        "app.safety.external_source": {
                            "SyntheticReferenceReadPolicy",
                            "_CopyExecutionPermit",
                            "_SyntheticReferenceLease",
                            "_consume_copy_execution_permit",
                            "_issue_copy_execution_permit",
                            "_validate_copy_execution_permit",
                        },
                        "app.safety.job_operation": {
                            "_OperationLease",
                            "_TestJobRuntime",
                            "_receipt_from_authenticated_terminal",
                        },
                        "app.safety.operation_ledger": {
                            "DurableOperationLedger",
                        },
                    }.get(base, set())
                )
                if (
                    module.file != allowed_file
                    and not job_kernel_import
                    and not operation_kernel_import
                    and not copy_ledger_kernel_import
                    and not copy_operation_kernel_import
                    and base.startswith(safety_module_prefixes)
                    and (
                        alias.name == "*"
                        or alias.name.startswith("_")
                        or alias.name in forbidden_private_imports
                        or alias.name in forbidden_constructors
                    )
                ):
                    findings.append(
                        (module.file, node.lineno, f"private import {alias.name}")
                    )
        if isinstance(node, (ast.Name, ast.Attribute)):
            resolved, _ = _resolve_callee(node, node_aliases)
            leaf = resolved.rsplit(".", 1)[-1]
            allowed_symbol_scopes = restricted_symbol_scopes.get(leaf)
            if allowed_symbol_scopes is not None:
                enclosing = _enclosing_function_qualname(node, module.parents)
                if (module.file, enclosing) not in allowed_symbol_scopes:
                    findings.append(
                        (
                            module.file,
                            getattr(node, "lineno", 0),
                            f"restricted private symbol {leaf} outside exact scope {enclosing}",
                        )
                    )
            if (
                leaf in forbidden_constructors
                and module.file not in symbol_definition_files.get(leaf, {allowed_file})
            ):
                findings.append(
                    (module.file, getattr(node, "lineno", 0), f"forbidden symbol reference {resolved}")
                )
        if isinstance(node, ast.Attribute):
            enclosing = _enclosing_function_qualname(node, module.parents)
            resolved, _ = _resolve_callee(node, node_aliases)
            receiver_kind = restricted_recovery_receiver_kind(node.value, enclosing)
            restricted_recovery_access = False
            if node.attr in restricted_recovery_registry_attributes:
                restricted_recovery_access = not restricted_recovery_registry_access_allowed(
                    node,
                    enclosing,
                )
            elif receiver_kind == "capability" and (
                node.attr in restricted_recovery_capability_attributes
                or node.attr in restricted_recovery_record_attributes
            ):
                restricted_recovery_access = (
                    not restricted_recovery_capability_access_allowed(
                        node.attr,
                        enclosing,
                    )
                )
            elif (
                receiver_kind == "record"
                and node.attr in restricted_recovery_record_attributes
            ):
                restricted_recovery_access = not restricted_recovery_record_access_allowed(
                    node,
                    enclosing,
                )
            if restricted_recovery_access:
                action = (
                    "attribute access"
                    if isinstance(node.ctx, ast.Load)
                    else "authority assignment"
                )
                findings.append(
                    (
                        module.file,
                        node.lineno,
                        f"restricted recovery {action} {resolved}",
                    )
                )
        if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load):
            parent = module.parents.get(node)
            if not (isinstance(parent, ast.Attribute) and parent.value is node):
                resolved, _ = _resolve_callee(node, node_aliases)
                sensitive_parts = sensitive_authority_attributes.intersection(
                    resolved.split(".")
                )
                if sensitive_parts:
                    enclosing = _enclosing_function_qualname(node, module.parents)
                    if not authority_attribute_access_allowed(enclosing):
                        findings.append(
                            (
                                module.file,
                                node.lineno,
                                f"sensitive authority attribute access {resolved}",
                            )
                        )
        if isinstance(node, ast.ClassDef):
            for base in node.bases:
                resolved, _ = _resolve_callee(base, node_aliases)
                leaf = resolved.rsplit(".", 1)[-1]
                if (
                    leaf in forbidden_constructors
                    and module.file
                    not in symbol_definition_files.get(leaf, {allowed_file})
                ):
                    findings.append(
                        (module.file, node.lineno, f"subclass {resolved}")
                    )
        if isinstance(node, ast.Call):
            callee, _ = _resolve_callee(node.func, node_aliases)
            leaf = callee.rsplit(".", 1)[-1]
            if (
                leaf == "_issue_authenticated_ancestors_under_existing_mutex"
                and not ancestor_issue_has_exact_verify(node)
            ):
                findings.append(
                    (
                        module.file,
                        node.lineno,
                        "authenticated ancestor issue must feed one exact local verify",
                    )
                )
            if (
                leaf == "_verify_external_ancestors_under_existing_mutex"
                and exact_issue_for_verify(node) is None
            ):
                findings.append(
                    (
                        module.file,
                        node.lineno,
                        "authenticated ancestor verify requires its exact one-shot issue result",
                    )
                )
            copy_ledger_seal_call = leaf == "_seal" and (
                "._ledgers._seal" in callee
                or "DurableCopyLedgers" in callee
                or callee.startswith("copy_ledgers._seal")
            )
            if copy_ledger_seal_call and (
                module.file,
                _enclosing_function_qualname(node, module.parents),
            ) not in {
                (
                    copy_operation_file,
                    "_TestLocalCopyOperation._seal_cross_reference_failure",
                ),
                (
                    copy_operation_file,
                    "_TestLocalCopyOperation._raise_recovery_contradiction",
                ),
                (allowed_file, "_create_test_copy_ledgers"),
            }:
                findings.append(
                    (module.file, node.lineno, "restricted private call _seal")
                )
            allowed_private_callers = restricted_private_calls.get(leaf)
            if (
                allowed_private_callers is not None
                and (
                    module.file,
                    _enclosing_function_qualname(node, module.parents),
                )
                not in allowed_private_callers
            ):
                findings.append(
                    (module.file, node.lineno, f"restricted private call {leaf}")
                )
            if (
                leaf in forbidden_constructors
                and module.file
                not in symbol_definition_files.get(leaf, {allowed_file})
            ):
                findings.append((module.file, node.lineno, f"constructor {callee}"))
            if leaf == "_NamespacePolicy__authorize":
                enclosing = _enclosing_function_qualname(node, module.parents)
                if not (
                    module.file == allowed_file
                    and enclosing
                    == "_BoundaryNamespacePolicy._authorize_pair_member"
                ):
                    findings.append(
                        (module.file, node.lineno, f"private pair policy call {leaf}")
                    )
            elif leaf in {
                "_authorize_paired",
                "_issue_pair_claim",
                "_authorize_pair_for_boundary",
                "_authorize_pair",
                "_install_boundary_pair_seal",
            } and module.file != allowed_file:
                findings.append((module.file, node.lineno, f"private pair policy call {leaf}"))
            if leaf in {"getattr", "setattr", "delattr"} and len(node.args) >= 2:
                attribute = _constant_text(node.args[1])
                enclosing = _enclosing_function_qualname(node, module.parents)
                receiver_kind = restricted_recovery_receiver_kind(
                    node.args[0],
                    enclosing,
                )
                dynamic_recovery_access = (
                    attribute in restricted_recovery_registry_attributes
                    or (
                        receiver_kind == "capability"
                        and (
                            attribute is None
                            or attribute in restricted_recovery_capability_attributes
                            or attribute in restricted_recovery_record_attributes
                        )
                    )
                    or (
                        receiver_kind == "record"
                        and (
                            attribute is None
                            or attribute in restricted_recovery_record_attributes
                        )
                    )
                )
                if dynamic_recovery_access:
                    findings.append(
                        (
                            module.file,
                            node.lineno,
                            f"dynamic restricted recovery authority {leaf}",
                        )
                    )
            if leaf == "vars" and node.args:
                enclosing = _enclosing_function_qualname(node, module.parents)
                if (
                    restricted_recovery_receiver_kind(node.args[0], enclosing)
                    is not None
                ):
                    findings.append(
                        (
                            module.file,
                            node.lineno,
                            "dynamic restricted recovery authority vars",
                        )
                    )
            if leaf in {"__getattribute__", "__setattr__", "__delattr__"}:
                reflective_receiver: ast.AST | None = None
                reflective_attribute: str | None = None
                if isinstance(node.func, ast.Attribute):
                    owner, _ = _resolve_callee(node.func.value, node_aliases)
                    if owner in {"object", "builtins.object"} and len(node.args) >= 2:
                        reflective_receiver = node.args[0]
                        reflective_attribute = _constant_text(node.args[1])
                    elif node.args:
                        reflective_receiver = node.func.value
                        reflective_attribute = _constant_text(node.args[0])
                if reflective_receiver is not None:
                    enclosing = _enclosing_function_qualname(node, module.parents)
                    receiver_kind = restricted_recovery_receiver_kind(
                        reflective_receiver,
                        enclosing,
                    )
                    if (
                        reflective_attribute in restricted_recovery_registry_attributes
                        or (
                            receiver_kind == "capability"
                            and (
                                reflective_attribute is None
                                or reflective_attribute
                                in restricted_recovery_capability_attributes
                                or reflective_attribute
                                in restricted_recovery_record_attributes
                            )
                        )
                        or (
                            receiver_kind == "record"
                            and (
                                reflective_attribute is None
                                or reflective_attribute
                                in restricted_recovery_record_attributes
                            )
                        )
                    ):
                        findings.append(
                            (
                                module.file,
                                node.lineno,
                                f"reflective restricted recovery authority {leaf}",
                            )
                        )
            if leaf in {"setattr", "__setattr__"} and len(node.args) >= 2:
                attribute = _constant_text(node.args[1])
                if attribute in sensitive_assignments and module.file != allowed_file:
                    findings.append(
                        (module.file, node.lineno, f"private state assignment {attribute}")
                    )
            if leaf == "getattr" and len(node.args) >= 2:
                receiver, _ = _resolve_callee(node.args[0], node_aliases)
                attribute = _constant_text(node.args[1])
                if (
                    receiver.startswith(safety_module_prefixes)
                    and (
                        attribute is None
                        or attribute in forbidden_constructors
                        or attribute in forbidden_private_imports
                        or attribute in sensitive_assignments
                    )
                    and module.file != allowed_file
                ):
                    findings.append(
                        (module.file, node.lineno, "dynamic safety attribute lookup")
                    )
            if leaf == "vars" and node.args:
                receiver, _ = _resolve_callee(node.args[0], node_aliases)
                if receiver.startswith(safety_module_prefixes) and module.file != allowed_file:
                    findings.append(
                        (module.file, node.lineno, "dynamic safety module dictionary lookup")
                    )
            if leaf == "__getattribute__":
                receiver = ""
                if isinstance(node.func, ast.Attribute):
                    receiver_node = node.func.value
                    receiver, _ = _resolve_callee(receiver_node, node_aliases)
                    if (
                        isinstance(receiver_node, ast.Call)
                        and receiver_node.args
                        and _resolve_callee(receiver_node.func, node_aliases)[0]
                        in {"type", "builtins.type"}
                    ):
                        receiver, _ = _resolve_callee(
                            receiver_node.args[0],
                            node_aliases,
                        )
                    if receiver in {"object", "builtins.object"} and node.args:
                        receiver, _ = _resolve_callee(node.args[0], node_aliases)
                elif node.args:
                    receiver, _ = _resolve_callee(node.args[0], node_aliases)
                if receiver.startswith(safety_module_prefixes) and module.file != allowed_file:
                    findings.append(
                        (module.file, node.lineno, "reflective safety attribute lookup")
                    )
            if leaf == "NamespacePolicy" and module.file != allowed_file:
                if any(keyword.arg == "_pair_authority" for keyword in node.keywords):
                    findings.append(
                        (module.file, node.lineno, "pair-enabled policy construction")
                    )
        if isinstance(node, ast.Attribute) and node.attr == "__dict__":
            receiver, _ = _resolve_callee(node.value, node_aliases)
            if receiver.startswith(safety_module_prefixes) and module.file != allowed_file:
                findings.append(
                    (module.file, node.lineno, "safety module __dict__ lookup")
                )
        if isinstance(node, ast.Subscript):
            indexed_attribute = _constant_text(node.slice)
            if indexed_attribute in restricted_recovery_registry_attributes:
                findings.append(
                    (
                        module.file,
                        node.lineno,
                        "dynamic restricted recovery registry lookup",
                    )
                )
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets: list[ast.expr]
            if isinstance(node, ast.Assign):
                targets = list(node.targets)
            else:
                targets = [node.target]
            for target in targets:
                target_name = ""
                if isinstance(target, ast.Attribute):
                    target_name = target.attr
                elif isinstance(target, ast.Name):
                    target_name = target.id
                if target_name not in sensitive_assignments:
                    continue
                allowed_assignment = (
                    module.file == allowed_file
                    or (module.file == "app/config.py" and target_name == "PROJECT_ROOT")
                    or (
                        module.file == project_root_file
                        and target_name == "PROJECT_ROOT"
                    )
                    or (
                        module.file == "app/safety/windows_handle_writer.py"
                        and target_name
                        in {
                            "_HANDLE_WRITER_CONSTRUCTOR",
                            "_IMMUTABLE_FILE_LEASE_CONSTRUCTOR",
                            "_DIRECTORY_PUBLISH_PERMIT_CONSTRUCTOR",
                            "_IDENTITY_MATERIAL_CONSTRUCTOR",
                            "__frame",
                            "__rows",
                            "_path_authority",
                            "_api",
                            "_writer",
                            "_workspace_root",
                            "_mutex_name",
                            "_ACTIVE_MUTEX_NAMES",
                        }
                    )
                    or (
                        module.file == ledger_file
                        and target_name
                        in {
                            "_storage",
                            "_key_store",
                            "_ledger",
                            "_sealed_code",
                            "_segments",
                            "_revisions",
                            "_batches",
                            "_record_ids",
                            "_head",
                            "_epoch_id",
                            "_initial_revision_id",
                            "_revision",
                            "_master_key",
                            "_KEY_ROOT",
                            "_SEGMENT_ROOT",
                            "_total_segment_bytes",
                            "_fresh_revision_ids",
                            "_LEDGER_CONSTRUCTOR",
                        }
                    )
                    or (
                        module.file == job_file
                        and target_name
                        in {
                            "_ledger",
                            "_runtime",
                            "_writer",
                            "_operation_ledger",
                            "_workspace_root",
                            "_JOB_RUNTIME_CONSTRUCTOR",
                        }
                    )
                    or (
                        module.file == operation_file
                        and target_name
                        in {
                            "_storage",
                            "_sealed_code",
                            "_segments",
                            "_head",
                            "_epoch_id",
                            "_revision",
                            "_known_revisions",
                            "_SEGMENT_ROOT",
                            "_OPERATION_LEDGER_CONSTRUCTOR",
                            "_total_segment_bytes",
                        }
                    )
                    or (
                        module.file == "app/safety/namespace_policy.py"
                        and target_name
                        in {
                            "_rules",
                            "_digest",
                            "_pair_claim_key",
                            "_pair_authority",
                            "__pair_authority",
                            "_PAIR_CLAIM_CONSTRUCTOR",
                            "POLICY_ID",
                            "POLICY_VERSION",
                            "POLICY_DIGEST",
                            "EXPECTED_POLICY_DIGEST",
                        }
                    )
                    or (
                        module.file == copy_ledger_file
                        and target_name
                        in {
                            "_COPY_LEDGERS_CONSTRUCTOR",
                            "_AUTHENTICATED_COPY_ANCESTORS_CONSTRUCTOR",
                            "_storage",
                            "_epoch_id",
                            "_sealed_code",
                            "_source_chain",
                            "_copy_chain",
                            "_revision",
                            "_run_scope_id",
                            "_run_scope_hmac_sha256",
                            "_known_revisions",
                            "_requested_revision_id",
                            "_append_enabled",
                            "_operation_ledger",
                            "_publish_terminal_binding_sha256s",
                            "_copy_cross_reference_sha256",
                            "auth_key",
                        }
                    )
                    or (
                        module.file == copy_operation_file
                        and target_name
                        in {
                            "_COPY_OPERATION_CONSTRUCTOR",
                            "_runtime",
                            "_ledgers",
                            "_source_policy",
                        }
                    )
                    or (
                        module.file == external_source_file
                        and target_name
                        in {
                            "CONTRACT_PROJECT_ROOT",
                            "_READ_API_CONSTRUCTOR",
                            "_POLICY_CONSTRUCTOR",
                            "_LEASE_CONSTRUCTOR",
                            "_COPY_EXECUTION_PERMIT_CONSTRUCTOR",
                            "_api",
                            "_policy",
                            "_locator_key",
                            "_digest_key",
                        }
                    )
                )
                if not allowed_assignment:
                    findings.append(
                        (module.file, node.lineno, f"private state assignment {target_name}")
                    )
    return findings


def inventory_digest(entries: Iterable[WriteEntry]) -> str:
    return _canonical_sha256([entry.to_dict() for entry in entries])


def payload_digest(payload: dict[str, Any]) -> str:
    canonical = dict(payload)
    canonical.pop("inventory_digest_sha256", None)
    return _canonical_sha256(canonical)


def production_source_manifest(
    snapshot: tuple[tuple[Path, bytes], ...] | None = None,
) -> tuple[dict[str, Any], ...]:
    root = _verified_project_root()
    source_snapshot = snapshot or _production_source_snapshot(root)
    rows: list[dict[str, Any]] = []
    for path, data in source_snapshot:
        rows.append(
            {
                "file": path.relative_to(root).as_posix(),
                "normalization": SOURCE_BYTE_NORMALIZATION,
                "size_bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )
    return tuple(rows)


def build_inventory_payload(
    *,
    generated_at: str,
    source_head: str,
) -> dict[str, Any]:
    manifest, _ = build_inventory_bundle(
        generated_at=generated_at,
        source_head=source_head,
    )
    return manifest


def build_inventory_bundle(
    *,
    generated_at: str,
    source_head: str,
) -> tuple[dict[str, Any], tuple[dict[str, Any], ...]]:
    root = _verified_project_root()
    snapshot = _production_source_snapshot(root)
    entries = _scan_production_snapshot(root, snapshot)
    counts = Counter(entry.kind.value for entry in entries)
    source_manifest = list(production_source_manifest(snapshot))
    chunks: list[dict[str, Any]] = []
    chunk_refs: list[dict[str, Any]] = []
    entry_rows = [entry.to_dict() for entry in entries]
    for start in range(0, len(entry_rows), ENTRY_CHUNK_SIZE):
        chunk_index = start // ENTRY_CHUNK_SIZE
        rows = entry_rows[start : start + ENTRY_CHUNK_SIZE]
        chunk: dict[str, Any] = {
            "schema_version": "2.0",
            "chunk_index": chunk_index,
            "entry_count": len(rows),
            "entries": rows,
        }
        chunk["chunk_digest_sha256"] = _canonical_sha256(chunk)
        chunks.append(chunk)
        chunk_refs.append(
            {
                "path": (
                    "Task/reports/M0/write-entry-inventory/"
                    f"entries-{chunk_index:03d}.json"
                ),
                "entry_count": len(rows),
                "canonical_payload_sha256": chunk["chunk_digest_sha256"],
                "serialized_file_sha256": hashlib.sha256(
                    _pretty_json_bytes(chunk)
                ).hexdigest(),
            }
        )
    payload: dict[str, Any] = {
        "schema_version": "2.0",
        "scanner_version": SCANNER_VERSION,
        "generated_at": generated_at,
        "source_head": source_head,
        "source_dirty": True,
        "project_root_id": "CONTRACT_PROJECT_ROOT",
        "included_roots": list(PRODUCTION_ROOTS),
        "excluded_roots": ["tests", "Base", "Copy", "Task/local", ".git"],
        "source_byte_normalization": SOURCE_BYTE_NORMALIZATION,
        "source_manifest": source_manifest,
        "source_manifest_digest_sha256": _canonical_sha256(source_manifest),
        "entry_count": len(entries),
        "entry_chunk_size": ENTRY_CHUNK_SIZE,
        "entry_chunks": chunk_refs,
        "entries_digest_sha256": inventory_digest(entries),
        "counts_by_kind": dict(sorted(counts.items())),
        "global_status": "UNMIGRATED_BLOCKED",
        "gate": {
            "unknown_dynamic_count": counts.get(
                WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY.value, 0
            ),
            "unmigrated_count": sum(
                entry.migration_status is MigrationStatus.UNMIGRATED_BLOCKED
                for entry in entries
            ),
            "production_writer_connected": False,
            "m0_exit_allowed": False,
        },
    }
    payload["inventory_digest_sha256"] = payload_digest(payload)
    return payload, tuple(chunks)


def _verified_project_root(_expected: Path = _VERIFIED_PROJECT_ROOT) -> Path:
    root = Path(PROJECT_ROOT)
    expected = Path(_expected)
    if str(root).casefold() != str(expected).casefold():
        raise RuntimeError("static audit project root differs from the execution contract")
    return root


def _production_source_paths(root: Path) -> tuple[Path, ...]:
    paths: set[Path] = set()
    for relative_root in PRODUCTION_ROOTS:
        candidate = root / relative_root
        if candidate.is_dir():
            for path in candidate.rglob("*"):
                if path.is_file() and path.suffix.casefold() in SOURCE_SUFFIXES:
                    paths.add(path)
    return tuple(sorted(paths, key=lambda item: item.as_posix().casefold()))


def _production_source_snapshot(root: Path) -> tuple[tuple[Path, bytes], ...]:
    paths = _production_source_paths(root)
    raw_snapshot = tuple((path, path.read_bytes()) for path in paths)
    if _production_source_paths(root) != paths:
        raise RuntimeError("production source set changed while inventory was captured")
    for path, data in raw_snapshot:
        if path.read_bytes() != data:
            raise RuntimeError(
                f"production source changed while inventory was captured: {path.name}"
            )
    return tuple(
        (path, _normalize_source_bytes(path, data)) for path, data in raw_snapshot
    )


def _normalize_source_bytes(path: Path, data: bytes) -> bytes:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeError(f"production source is not UTF-8: {path.name}") from exc
    if text.startswith("\ufeff"):
        raise RuntimeError(f"production source must not use a UTF-8 BOM: {path.name}")
    return text.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")


def _load_module_facts(
    root: Path,
    snapshot: tuple[tuple[Path, bytes], ...] | None = None,
) -> dict[str, _ModuleFacts]:
    result: dict[str, _ModuleFacts] = {}
    for path, data in snapshot or _production_source_snapshot(root):
        if path.suffix.casefold() != ".py":
            continue
        relative = path.relative_to(root).as_posix()
        facts = _module_facts_from_text(
            data.decode("utf-8"),
            file=relative,
            source_sha256=hashlib.sha256(data).hexdigest(),
        )
        result[facts.module] = facts
    return result


def _module_facts_from_text(
    source: str,
    *,
    file: str,
    source_sha256: str | None = None,
) -> _ModuleFacts:
    tree = ast.parse(source, filename=file)
    module_name = _module_name(file)
    imports = _collect_imports(tree, module_name)
    parents = _parents(tree)
    functions: dict[str, _FunctionFact] = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        qualname = _qualname(node, parents)
        canonical = f"{module_name}.{qualname}"
        functions[canonical] = _FunctionFact(
            canonical=canonical,
            file=file,
            node=node,
            root_ids=_root_ids(node, file),
        )
    return _ModuleFacts(
        file=file,
        module=module_name,
        source_sha256=source_sha256 or hashlib.sha256(source.encode("utf-8")).hexdigest(),
        tree=tree,
        parents=parents,
        imports=imports,
        functions=functions,
    )


def _scan_module(
    module: _ModuleFacts,
    *,
    audited_indexed_hits: Counter[tuple[str, str, str]] | None = None,
) -> list[_RawEntry]:
    visitor = _SinkVisitor(module, audited_indexed_hits=audited_indexed_hits)
    visitor.visit(module.tree)
    return visitor.entries


class _SinkVisitor(ast.NodeVisitor):
    def __init__(
        self,
        module: _ModuleFacts,
        *,
        audited_indexed_hits: Counter[tuple[str, str, str]] | None = None,
    ) -> None:
        self.module = module
        self.entries: list[_RawEntry] = []
        self.scope_stack: list[str] = ["<module>"]
        self.alias_stack: list[dict[str, str]] = [dict(module.imports)]
        self.constant_stack: list[dict[str, str | None]] = [{}]
        self.global_stack: list[set[str]] = [set()]
        self.parameter_stack: list[set[str]] = [set()]
        self.ordinal: Counter[tuple[str, str, str]] = Counter()
        self.audited_indexed_hits = audited_indexed_hits

    @property
    def aliases(self) -> dict[str, str]:
        merged: dict[str, str] = {}
        for scope in self.alias_stack:
            merged.update(scope)
        return merged

    @property
    def function(self) -> str:
        return self.scope_stack[-1]

    @property
    def constants(self) -> dict[str, str]:
        merged: dict[str, str] = {}
        for scope in self.constant_stack:
            for name, value in scope.items():
                if value is None:
                    merged.pop(name, None)
                else:
                    merged[name] = value
        return merged

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        return self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        return self._visit_function(node)

    def visit_Lambda(self, node: ast.Lambda) -> Any:
        for default in (*node.args.defaults, *node.args.kw_defaults):
            if default is not None:
                self._emit_stored_capability(
                    default,
                    "callable default stores a write or native capability",
                    include_native_call_results=True,
                )
                self.visit(default)
        argument_nodes = (
            *node.args.posonlyargs,
            *node.args.args,
            *node.args.kwonlyargs,
        )
        argument_names = {argument.arg for argument in argument_nodes}
        if node.args.vararg is not None:
            argument_names.add(node.args.vararg.arg)
        if node.args.kwarg is not None:
            argument_names.add(node.args.kwarg.arg)
        self.alias_stack.append({name: name for name in argument_names})
        self.constant_stack.append({name: None for name in argument_names})
        self.global_stack.append(set())
        self.parameter_stack.append(argument_names)
        self._emit_stored_capability(
            node.body,
            "lambda returns a write or native capability",
            include_native_call_results=True,
        )
        self.visit(node.body)
        self.parameter_stack.pop()
        self.global_stack.pop()
        self.constant_stack.pop()
        self.alias_stack.pop()

    def visit_ListComp(self, node: ast.ListComp) -> Any:
        self._visit_comprehension(node.generators, (node.elt,))

    def visit_SetComp(self, node: ast.SetComp) -> Any:
        self._visit_comprehension(node.generators, (node.elt,))

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> Any:
        self._visit_comprehension(node.generators, (node.elt,))

    def visit_DictComp(self, node: ast.DictComp) -> Any:
        self._visit_comprehension(node.generators, (node.key, node.value))

    def _visit_comprehension(
        self,
        generators: list[ast.comprehension],
        outputs: tuple[ast.AST, ...],
    ) -> None:
        self.alias_stack.append({})
        self.constant_stack.append({})
        self.global_stack.append(set())
        try:
            for generator in generators:
                self._emit_stored_capability(
                    generator.iter,
                    "comprehension source contains a write or native capability",
                    include_native_call_results=True,
                )
                self.visit(generator.iter)
                self._invalidate_target(generator.target)
                for condition in generator.ifs:
                    self.visit(condition)
            for output in outputs:
                self.visit(output)
        finally:
            self.global_stack.pop()
            self.constant_stack.pop()
            self.alias_stack.pop()

    def _visit_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        qualname = _qualname(node, self.module.parents)
        canonical = f"{self.module.module}.{qualname}"
        for decorator in node.decorator_list:
            self._emit_stored_capability(
                decorator,
                "decorator applies an escaped write or native capability",
                include_native_call_results=True,
            )
            self.visit(decorator)
        for default in (*node.args.defaults, *node.args.kw_defaults):
            if default is not None:
                self._emit_stored_capability(
                    default,
                    "callable default stores a write or native capability",
                    include_native_call_results=True,
                )
                self.visit(default)
        if node.returns is not None:
            self.visit(node.returns)
        argument_nodes = (
            *node.args.posonlyargs,
            *node.args.args,
            *node.args.kwonlyargs,
        )
        for argument in argument_nodes:
            if argument.annotation is not None:
                self.visit(argument.annotation)
        if node.args.vararg is not None and node.args.vararg.annotation is not None:
            self.visit(node.args.vararg.annotation)
        if node.args.kwarg is not None and node.args.kwarg.annotation is not None:
            self.visit(node.args.kwarg.annotation)
        argument_names = {argument.arg for argument in argument_nodes}
        if node.args.vararg is not None:
            argument_names.add(node.args.vararg.arg)
        if node.args.kwarg is not None:
            argument_names.add(node.args.kwarg.arg)
        self.scope_stack.append(canonical)
        self.alias_stack.append({name: name for name in argument_names})
        self.constant_stack.append({name: None for name in argument_names})
        self.global_stack.append(set())
        self.parameter_stack.append(argument_names)
        for statement in node.body:
            self.visit(statement)
        self.parameter_stack.pop()
        self.global_stack.pop()
        self.constant_stack.pop()
        self.alias_stack.pop()
        self.scope_stack.pop()

    def visit_Import(self, node: ast.Import) -> Any:
        for alias in node.names:
            if (
                alias.name in {"_cffi_backend", "_ctypes"}
                or alias.name.startswith(("_cffi_backend.", "_ctypes."))
            ):
                self._emit(
                    node,
                    WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY,
                    alias.name,
                    ResolutionConfidence.DYNAMIC,
                    "private native backend import exposes unattributed execution",
                )
            bound_name = alias.asname or alias.name.split(".", 1)[0]
            self._invalidate_names({bound_name})
            self._set_alias(bound_name, alias.name)

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        for base in node.bases:
            base_name, _ = _resolve_callee(base, self.aliases)
            stored_base = _stored_capability_reference(base, self.aliases)
            if (
                base_name.casefold() in {"_ctypes.cfuncptr", "ctypes._cfuncptr"}
                or stored_base is not None
            ):
                self._emit(
                    node,
                    WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY,
                    stored_base or base_name,
                    ResolutionConfidence.DYNAMIC,
                    "native C function pointer subclass is not attributable",
                )
            self.visit(base)
        for keyword in node.keywords:
            self.visit(keyword.value)
        for decorator in node.decorator_list:
            self._emit_stored_capability(
                decorator,
                "class decorator applies an escaped write or native capability",
                include_native_call_results=True,
            )
            self.visit(decorator)
        for type_parameter in getattr(node, "type_params", ()):
            self.visit(type_parameter)

        self.alias_stack.append({})
        self.constant_stack.append({})
        self.global_stack.append(set())
        self.parameter_stack.append(set())
        for statement in node.body:
            self.visit(statement)
        class_aliases = dict(self.alias_stack[-1])
        self.parameter_stack.pop()
        self.global_stack.pop()
        self.constant_stack.pop()
        self.alias_stack.pop()
        for name, value in class_aliases.items():
            if value and value != "<ambiguous>":
                self.alias_stack[-1][f"{node.name}.{name}"] = value

    def visit_Attribute(self, node: ast.Attribute) -> Any:
        resolved, _ = _resolve_callee(node, self.aliases)
        native_name = resolved.casefold()
        if node.attr == "__dict__":
            self._emit(
                node,
                WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY,
                resolved,
                ResolutionConfidence.DYNAMIC,
                "attribute dictionary lookup can hide an executable capability",
            )
        if native_name == "sys.modules" or native_name.startswith("sys.modules."):
            self._emit(
                node,
                WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY,
                resolved,
                ResolutionConfidence.DYNAMIC,
                "runtime module registry lookup can hide an executable capability",
            )
        if node.attr == "_handle" and native_name.startswith(
            (
                "ctypes.cdll",
                "ctypes.libraryloader",
                "ctypes.oledll",
                "ctypes.pydll",
                "ctypes.pythonapi",
                "ctypes.windll",
            )
        ):
            self._emit(
                node,
                WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY,
                resolved,
                ResolutionConfidence.DYNAMIC,
                "native library handle extraction is forbidden",
            )
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
        if any(alias.name == "*" for alias in node.names):
            self._emit(
                node,
                WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY,
                "star-import",
                ResolutionConfidence.DYNAMIC,
                "star import prevents fail-closed capability resolution",
            )
            return
        base = _resolve_import_module(self.module.module, node.module, node.level)
        if base in {"_cffi_backend", "_ctypes"} or base.startswith(
            ("_cffi_backend.", "_ctypes.")
        ):
            self._emit(
                node,
                WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY,
                base,
                ResolutionConfidence.DYNAMIC,
                "private native backend import exposes unattributed execution",
            )
        elif base == "ctypes" and any(
            alias.name in {"cdll", "oledll", "pydll", "pythonapi", "windll"}
            for alias in node.names
        ):
            self._emit(
                node,
                WritePrimitiveKind.NATIVE_API_BINDING,
                base,
                ResolutionConfidence.CONSERVATIVE,
                "ctypes native loader import requires an audited symbol allowlist",
            )
        for alias in node.names:
            bound_name = alias.asname or alias.name
            self._invalidate_names({bound_name})
            self._set_alias(bound_name, f"{base}.{alias.name}")

    def visit_Global(self, node: ast.Global) -> Any:
        self.global_stack[-1].update(node.names)
        for name in node.names:
            if len(self.constant_stack) > 1:
                self.constant_stack[-1].pop(name, None)
                self.alias_stack[-1].pop(name, None)
            self.constant_stack[0][name] = None
            self.alias_stack[0][name] = "<ambiguous>"

    def visit_Nonlocal(self, node: ast.Nonlocal) -> Any:
        for name in node.names:
            for constants in self.constant_stack[:-1]:
                constants[name] = None
            for aliases in self.alias_stack[:-1]:
                aliases[name] = "<ambiguous>"

    def visit_Assign(self, node: ast.Assign) -> Any:
        value_name, _ = _resolve_callee(node.value, self.aliases)
        constant = _constant_text_with_aliases(node.value, self.constants)
        self._emit_stored_capability(
            node.value,
            "assignment stores a write or native capability",
            include_native_call_results=(
                self._is_class_body(node)
                or any(isinstance(target, ast.Attribute) for target in node.targets)
                or _expression_can_hide_capability(node.value)
            ),
        )
        for target in node.targets:
            self._invalidate_target(target)
            self._record_destructured_alias(target, node.value, value_name)
            if isinstance(target, ast.Name):
                self._set_constant(target.id, constant)
        self.visit(node.value)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        if node.value is not None:
            value_name, _ = _resolve_callee(node.value, self.aliases)
            self._emit_stored_capability(
                node.value,
                "annotated assignment stores a write or native capability",
                include_native_call_results=(
                    self._is_class_body(node)
                    or isinstance(node.target, ast.Attribute)
                    or _expression_can_hide_capability(node.value)
                ),
            )
            self._invalidate_target(node.target)
            self._record_alias(node.target, value_name)
            constant = _constant_text_with_aliases(node.value, self.constants)
            if isinstance(node.target, ast.Name):
                self._set_constant(node.target.id, constant)
            self.visit(node.value)

    def visit_AugAssign(self, node: ast.AugAssign) -> Any:
        self._emit_stored_capability(
            node.value,
            "augmented assignment stores a write or native capability",
            include_native_call_results=True,
        )
        self._invalidate_target(node.target)
        self.visit(node.value)

    def visit_If(self, node: ast.If) -> Any:
        self._visit_control_flow(node)

    def visit_For(self, node: ast.For) -> Any:
        self._visit_control_flow(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> Any:
        self._visit_control_flow(node)

    def visit_While(self, node: ast.While) -> Any:
        self._visit_control_flow(node)

    def visit_Try(self, node: ast.Try) -> Any:
        self._visit_control_flow(node)

    def visit_TryStar(self, node: ast.TryStar) -> Any:
        self._visit_control_flow(node)

    def visit_Match(self, node: ast.Match) -> Any:
        self._visit_control_flow(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> Any:
        self._emit_stored_capability(
            node.value,
            "assignment expression stores a write or native capability",
            include_native_call_results=_expression_can_hide_capability(node.value),
        )
        self.visit(node.value)
        value_name, _ = _resolve_callee(node.value, self.aliases)
        constant = _constant_text_with_aliases(node.value, self.constants)
        self._invalidate_target(node.target)
        self._record_alias(node.target, value_name)
        if isinstance(node.target, ast.Name):
            self._set_constant(node.target.id, constant)

    def _visit_control_flow(self, node: ast.AST) -> None:
        branches: list[tuple[tuple[ast.AST, ...], list[ast.stmt]]] = []
        if isinstance(node, ast.If):
            self.visit(node.test)
            branches = [((), node.body), ((), node.orelse)]
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            self._emit_stored_capability(
                node.iter,
                "iteration source contains a write or native capability",
                include_native_call_results=True,
            )
            self.visit(node.iter)
            branches = [((), node.body), ((), node.orelse)]
        elif isinstance(node, ast.While):
            self.visit(node.test)
            branches = [((), node.body), ((), node.orelse)]
        elif isinstance(node, (ast.Try, ast.TryStar)):
            branches = [((), node.body), ((), node.orelse), ((), node.finalbody)]
            branches.extend(
                (
                    ((handler.type,) if handler.type is not None else ()),
                    handler.body,
                )
                for handler in node.handlers
            )
        elif isinstance(node, ast.Match):
            self.visit(node.subject)
            branches = [
                (
                    (case.pattern, case.guard)
                    if case.guard is not None
                    else (case.pattern,),
                    case.body,
                )
                for case in node.cases
            ]
        assigned = _assigned_names(node)
        if isinstance(node, ast.Match):
            for case in node.cases:
                assigned.update(_pattern_bound_names(case.pattern))
        if isinstance(node, (ast.Try, ast.TryStar)):
            assigned.update(
                handler.name
                for handler in node.handlers
                if isinstance(handler.name, str)
            )
        self._invalidate_names(assigned)
        base_aliases = dict(self.alias_stack[-1])
        base_constants = dict(self.constant_stack[-1])
        for prelude, statements in branches:
            self.alias_stack[-1] = dict(base_aliases)
            self.constant_stack[-1] = dict(base_constants)
            for item in prelude:
                self.visit(item)
            for statement in statements:
                self.visit(statement)
        self.alias_stack[-1] = base_aliases
        self.constant_stack[-1] = base_constants
        self._invalidate_names(assigned)

    def _invalidate_names(self, names: set[str]) -> None:
        for name in names:
            index = self._binding_scope_index(name)
            self.constant_stack[index][name] = None
            self.alias_stack[index][name] = "<ambiguous>"

    def _binding_scope_index(self, name: str) -> int:
        if name in self.global_stack[-1]:
            return 0
        return len(self.alias_stack) - 1

    def _set_constant(self, name: str, value: str | None) -> None:
        self.constant_stack[self._binding_scope_index(name)][name] = value

    def _set_alias(self, name: str, value: str) -> None:
        self.alias_stack[self._binding_scope_index(name)][name] = value

    def _invalidate_target(self, target: ast.expr) -> None:
        if isinstance(target, ast.Name):
            self._invalidate_names({target.id})
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self._invalidate_target(element)

    def visit_With(self, node: ast.With) -> Any:
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars is not None:
                value_name, _ = _resolve_callee(item.context_expr, self.aliases)
                self._invalidate_target(item.optional_vars)
                self._record_alias(item.optional_vars, value_name)
        for statement in node.body:
            self.visit(statement)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> Any:
        self.visit_With(node)

    def _record_alias(self, target: ast.expr, value_name: str) -> None:
        if not value_name:
            return
        if isinstance(target, ast.Name):
            self._set_alias(target.id, value_name)
        elif isinstance(target, ast.Attribute):
            target_name, _ = _resolve_callee(target, self.aliases)
            self.alias_stack[-1][target_name] = value_name

    def _record_destructured_alias(
        self,
        target: ast.expr,
        value: ast.expr,
        fallback_name: str,
    ) -> None:
        if (
            isinstance(target, (ast.Tuple, ast.List))
            and isinstance(value, (ast.Tuple, ast.List))
            and len(target.elts) == len(value.elts)
        ):
            for target_item, value_item in zip(target.elts, value.elts, strict=True):
                value_name, _ = _resolve_callee(value_item, self.aliases)
                self._record_destructured_alias(target_item, value_item, value_name)
            return
        self._record_alias(target, fallback_name)

    def visit_Return(self, node: ast.Return) -> Any:
        if node.value is not None:
            self._emit_stored_capability(
                node.value,
                "return value exposes a write or native capability",
                include_native_call_results=True,
            )
            self.visit(node.value)

    def visit_Yield(self, node: ast.Yield) -> Any:
        if node.value is not None:
            self._emit_stored_capability(
                node.value,
                "yield value exposes a write or native capability",
                include_native_call_results=True,
            )
            self.visit(node.value)

    def visit_YieldFrom(self, node: ast.YieldFrom) -> Any:
        self._emit_stored_capability(
            node.value,
            "yield-from value exposes a write or native capability",
            include_native_call_results=True,
        )
        self.visit(node.value)

    def _emit_stored_capability(
        self,
        node: ast.AST,
        detail: str,
        *,
        include_native_call_results: bool = False,
    ) -> None:
        reference = _stored_capability_reference(
            node,
            self.aliases,
            include_native_call_results=include_native_call_results,
        )
        if reference is not None:
            store_node = node
            current = node
            while current in self.module.parents:
                current = self.module.parents[current]
                if isinstance(
                    current,
                    (
                        ast.Assign,
                        ast.AnnAssign,
                        ast.AugAssign,
                        ast.NamedExpr,
                        ast.Return,
                        ast.Yield,
                        ast.YieldFrom,
                    ),
                ):
                    store_node = current
                    break
            callsite = _indexed_callsite_key(
                store_node,
                file=self.module.file,
                function=self.function,
            )
            if (
                self.audited_indexed_hits is not None
                and callsite in _AUDITED_CAPABILITY_STORES
            ):
                self.audited_indexed_hits[callsite] += 1
                return
            self._emit(
                node,
                WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY,
                reference,
                ResolutionConfidence.DYNAMIC,
                detail,
            )

    def _is_class_body(self, node: ast.AST) -> bool:
        current = node
        while current in self.module.parents:
            current = self.module.parents[current]
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                return False
            if isinstance(current, ast.ClassDef):
                return True
        return False

    def visit_Call(self, node: ast.Call) -> Any:
        callee, resolution = _resolve_callee(node.func, self.aliases)
        callsite = _indexed_callsite_key(
            node,
            file=self.module.file,
            function=self.function,
        )
        classification = _classify_call(
            node,
            callee,
            self.constants,
            aliases=self.aliases,
            parameter_names=set().union(*self.parameter_stack),
            file=self.module.file,
            function=self.function,
            allow_audited_indexed=self.audited_indexed_hits is not None,
        )
        if (
            classification is not None
            and classification[0] is WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY
            and callsite in _AUDITED_DYNAMIC_CALLS
            and self.audited_indexed_hits is not None
        ):
            self.audited_indexed_hits[callsite] += 1
            classification = None
        if (
            classification is None
            and callsite in (_AUDITED_INDEXED_CALLS | _AUDITED_PARAMETER_CALLS)
            and self.audited_indexed_hits is not None
        ):
            self.audited_indexed_hits[callsite] += 1
        if classification is not None:
            kind, detail, forced_resolution = classification
            self._emit(
                node,
                kind,
                callee,
                forced_resolution or resolution,
                detail,
            )
        self.generic_visit(node)

    def _emit(
        self,
        node: ast.AST,
        kind: WritePrimitiveKind,
        callee: str,
        resolution: ResolutionConfidence,
        detail: str,
    ) -> None:
        fingerprint = hashlib.sha256(
            ast.dump(node, include_attributes=False).encode("utf-8")
        ).hexdigest()
        self.entries.append(
            _RawEntry(
                file=self.module.file,
                source_sha256=self.module.source_sha256,
                line=getattr(node, "lineno", 0),
                column=getattr(node, "col_offset", 0),
                end_line=getattr(node, "end_lineno", getattr(node, "lineno", 0)),
                end_column=getattr(node, "end_col_offset", 0),
                function=self.function,
                kind=kind,
                callee=callee,
                resolution=resolution,
                statement_fingerprint=fingerprint,
                detail=detail,
            )
        )


def _indexed_callsite_key(
    node: ast.Call,
    *,
    file: str,
    function: str,
) -> tuple[str, str, str]:
    fingerprint = hashlib.sha256(
        ast.dump(node, include_attributes=False).encode("utf-8")
    ).hexdigest()
    return file, function, fingerprint


def _classify_call(
    node: ast.Call,
    callee: str,
    constants: dict[str, str] | None = None,
    *,
    aliases: dict[str, str] | None = None,
    parameter_names: set[str] | None = None,
    file: str = "synthetic.py",
    function: str = "<module>",
    allow_audited_indexed: bool = False,
) -> tuple[WritePrimitiveKind, str, ResolutionConfidence | None] | None:
    canonical = callee.casefold()
    leaf = canonical.rsplit(".", 1)[-1]
    source_leaf = callee.rsplit(".", 1)[-1]
    if leaf in {"getattr", "getattr_static", "__getattribute__", "vars"}:
        receiver_name = canonical.rsplit(".", 1)[0] if "." in canonical else ""
        if _is_reflective_capability_source(receiver_name):
            return (
                WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY,
                "reflective module capability lookup is forbidden",
                ResolutionConfidence.DYNAMIC,
            )
        reflected_owner_node: ast.AST | None = None
        reflected_attribute: str | None = None
        if leaf in {"getattr", "getattr_static"} and len(node.args) >= 2:
            reflected_owner_node = node.args[0]
            reflected_attribute = _constant_text(node.args[1])
        elif leaf == "__getattribute__":
            if len(node.args) >= 2:
                reflected_owner_node = node.args[0]
                reflected_attribute = _constant_text(node.args[1])
            elif node.args:
                reflected_attribute = _constant_text(node.args[0])
        if reflected_owner_node is not None:
            reflected_owner, _ = _resolve_callee(
                reflected_owner_node,
                aliases or {},
            )
        else:
            reflected_owner = receiver_name
        if reflected_owner.casefold() == "sys" and reflected_attribute == "modules":
            return (
                WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY,
                "runtime module registry lookup can hide an executable capability",
                ResolutionConfidence.DYNAMIC,
            )
        reflective_targets = list(node.args[:-1] if leaf != "vars" else node.args)
        if leaf in {"getattr", "getattr_static"} and node.args:
            reflective_targets = [node.args[0]]
        for target in reflective_targets:
            receiver, _ = _resolve_callee(target, aliases or {})
            native_name = receiver.casefold()
            if _is_reflective_capability_source(native_name):
                return (
                    WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY,
                    "reflective native API lookup is forbidden",
                    ResolutionConfidence.DYNAMIC,
                )
    for argument in (*node.args, *(keyword.value for keyword in node.keywords)):
        for candidate in _iter_container_expressions(argument, aliases or {}):
            argument_name, _ = _resolve_callee(candidate, aliases or {})
            normalized_argument = argument_name.casefold()
            native_prefix = normalized_argument.startswith(
                _NATIVE_CAPABILITY_PREFIXES
            )
            native_result = normalized_argument.endswith("()") and normalized_argument not in {
                "ctypes.cdll()",
                "ctypes.libraryloader()",
                "ctypes.oledll()",
                "ctypes.pydll()",
                "ctypes.windll()",
            }
            native_argument = (
                normalized_argument in {"ctypes", "_ctypes"}
                or (native_prefix and not native_result)
            )
            if (
                normalized_argument in _RISKY_CAPABILITY_REFERENCES
                or (
                    normalized_argument in _CAPABILITY_NAMESPACE_REFERENCES
                    and not (
                        leaf in {"getattr", "getattr_static"}
                        and node.args
                        and candidate is node.args[0]
                        and len(node.args) >= 2
                        and (
                            (_constant_text(node.args[1]) or "").replace("_", "A")
                        ).isalnum()
                        and (_constant_text(node.args[1]) or "").upper()
                        == (_constant_text(node.args[1]) or "")
                    )
                )
                or native_argument
                or _is_native_escaping_result(normalized_argument)
            ):
                return (
                    WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY,
                    "write or native capability passed through a generic call",
                    ResolutionConfidence.DYNAMIC,
                )
    if callee.startswith("<value>."):
        escaped_reference = _stored_capability_reference(
            node.func,
            aliases or {},
            include_native_call_results=True,
        )
        if escaped_reference is not None:
            return (
                WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY,
                "expression call contains an unattributed write or native capability",
                ResolutionConfidence.DYNAMIC,
            )
    if canonical in {
        "ctypes.cfunctype",
        "ctypes.cdll",
        "ctypes.cast",
        "ctypes.libraryloader",
        "ctypes.memmove",
        "ctypes.memset",
        "ctypes.oledll",
        "ctypes.pyfunctype",
        "ctypes.pydll",
        "ctypes.winfunctype",
        "ctypes.windll",
        "ctypes.cdll.loadlibrary",
        "ctypes.oledll.loadlibrary",
        "ctypes.pydll.loadlibrary",
        "ctypes.windll.loadlibrary",
    }:
        if canonical in {
            "ctypes.cdll",
            "ctypes.libraryloader",
            "ctypes.oledll",
            "ctypes.pydll",
            "ctypes.windll",
        }:
            library = _constant_text(node.args[0]) if node.args else None
            if library is None or library.casefold().removesuffix(".dll") not in {
                "advapi32",
                "kernel32",
                "ntdll",
                "shell32",
                "user32",
            }:
                return (
                    WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY,
                    "native library identity is not on the fixed audited allowlist",
                    ResolutionConfidence.DYNAMIC,
                )
        return (
            WritePrimitiveKind.NATIVE_API_BINDING,
            "native library binding requires an audited symbol allowlist",
            ResolutionConfidence.CONSERVATIVE,
        )
    if canonical.startswith(
        ("ctypes.cfunctype()()", "ctypes.pyfunctype()()", "ctypes.winfunctype()()")
    ):
        return (
            WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY,
            "native function pointer invocation is not statically attributable",
            ResolutionConfidence.DYNAMIC,
        )
    if canonical.startswith(
        ("ctypes.cfunctype()", "ctypes.pyfunctype()", "ctypes.winfunctype()")
    ):
        return (
            WritePrimitiveKind.NATIVE_API_BINDING,
            "native function pointer construction requires an audited target",
            ResolutionConfidence.CONSERVATIVE,
        )
    if canonical in {
        "eval",
        "exec",
        "builtins.compile",
        "compile",
        "__import__",
        "builtins.eval",
        "builtins.exec",
        "importlib.import_module",
        "importlib.machinery.extensionfileloader",
        "importlib.machinery.sourcelessfileloader",
        "importlib.machinery.sourcefileloader",
        "importlib.util.module_from_spec",
        "globals",
        "locals",
        "marshal.loads",
        "pickle.load",
        "pickle.loads",
        "runpy.run_module",
        "runpy.run_path",
        "types.codetype",
        "types.functiontype",
        "types.methodtype",
    }:
        return (
            WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY,
            "dynamic execution or import can hide a write capability",
            ResolutionConfidence.DYNAMIC,
        )
    if canonical.startswith("ctypes._"):
        return (
            WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY,
            "private ctypes execution or raw-address surface is forbidden",
            ResolutionConfidence.DYNAMIC,
        )
    if (
        canonical.startswith("importlib.machinery.")
        and leaf in {"create_module", "exec_module", "load_module"}
    ):
        return (
            WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY,
            "dynamic source or extension loader execution is forbidden",
            ResolutionConfidence.DYNAMIC,
        )
    if canonical in {"cffi.ffi", "cffi.ffi.dlopen", "cffi.ffi().dlopen", "ffi.dlopen"}:
        if leaf == "dlopen":
            library = _constant_text(node.args[0]) if node.args else None
            if library is None or library.casefold().removesuffix(".dll") not in {
                "advapi32",
                "kernel32",
                "ntdll",
                "shell32",
                "user32",
            }:
                return (
                    WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY,
                    "CFFI library identity is not on the fixed audited allowlist",
                    ResolutionConfidence.DYNAMIC,
                )
        return (
            WritePrimitiveKind.NATIVE_API_BINDING,
            "CFFI native binding requires a fixed library and symbol allowlist",
            ResolutionConfidence.CONSERVATIVE,
        )
    if canonical == "mmap.mmap":
        return (
            WritePrimitiveKind.FILESYSTEM_FILE_WRITE,
            "memory mapping may mutate the mapped file",
            ResolutionConfidence.CONSERVATIVE,
        )
    if canonical in {"ctypes.cast()"} or canonical.startswith(
        ("ctypes.cfunctype()()", "ctypes.pyfunctype()()", "ctypes.winfunctype()()")
    ):
        return (
            WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY,
            "escaped native callable invocation is not attributable",
            ResolutionConfidence.DYNAMIC,
        )
    if canonical in {
        "functools.partial",
        "functools.partialmethod",
        "operator.attrgetter",
        "operator.methodcaller",
    }:
        return (
            WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY,
            "callable wrapper can hide a write or external-execution capability",
            ResolutionConfidence.DYNAMIC,
        )
    if leaf == "mkdir" or canonical in {"os.mkdir", "os.makedirs"}:
        return WritePrimitiveKind.FILESYSTEM_DIRECTORY_CREATE, "directory creation", None
    if leaf in {"createdirectorya", "createdirectoryw"}:
        return (
            WritePrimitiveKind.FILESYSTEM_DIRECTORY_CREATE,
            "Win32 directory creation",
            ResolutionConfidence.CONSERVATIVE,
        )
    if canonical in {"print", "builtins.print"}:
        file_targets = tuple(
            _resolve_callee(keyword.value, {})[0]
            for keyword in node.keywords
            if keyword.arg == "file"
        )
        if file_targets and not all(
            target in {"sys.stdout", "sys.stderr"} for target in file_targets
        ):
            return (
                WritePrimitiveKind.FILESYSTEM_FILE_WRITE,
                "print with an explicit file target",
                ResolutionConfidence.CONSERVATIVE,
            )
    if leaf in {"write_text", "write_bytes", "writelines", "truncate", "touch"}:
        return WritePrimitiveKind.FILESYSTEM_FILE_WRITE, "file content mutation", None
    if leaf == "write":
        if _looks_like_archive_receiver(canonical):
            return WritePrimitiveKind.ARCHIVE_WRITE, "archive member write", None
        return (
            WritePrimitiveKind.FILESYSTEM_FILE_WRITE,
            "stream or file descriptor write",
            ResolutionConfidence.CONSERVATIVE,
        )
    if canonical in {"os.write", "os.pwrite", "os.ftruncate"}:
        return WritePrimitiveKind.FILESYSTEM_FILE_WRITE, "low-level descriptor mutation", None
    if leaf in {
        "createfilea",
        "createfilew",
        "createfilemappinga",
        "createfilemappingw",
        "flushfilebuffers",
        "setendoffile",
        "writefile",
    }:
        return (
            WritePrimitiveKind.FILESYSTEM_FILE_WRITE,
            "Win32 file mutation or durability primitive",
            ResolutionConfidence.CONSERVATIVE,
        )
    if canonical == "os.open":
        if _os_open_may_write(node):
            return WritePrimitiveKind.FILESYSTEM_FILE_WRITE, "low-level open may write", None
        return None
    if canonical == "io.fileio":
        if _open_call_may_write(node, canonical):
            return (
                WritePrimitiveKind.FILESYSTEM_FILE_WRITE,
                "FileIO construction opens a write-capable file",
                ResolutionConfidence.CONSERVATIVE,
            )
        return None
    if leaf == "open" and _looks_like_archive_receiver(canonical):
        if _archive_member_open_may_write(node):
            return WritePrimitiveKind.ARCHIVE_WRITE, "archive member opened for writing", None
        return None
    if leaf == "open" and _is_file_open_symbol(canonical):
        if _open_call_may_write(node, canonical):
            return WritePrimitiveKind.FILESYSTEM_FILE_WRITE, "file open in write-capable mode", None
        return None
    if leaf == "save":
        return (
            WritePrimitiveKind.FILESYSTEM_FILE_WRITE,
            "serializer/image save writes a target",
            ResolutionConfidence.CONSERVATIVE,
        )
    if canonical in {
        "shutil.copy",
        "shutil.copy2",
        "shutil.copyfile",
        "shutil.copyfileobj",
        "shutil.copytree",
        "pathlib.path.copy",
    } or leaf in {"copyfilea", "copyfilew"}:
        return WritePrimitiveKind.FILESYSTEM_COPY, "filesystem copy", None
    if leaf == "rename" or (
        leaf == "replace"
        and len(node.args) == 1
        and canonical not in {"dataclasses.replace", "str.replace"}
    ) or canonical in {
        "os.rename",
        "os.replace",
        "shutil.move",
    }:
        if canonical in {"dataclasses.replace", "str.replace"}:
            return None
        return (
            WritePrimitiveKind.FILESYSTEM_MOVE_OR_REPLACE,
            "filesystem move or replacement",
            ResolutionConfidence.CONSERVATIVE,
        )
    if leaf in {
        "movefilea",
        "movefilew",
        "movefileexa",
        "movefileexw",
        "replacefilea",
        "replacefilew",
        "setfileinformationbyhandle",
    }:
        return (
            WritePrimitiveKind.FILESYSTEM_MOVE_OR_REPLACE,
            "Win32 move, replacement, or handle rename primitive",
            ResolutionConfidence.CONSERVATIVE,
        )
    if leaf in {
        "deletefilea",
        "deletefilew",
        "removedirectorya",
        "removedirectoryw",
    }:
        return (
            WritePrimitiveKind.FILESYSTEM_DELETE,
            "Win32 filesystem deletion",
            ResolutionConfidence.CONSERVATIVE,
        )
    if leaf in {
        "createhardlinka",
        "createhardlinkw",
        "createsymboliclinka",
        "createsymboliclinkw",
    }:
        return (
            WritePrimitiveKind.FILESYSTEM_LINK,
            "Win32 filesystem link creation",
            ResolutionConfidence.CONSERVATIVE,
        )
    if leaf in {
        "setfileattributesa",
        "setfileattributesw",
        "setfiletime",
    }:
        return (
            WritePrimitiveKind.FILESYSTEM_METADATA,
            "Win32 filesystem metadata mutation",
            ResolutionConfidence.CONSERVATIVE,
        )
    if leaf in {"unlink", "rmdir"} or canonical in {
        "os.remove",
        "os.unlink",
        "os.rmdir",
        "os.removedirs",
        "shutil.rmtree",
    }:
        return WritePrimitiveKind.FILESYSTEM_DELETE, "filesystem deletion", None
    if leaf in {"symlink_to", "hardlink_to", "link_to"} or canonical in {
        "os.symlink",
        "os.link",
    }:
        return WritePrimitiveKind.FILESYSTEM_LINK, "link creation", None
    if leaf in {"chmod", "chown", "lchmod"} or canonical in {
        "os.chmod",
        "os.chown",
        "os.lchmod",
        "os.utime",
    }:
        return WritePrimitiveKind.FILESYSTEM_METADATA, "filesystem metadata mutation", None
    if canonical.startswith("tempfile.") and leaf in {
        "mkstemp",
        "mkdtemp",
        "namedtemporaryfile",
        "temporaryfile",
        "temporarydirectory",
        "spooledtemporaryfile",
    }:
        return WritePrimitiveKind.TEMPORARY_RESOURCE, "temporary filesystem resource", None
    if canonical in {"shutil.make_archive"} or leaf == "writestr" or (
        leaf == "add" and _looks_like_archive_receiver(canonical)
    ):
        return WritePrimitiveKind.ARCHIVE_WRITE, "archive creation or member add", None
    if canonical in {"shutil.unpack_archive"} or leaf in {"extract", "extractall"}:
        return WritePrimitiveKind.ARCHIVE_EXTRACT, "archive extraction writes files", None
    if canonical in {"zipfile.zipfile", "tarfile.open"} and _archive_open_may_write(node, canonical):
        return WritePrimitiveKind.ARCHIVE_WRITE, "archive opened in write-capable mode", None
    if canonical == "sqlite3.connect":
        return WritePrimitiveKind.SQLITE_RAW_CONNECT, "SQLite connection may create database/sidecars", None
    if leaf == "connect_database":
        return WritePrimitiveKind.DATABASE_GATEWAY, "legacy database gateway", None
    if leaf == "publish_new_file":
        return (
            WritePrimitiveKind.DURABLE_LEDGER_GATEWAY,
            "fixed durable ledger publication gateway",
            ResolutionConfidence.CONSERVATIVE,
        )
    if leaf == "initialize_database":
        return WritePrimitiveKind.DATABASE_IMPLICIT_INITIALIZER, "implicit schema/directory initialization", None
    if leaf in {"execute", "executemany", "executescript"}:
        sql = (
            _constant_text_with_aliases(node.args[0], constants or {})
            if node.args
            else None
        )
        if sql is None:
            return (
                WritePrimitiveKind.SQLITE_DYNAMIC_SQL,
                "dynamic SQL is fail-closed because its effect cannot be proven",
                ResolutionConfidence.DYNAMIC,
            )
        effect, verbs = _sql_effect(sql)
        if effect == "READ":
            return None
        if effect == "DYNAMIC":
            return (
                WritePrimitiveKind.SQLITE_DYNAMIC_SQL,
                "SQL effect cannot be proven read-only",
                ResolutionConfidence.DYNAMIC,
            )
        if effect == "TRANSACTION":
            return WritePrimitiveKind.SQLITE_TRANSACTION, ",".join(verbs), None
        return WritePrimitiveKind.SQLITE_MUTATION, ",".join(verbs), None
    if leaf in {"commit", "rollback"} and _looks_like_database_receiver(canonical):
        return WritePrimitiveKind.SQLITE_TRANSACTION, f"transaction {leaf}", None
    if leaf in {"backup", "deserialize", "load_extension", "enable_load_extension"} and _looks_like_database_receiver(canonical):
        return WritePrimitiveKind.SQLITE_BACKUP_OR_EXTENSION, f"SQLite {leaf}", None
    if canonical in {
        "subprocess.run",
        "subprocess.popen",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.getoutput",
        "subprocess.getstatusoutput",
        "os.system",
        "os.popen",
        "os.startfile",
        "asyncio.create_subprocess_exec",
        "asyncio.create_subprocess_shell",
        "multiprocessing.process",
        "multiprocessing.pool",
        "concurrent.futures.processpoolexecutor",
    } or canonical.startswith(("os.spawn", "os.exec")) or (
        canonical.startswith("multiprocessing.")
        and leaf in {"process", "pool"}
    ) or (
        "processpoolexecutor" in canonical
        and leaf in {"processpoolexecutor", "submit", "map"}
    ) or (
        leaf == "start"
        and any(token in canonical for token in ("multiprocessing", "process()"))
    ):
        return WritePrimitiveKind.EXTERNAL_PROCESS, "external process invocation", None
    if source_leaf != "Request" and (
        canonical in {
        "urllib.request.urlopen",
        "urllib.request.urlretrieve",
        "requests.get",
        "requests.post",
        "requests.put",
        "requests.patch",
        "requests.delete",
        "requests.request",
        "httpx.get",
        "httpx.post",
        "httpx.put",
        "httpx.patch",
        "httpx.delete",
        "socket.create_connection",
        }
        or leaf in {"urlopen", "urlretrieve"}
        or (
        any(token in canonical for token in ("requests", "httpx", "urllib", "socket"))
        and leaf in {
            "request",
            "get",
            "post",
            "put",
            "patch",
            "delete",
            "head",
            "options",
            "connect",
            "create_connection",
        }
        )
        or (
            source_leaf in {"request", "connect", "listen", "send", "sendall"}
            and canonical not in {"sqlite3.connect"}
        )
    ):
        return WritePrimitiveKind.NETWORK_REQUEST, "network request", None
    if canonical == "app.run" or (
        leaf in {"run", "serve", "listen"}
        and any(keyword.arg in {"host", "port"} for keyword in node.keywords)
    ):
        return WritePrimitiveKind.NETWORK_REQUEST, "network listener startup", None
    if canonical.startswith("winreg.") and leaf in {
        "createkey",
        "createkeyex",
        "setvalue",
        "setvalueex",
        "deletekey",
        "deletevalue",
    }:
        return WritePrimitiveKind.SYSTEM_STATE, "Windows registry mutation", None
    if leaf in {
        "assignprocesstojobobject",
        "createjobobjecta",
        "createjobobjectw",
        "openprocess",
        "openthread",
        "resumeprocess",
        "resumethread",
        "setinformationjobobject",
        "terminatejobobject",
        "terminateprocess",
    }:
        return (
            WritePrimitiveKind.EXTERNAL_PROCESS,
            "Win32 process or Job Object control",
            ResolutionConfidence.CONSERVATIVE,
        )
    if leaf in {"createmutexw", "waitforsingleobject", "releasemutex"}:
        return (
            WritePrimitiveKind.RUNTIME_SYNCHRONIZATION,
            "Win32 Local named-mutex synchronization",
            ResolutionConfidence.CONSERVATIVE,
        )
    native_read_only = {
        "byref",
        "cancelioex",
        "c_ulong",
        "c_void_p",
        "closehandle",
        "create_string_buffer",
        "createtoolhelp32snapshot",
        "getfileinformationbyhandle",
        "getfileinformationbyhandleex",
        "getfinalpathnamebyhandlea",
        "getfinalpathnamebyhandlew",
        "getvolumeinformationw",
        "getvolumepathnamew",
        "get_last_error",
        "queryinformationjobobject",
        "readfile",
        "readdirectorychangesw",
        "rtlntstatustodoserror",
        "setfilepointerex",
        "sizeof",
        "thread32first",
        "thread32next",
    }
    native_receiver = any(
        token in canonical
        for token in (
            ".advapi32.",
            ".kernel32.",
            "._ctypes.",
            "._kernel32.",
            ".dlopen().",
            ".ntdll.",
            ".shell32.",
            ".user32.",
        )
    ) or canonical.startswith(
        (
            "advapi32.",
            "ctypes.cdll.",
            "ctypes.cdll().",
            "ctypes.cfunctype().",
            "ctypes.cast().",
            "ctypes.libraryloader().",
            "ctypes.oledll.",
            "ctypes.oledll().",
            "ctypes.pydll.",
            "ctypes.pydll().",
            "ctypes.pythonapi.",
            "ctypes.pyfunctype().",
            "ctypes.windll.",
            "ctypes.windll().",
            "ctypes.winfunctype().",
            "cffi.ffi().dlopen().",
            "ffi.dlopen().",
            "kernel32.",
            "ntdll.",
            "shell32.",
            "user32.",
        )
    )
    if native_receiver and leaf == "ntcreatefile":
        return (
            WritePrimitiveKind.FILESYSTEM_DIRECTORY_CREATE,
            "NtCreateFile may create a relative-parent directory or file",
            ResolutionConfidence.CONSERVATIVE,
        )
    raw_root = _raw_callee_name(node.func).split(".", 1)[0]
    resolved_root = callee.split(".", 1)[0]
    if (
        source_leaf[:1] in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        and (
            (
                raw_root not in {"cls", "self"}
                and raw_root in (parameter_names or set())
            )
            or (
                resolved_root not in {"cls", "self"}
                and resolved_root in (parameter_names or set())
            )
            or callee.startswith(("<ambiguous>.", "<value>."))
        )
    ):
        return (
            WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY,
            "parameter-rooted native-style symbol lacks a proven library identity",
            ResolutionConfidence.DYNAMIC,
        )
    if native_receiver and leaf not in native_read_only:
        return (
            WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY,
            "native API symbol is outside the audited allowlist",
            ResolutionConfidence.DYNAMIC,
        )
    if callee.startswith("<indexed>."):
        if leaf == "start":
            return (
                WritePrimitiveKind.EXTERNAL_PROCESS,
                "unresolved indexed receiver start may launch a process or thread",
                ResolutionConfidence.CONSERVATIVE,
            )
        callsite = _indexed_callsite_key(node, file=file, function=function)
        if allow_audited_indexed and callsite in _AUDITED_INDEXED_CALLS:
            return None
        return (
            WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY,
            "unresolved method on an indexed receiver",
            ResolutionConfidence.DYNAMIC,
        )
    if (
        callee in {"<ambiguous>", "<dynamic>", "<indexed>"}
        or callee.startswith("<dynamic>.")
    ):
        return (
            WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY,
            "unresolved dynamic call",
            ResolutionConfidence.DYNAMIC,
        )
    parameter_name = canonical if canonical in {
        name.casefold() for name in (parameter_names or set())
    } else ""
    if parameter_name:
        callsite = _indexed_callsite_key(node, file=file, function=function)
        if allow_audited_indexed and callsite in _AUDITED_PARAMETER_CALLS:
            return None
        return (
            WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY,
            "direct invocation of a callable parameter is not attributable",
            ResolutionConfidence.DYNAMIC,
        )
    return None


def _scan_sql_files(
    root: Path,
    snapshot: tuple[tuple[Path, bytes], ...] | None = None,
) -> list[_RawEntry]:
    result: list[_RawEntry] = []
    for path, data in snapshot or _production_source_snapshot(root):
        if path.suffix.casefold() != ".sql":
            continue
        relative = path.relative_to(root).as_posix()
        source = data.decode("utf-8")
        source_hash = hashlib.sha256(data).hexdigest()
        for ordinal, match in enumerate(_SQL_PREFIX.finditer(_SQL_COMMENTS.sub("", source)), start=1):
            verb = match.group(1).upper()
            if verb not in _SQL_MUTATION and verb not in _SQL_TRANSACTION:
                continue
            line = source.count("\n", 0, match.start()) + 1
            fingerprint = hashlib.sha256(
                f"{verb}:{ordinal}:{match.start()}".encode("ascii")
            ).hexdigest()
            result.append(
                _RawEntry(
                    file=relative,
                    source_sha256=source_hash,
                    line=line,
                    column=0,
                    end_line=line,
                    end_column=len(verb),
                    function="<sql-script>",
                    kind=(
                        WritePrimitiveKind.SQLITE_TRANSACTION
                        if verb in _SQL_TRANSACTION
                        else WritePrimitiveKind.SQLITE_SCHEMA_MUTATION
                    ),
                    callee=f"SQL:{verb}",
                    resolution=ResolutionConfidence.EXACT,
                    statement_fingerprint=fingerprint,
                    detail=f"schema statement {verb}",
                )
            )
    return result


def _enrich_entries(
    raw_entries: Iterable[_RawEntry],
    graph: dict[str, set[str]],
    roots: dict[str, tuple[str, ...]],
) -> list[WriteEntry]:
    reverse: dict[str, set[str]] = defaultdict(set)
    for caller, callees in graph.items():
        for callee in callees:
            reverse[callee].add(caller)
    result: list[WriteEntry] = []
    ordinal: Counter[tuple[str, str, str, str]] = Counter()
    for raw in raw_entries:
        key = (raw.file, raw.function, raw.kind.value, raw.statement_fingerprint)
        ordinal[key] += 1
        stable_payload = {
            "file": raw.file,
            "function": raw.function,
            "kind": raw.kind.value,
            "callee": raw.callee,
            "fingerprint": raw.statement_fingerprint,
            "ordinal": ordinal[key],
        }
        entry_id = "WE-" + _canonical_sha256(stable_payload)[:24].upper()
        root_ids, chain = _reachable_roots(raw.function, reverse, roots)
        owner = _owner_for(raw.file)
        target = _target_namespace(raw)
        control = _required_control(raw.kind)
        status = _migration_status(raw)
        input_source = _input_source(raw, root_ids)
        risk = _risk_level(raw.kind)
        result.append(
            WriteEntry(
                entry_id=entry_id,
                file=raw.file,
                source_sha256=raw.source_sha256,
                line=raw.line,
                column=raw.column,
                end_line=raw.end_line,
                end_column=raw.end_column,
                function=raw.function,
                kind=raw.kind,
                callee=raw.callee,
                resolution=raw.resolution,
                statement_fingerprint=raw.statement_fingerprint,
                owner=owner,
                target_namespace=target,
                required_control=control,
                migration_status=status,
                input_source=input_source,
                risk=risk,
                root_ids=root_ids,
                call_chain=chain,
                detail=raw.detail,
            )
        )
    return result


def _build_call_graph(
    modules: dict[str, _ModuleFacts],
) -> tuple[dict[str, set[str]], dict[str, tuple[str, ...]]]:
    known = {name for module in modules.values() for name in module.functions}
    graph: dict[str, set[str]] = defaultdict(set)
    roots: dict[str, tuple[str, ...]] = {}
    for module in modules.values():
        for function in module.functions.values():
            roots[function.canonical] = function.root_ids
            local_aliases = dict(module.imports)
            for _ in range(8):
                changed = False
                for assignment in ast.walk(function.node):
                    if not isinstance(assignment, (ast.Assign, ast.AnnAssign)):
                        continue
                    if isinstance(assignment, ast.Assign):
                        targets = assignment.targets
                        value = assignment.value
                    elif assignment.value is not None:
                        targets = [assignment.target]
                        value = assignment.value
                    else:
                        continue
                    resolved, _ = _resolve_callee(value, local_aliases)
                    for target in targets:
                        if isinstance(target, ast.Name) and local_aliases.get(target.id) != resolved:
                            local_aliases[target.id] = resolved
                            changed = True
                if not changed:
                    break
            class_prefix = function.canonical.rsplit(".", 1)[0]
            for node in ast.walk(function.node):
                if isinstance(node, ast.Call):
                    callee, _ = _resolve_callee(node.func, local_aliases)
                    candidates = {callee}
                    if callee.startswith("self."):
                        candidates.add(f"{class_prefix}.{callee[5:]}")
                    if not callee.startswith("app.") and "." not in callee:
                        candidates.add(f"{module.module}.{callee}")
                    for candidate in candidates:
                        if candidate in known:
                            graph[function.canonical].add(candidate)
    return graph, roots


def _reachable_roots(
    function: str,
    reverse: dict[str, set[str]],
    roots: dict[str, tuple[str, ...]],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    if function == "<module>" or function == "<sql-script>":
        return ("MODULE-LOAD",), (function,)
    queue: deque[tuple[str, tuple[str, ...]]] = deque([(function, (function,))])
    visited = {function}
    found: list[tuple[str, tuple[str, ...]]] = []
    while queue and len(visited) <= 5000:
        current, path = queue.popleft()
        for root_id in roots.get(current, ()):
            found.append((root_id, tuple(reversed(path))))
        for parent in sorted(reverse.get(current, ())):
            if parent not in visited:
                visited.add(parent)
                queue.append((parent, path + (parent,)))
    if not found:
        return ("INTERNAL-DIRECT",), (function,)
    found.sort(key=lambda item: (len(item[1]), item[0], item[1]))
    root_ids = tuple(sorted({item[0] for item in found}))
    return root_ids, found[0][1]


def _root_ids(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    file: str,
) -> tuple[str, ...]:
    roots: list[str] = []
    if file == "app/cli.py" and node.name == "main":
        roots.append("CLI:MAIN")
    if file == "app/__main__.py" and node.name == "main":
        roots.append("MODULE:APP")
    if file == "app/web.py" and node.name == "create_app":
        roots.append("FACTORY:CREATE_APP")
    if file.startswith("scripts/") and node.name == "main":
        roots.append(f"SCRIPT:{file}")
    for decorator in node.decorator_list:
        if not isinstance(decorator, ast.Call):
            continue
        leaf = _raw_callee_name(decorator.func).rsplit(".", 1)[-1].upper()
        if leaf not in {"GET", "POST", "PUT", "PATCH", "DELETE", "ROUTE"}:
            continue
        route = _constant_text(decorator.args[0]) if decorator.args else "<dynamic>"
        methods: list[str] = [leaf]
        if leaf == "ROUTE":
            methods = ["ROUTE"]
            for keyword in decorator.keywords:
                if keyword.arg == "methods" and isinstance(keyword.value, (ast.List, ast.Tuple)):
                    methods = [
                        str(item.value).upper()
                        for item in keyword.value.elts
                        if isinstance(item, ast.Constant)
                    ] or methods
        roots.extend(f"WEB:{method} {route}" for method in methods)
    return tuple(sorted(set(roots)))


def _collect_imports(tree: ast.Module, module_name: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                result[alias.asname or alias.name.split(".", 1)[0]] = alias.name
        elif isinstance(node, ast.ImportFrom):
            base = _resolve_import_module(module_name, node.module, node.level)
            for alias in node.names:
                if alias.name != "*":
                    result[alias.asname or alias.name] = f"{base}.{alias.name}"
    return result


def _resolve_import_module(current: str, module: str | None, level: int) -> str:
    if level <= 0:
        return module or ""
    parts = current.split(".")[:-1]
    keep = max(0, len(parts) - (level - 1))
    base = parts[:keep]
    if module:
        base.extend(module.split("."))
    return ".".join(base)


def _resolve_callee(
    node: ast.AST,
    aliases: dict[str, str],
) -> tuple[str, ResolutionConfidence]:
    if isinstance(node, ast.Name):
        resolved = aliases.get(node.id, node.id)
        return (
            resolved,
            ResolutionConfidence.ALIAS_RESOLVED
            if resolved != node.id
            else ResolutionConfidence.EXACT,
        )
    if isinstance(node, ast.Attribute):
        prefix, confidence = _resolve_callee(node.value, aliases)
        direct = f"{prefix}.{node.attr}" if prefix else node.attr
        resolved = aliases.get(direct, direct)
        return (
            resolved,
            ResolutionConfidence.ALIAS_RESOLVED
            if resolved != direct or confidence is ResolutionConfidence.ALIAS_RESOLVED
            else confidence,
        )
    if isinstance(node, ast.Call):
        callee, confidence = _resolve_callee(node.func, aliases)
        if callee.rsplit(".", 1)[-1] == "getattr" and len(node.args) >= 2:
            attr = _constant_text(node.args[1])
            if attr is not None:
                base, _ = _resolve_callee(node.args[0], aliases)
                return f"{base}.{attr}", ResolutionConfidence.ALIAS_RESOLVED
            return "<dynamic>", ResolutionConfidence.DYNAMIC
        return f"{callee}()", confidence
    if isinstance(node, ast.Subscript):
        return "<indexed>", ResolutionConfidence.DYNAMIC
    if isinstance(
        node,
        (
            ast.Constant,
            ast.JoinedStr,
            ast.List,
            ast.Tuple,
            ast.Set,
            ast.Dict,
            ast.BinOp,
            ast.UnaryOp,
            ast.BoolOp,
            ast.Compare,
            ast.IfExp,
            ast.ListComp,
            ast.SetComp,
            ast.DictComp,
            ast.GeneratorExp,
        ),
    ):
        return "<value>", ResolutionConfidence.DYNAMIC
    return "<dynamic>", ResolutionConfidence.DYNAMIC


def _iter_container_expressions(
    node: ast.AST,
    aliases: dict[str, str],
) -> Iterator[ast.AST]:
    """Yield capability-bearing descendants without treating call names as values."""

    yield node
    if isinstance(node, (ast.Name, ast.Constant)):
        return
    if isinstance(node, ast.Attribute):
        resolved, _ = _resolve_callee(node, aliases)
        if resolved.startswith(
            ("<ambiguous>.", "<dynamic>.", "<indexed>.", "<value>.")
        ):
            yield from _iter_container_expressions(node.value, aliases)
        return
    if isinstance(node, ast.Call):
        children: tuple[ast.AST, ...] = ()
    else:
        children = tuple(ast.iter_child_nodes(node))
    for child in children:
        if isinstance(child, ast.expr):
            yield from _iter_container_expressions(child, aliases)


def _expression_can_hide_capability(node: ast.AST) -> bool:
    return isinstance(
        node,
        (
            ast.BoolOp,
            ast.Dict,
            ast.DictComp,
            ast.GeneratorExp,
            ast.IfExp,
            ast.List,
            ast.ListComp,
            ast.Set,
            ast.SetComp,
            ast.Subscript,
            ast.Tuple,
        ),
    )


def _stored_capability_reference(
    node: ast.AST,
    aliases: dict[str, str],
    *,
    include_native_call_results: bool = False,
) -> str | None:
    for candidate in _iter_container_expressions(node, aliases):
        resolved, _ = _resolve_callee(candidate, aliases)
        canonical = resolved.casefold()
        if isinstance(candidate, ast.Call):
            if (
                include_native_call_results
                and _is_native_escaping_result(canonical)
            ):
                return resolved
            continue
        if canonical.endswith("()"):
            if (
                include_native_call_results
                and _is_native_escaping_result(canonical)
            ):
                return resolved
            continue
        if (
            canonical in _RISKY_CAPABILITY_REFERENCES
            or canonical in _CAPABILITY_NAMESPACE_REFERENCES
            or canonical == "ctypes._cfuncptr"
            or canonical.startswith(_NATIVE_CAPABILITY_PREFIXES)
        ):
            return resolved
    return None


def _is_native_escaping_result(canonical: str) -> bool:
    return canonical in _NATIVE_ESCAPING_RESULTS or canonical.startswith(
        (
            "ctypes.cfunctype()()",
            "ctypes.pyfunctype()()",
            "ctypes.winfunctype()()",
        )
    )


def _is_reflective_capability_source(canonical: str) -> bool:
    normalized = canonical.casefold()
    return (
        normalized in {"ctypes", "_ctypes", "sys.modules"}
        or normalized.startswith((*_NATIVE_CAPABILITY_PREFIXES, "sys.modules."))
        or any(
            token in normalized
            for token in (
                ".advapi32",
                ".kernel32",
                ".ntdll",
                ".shell32",
                ".user32",
            )
        )
    )


def _raw_callee_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _raw_callee_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return "<dynamic>"


def _module_name(file: str) -> str:
    path = Path(file)
    parts = list(path.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts) or "synthetic"


def _parents(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    result: dict[ast.AST, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            result[child] = parent
    return result


def _assigned_names(node: ast.AST) -> set[str]:
    names: set[str] = set()
    for candidate in ast.walk(node):
        if isinstance(candidate, ast.Name) and isinstance(candidate.ctx, ast.Store):
            names.add(candidate.id)
    return names


def _pattern_bound_names(pattern: ast.pattern) -> set[str]:
    names: set[str] = set()
    if isinstance(pattern, ast.MatchAs):
        if pattern.name is not None:
            names.add(pattern.name)
        if pattern.pattern is not None:
            names.update(_pattern_bound_names(pattern.pattern))
    elif isinstance(pattern, ast.MatchStar):
        if pattern.name is not None:
            names.add(pattern.name)
    elif isinstance(pattern, ast.MatchMapping):
        if pattern.rest is not None:
            names.add(pattern.rest)
        for child in pattern.patterns:
            names.update(_pattern_bound_names(child))
    elif isinstance(pattern, ast.MatchClass):
        for child in (*pattern.patterns, *pattern.kwd_patterns):
            names.update(_pattern_bound_names(child))
    elif isinstance(pattern, (ast.MatchSequence, ast.MatchOr)):
        for child in pattern.patterns:
            names.update(_pattern_bound_names(child))
    return names


def _enclosing_function_qualname(
    node: ast.AST,
    parents: dict[ast.AST, ast.AST],
) -> str:
    current = node
    while current in parents:
        current = parents[current]
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return _qualname(current, parents)
    return "<module>"


def _qualname(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> str:
    names: list[str] = [getattr(node, "name", "<anonymous>")]
    current = node
    while current in parents:
        current = parents[current]
        if isinstance(current, ast.ClassDef):
            names.append(current.name)
        elif isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            names.append(current.name)
    return ".".join(reversed(names))


def _constant_text(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        if all(isinstance(value, ast.Constant) for value in node.values):
            return "".join(str(value.value) for value in node.values if isinstance(value, ast.Constant))
        return None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _constant_text(node.left)
        right = _constant_text(node.right)
        return left + right if left is not None and right is not None else None
    return None


def _constant_text_with_aliases(
    node: ast.AST,
    constants: dict[str, str],
) -> str | None:
    if isinstance(node, ast.Name):
        return constants.get(node.id)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _constant_text_with_aliases(node.left, constants)
        right = _constant_text_with_aliases(node.right, constants)
        return left + right if left is not None and right is not None else None
    return _constant_text(node)


def _open_call_may_write(node: ast.Call, callee: str) -> bool:
    mode_index = 1 if callee in {"open", "builtins.open", "io.fileio", "io.open"} else 0
    mode_node: ast.AST | None = node.args[mode_index] if len(node.args) > mode_index else None
    for keyword in node.keywords:
        if keyword.arg == "mode":
            mode_node = keyword.value
    if mode_node is None:
        return False
    mode = _constant_text(mode_node)
    return True if mode is None else any(flag in mode for flag in "wax+")


def _os_open_may_write(node: ast.Call) -> bool:
    if len(node.args) < 2:
        return True
    flags = node.args[1]
    if isinstance(flags, ast.Constant) and isinstance(flags.value, int):
        return flags.value != 0
    text = ast.dump(flags, include_attributes=False).upper()
    write_markers = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND", "O_EXCL")
    if any(marker in text for marker in write_markers):
        return True
    return "O_RDONLY" not in text


def _archive_open_may_write(node: ast.Call, callee: str) -> bool:
    mode_index = 1 if callee == "zipfile.zipfile" else 1
    mode_node: ast.AST | None = node.args[mode_index] if len(node.args) > mode_index else None
    for keyword in node.keywords:
        if keyword.arg == "mode":
            mode_node = keyword.value
    if mode_node is None:
        return False
    mode = _constant_text(mode_node)
    return True if mode is None else any(flag in mode for flag in "wax")


def _archive_member_open_may_write(node: ast.Call) -> bool:
    mode_node: ast.AST | None = node.args[1] if len(node.args) > 1 else None
    for keyword in node.keywords:
        if keyword.arg == "mode":
            mode_node = keyword.value
    if mode_node is None:
        return False
    mode = _constant_text(mode_node)
    return True if mode is None else any(flag in mode for flag in "wax+")


def _is_file_open_symbol(callee: str) -> bool:
    return callee in {"open", "builtins.open", "io.fileio", "io.open", "path.open", "pathlib.path.open"} or (
        callee.endswith(".open")
        and not any(
            token in callee
            for token in (
                "fitz.",
                "pymupdf.",
                "urllib.",
                "webbrowser.",
                "tarfile.",
                "zipfile.",
                "archive",
            )
        )
    )


def _looks_like_archive_receiver(callee: str) -> bool:
    receiver = callee.rsplit(".", 1)[0]
    receiver_leaf = receiver.rsplit(".", 1)[-1]
    return any(token in callee for token in ("zip", "tar", "archive")) or receiver_leaf in {
        "zf",
        "tf",
    }


def _looks_like_path_receiver(callee: str) -> bool:
    receiver = callee.rsplit(".", 1)[0]
    leaf = receiver.rsplit(".", 1)[-1]
    return receiver.startswith(("pathlib.path", "path()")) or leaf.endswith(
        (
            "path",
            "file",
            "target",
            "source",
            "output",
            "candidate",
            "partial",
            "staging",
            "temp",
            "tmp",
        )
    )


def _looks_like_database_receiver(callee: str) -> bool:
    receiver = callee.rsplit(".", 1)[0]
    return any(token in receiver for token in ("conn", "connection", "cursor", "sqlite", ".db", "database"))


def _looks_like_sql_call(node: ast.Call, callee: str) -> bool:
    return callee.rsplit(".", 1)[-1] in {
        "execute",
        "executemany",
        "executescript",
    }


def _sql_effect(sql: str) -> tuple[str, tuple[str, ...]]:
    verbs = _sql_statement_verbs(sql)
    if not verbs:
        return "DYNAMIC", ()
    known = _SQL_MUTATION | _SQL_TRANSACTION | {"SELECT", "EXPLAIN"}
    if any(verb not in known for verb in verbs):
        return "DYNAMIC", verbs
    if any(verb in _SQL_MUTATION for verb in verbs):
        return "MUTATION", verbs
    if any(verb in _SQL_TRANSACTION for verb in verbs):
        return "TRANSACTION", verbs
    return "READ", verbs


def _sql_statement_verbs(sql: str) -> tuple[str, ...]:
    cleaned = _strip_sql_literals_and_comments(sql)
    verbs: list[str] = []
    for statement in cleaned.split(";"):
        tokens = re.findall(r"[A-Za-z_]+|[()]", statement)
        if not tokens:
            continue
        upper = [token.upper() for token in tokens]
        index = 0
        if upper[index] == "EXPLAIN":
            index += 1
            if index + 1 < len(upper) and upper[index : index + 2] == ["QUERY", "PLAN"]:
                index += 2
        if index >= len(upper):
            continue
        if upper[index] != "WITH":
            verbs.append(upper[index])
            continue
        index += 1
        if index < len(upper) and upper[index] == "RECURSIVE":
            index += 1
        depth = 0
        main_verb: str | None = None
        while index < len(upper):
            token = upper[index]
            if token == "(":
                depth += 1
            elif token == ")":
                depth = max(0, depth - 1)
            elif depth == 0 and token in {
                "SELECT",
                "INSERT",
                "UPDATE",
                "DELETE",
                "REPLACE",
            }:
                main_verb = token
                break
            index += 1
        verbs.append(main_verb or "WITH")
    return tuple(verbs)


def _strip_sql_literals_and_comments(sql: str) -> str:
    output: list[str] = []
    index = 0
    quote: str | None = None
    while index < len(sql):
        char = sql[index]
        next_char = sql[index + 1] if index + 1 < len(sql) else ""
        if quote is not None:
            if quote == "]":
                if char == "]":
                    quote = None
                output.append(" ")
                index += 1
                continue
            if char == quote:
                if next_char == quote:
                    output.extend((" ", " "))
                    index += 2
                    continue
                quote = None
            output.append(" ")
            index += 1
            continue
        if char == "-" and next_char == "-":
            while index < len(sql) and sql[index] not in "\r\n":
                output.append(" ")
                index += 1
            continue
        if char == "/" and next_char == "*":
            output.extend((" ", " "))
            index += 2
            while index < len(sql):
                if sql[index] == "*" and index + 1 < len(sql) and sql[index + 1] == "/":
                    output.extend((" ", " "))
                    index += 2
                    break
                output.append(" ")
                index += 1
            continue
        if char in {"'", '"', "`"}:
            quote = char
            output.append(" ")
            index += 1
            continue
        if char == "[":
            quote = "]"
            output.append(" ")
            index += 1
            continue
        output.append(char)
        index += 1
    return "".join(output)


def _owner_for(file: str) -> str:
    name = Path(file).name
    if file.startswith("scripts/"):
        return "TEST_INFRASTRUCTURE"
    if file.startswith("app/safety/") or name == "workspace_guard.py":
        return "SAFETY_SERVICE"
    if name in {"database.py", "search_index.py"}:
        return "DATABASE_SERVICE"
    if any(token in name for token in ("import", "question_split", "question_assets", "pdf_scan")):
        return "IMPORT_SERVICE"
    if any(token in name for token in ("export", "render")):
        return "EXPORT_SERVICE"
    if "report" in name or name.startswith("stage"):
        return "REPORT_SERVICE"
    if name == "web.py":
        return "WEB_ADAPTER"
    if name == "cli.py":
        return "CLI_ADAPTER"
    if name == "health.py":
        return "HEALTH_SERVICE"
    return "APPLICATION_SERVICE"


def _target_namespace(raw: _RawEntry) -> str:
    if _migration_status(raw) is MigrationStatus.ACCEPTED_MEMORY_ONLY:
        return "MEMORY_ONLY"
    if raw.file.startswith("scripts/"):
        return "TEST_LAB_RUNTIME"
    if raw.kind in {
        WritePrimitiveKind.SQLITE_RAW_CONNECT,
        WritePrimitiveKind.DATABASE_GATEWAY,
        WritePrimitiveKind.DATABASE_IMPLICIT_INITIALIZER,
        WritePrimitiveKind.SQLITE_MUTATION,
        WritePrimitiveKind.SQLITE_DYNAMIC_SQL,
        WritePrimitiveKind.SQLITE_TRANSACTION,
        WritePrimitiveKind.SQLITE_BACKUP_OR_EXTENSION,
        WritePrimitiveKind.SQLITE_SCHEMA_MUTATION,
    }:
        return "LEGACY_CALLER_CONTROLLED_DATABASE_PATH"
    if raw.kind is WritePrimitiveKind.NETWORK_REQUEST:
        return "NETWORK_DEFAULT_DENY"
    if raw.kind is WritePrimitiveKind.EXTERNAL_PROCESS:
        return "PROCESS_DEFAULT_DENY"
    if raw.kind is WritePrimitiveKind.SYSTEM_STATE:
        return "SYSTEM_STATE_DEFAULT_DENY"
    if raw.kind is WritePrimitiveKind.RUNTIME_SYNCHRONIZATION:
        return "WINDOWS_LOCAL_NAMED_MUTEX"
    if raw.kind is WritePrimitiveKind.DURABLE_LEDGER_GATEWAY:
        return "FIXED_DURABLE_LEDGER_STORE"
    if raw.kind is WritePrimitiveKind.NATIVE_API_BINDING:
        return "NATIVE_API_FIXED_LIBRARY_AND_SYMBOL_ALLOWLIST"
    if raw.kind is WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY:
        return "UNRESOLVED_DYNAMIC_TARGET"
    return "LEGACY_CALLER_CONTROLLED_FILESYSTEM"


def _required_control(kind: WritePrimitiveKind) -> str:
    if kind in {
        WritePrimitiveKind.SQLITE_RAW_CONNECT,
        WritePrimitiveKind.DATABASE_GATEWAY,
        WritePrimitiveKind.DATABASE_IMPLICIT_INITIALIZER,
        WritePrimitiveKind.SQLITE_MUTATION,
        WritePrimitiveKind.SQLITE_DYNAMIC_SQL,
        WritePrimitiveKind.SQLITE_TRANSACTION,
        WritePrimitiveKind.SQLITE_BACKUP_OR_EXTENSION,
        WritePrimitiveKind.SQLITE_SCHEMA_MUTATION,
    }:
        return "S3_DATABASE_LEASE_AND_TRANSACTION_GATE"
    if kind is WritePrimitiveKind.NETWORK_REQUEST:
        return "S3_NETWORK_DEFAULT_DENY_LOOPBACK_ALLOWLIST"
    if kind is WritePrimitiveKind.EXTERNAL_PROCESS:
        return "S3_CONTROLLED_PROCESS_WRAPPER"
    if kind is WritePrimitiveKind.RUNTIME_SYNCHRONIZATION:
        return "S3_FIXED_CONTRACT_ROOT_RUNTIME_MUTEX"
    if kind is WritePrimitiveKind.DURABLE_LEDGER_GATEWAY:
        return "S3_FIXED_FACTORY_HANDLE_PUBLISH_AND_CHAIN_VALIDATION"
    if kind in {WritePrimitiveKind.ARCHIVE_WRITE, WritePrimitiveKind.ARCHIVE_EXTRACT}:
        return "S3_ARCHIVE_MANIFEST_AND_ZIP_SLIP_GATE"
    if kind in {WritePrimitiveKind.FILESYSTEM_DELETE, WritePrimitiveKind.FILESYSTEM_MOVE_OR_REPLACE}:
        return "S3_PAIRED_QUARANTINE_OR_ATOMIC_PUBLISH_WRITER"
    if kind is WritePrimitiveKind.FILESYSTEM_LINK:
        return "PERMANENT_LINK_CREATION_DENY"
    if kind is WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY:
        return "P0_RESOLVE_OR_REMOVE_DYNAMIC_CAPABILITY"
    if kind is WritePrimitiveKind.SYSTEM_STATE:
        return "D3_USER_DECISION_SYSTEM_MUTATION"
    if kind is WritePrimitiveKind.NATIVE_API_BINDING:
        return "S3_NATIVE_API_FIXED_LIBRARY_AND_SYMBOL_ALLOWLIST"
    return "S3_HANDLE_LEVEL_WORKSPACE_WRITER"


def _migration_status(raw: _RawEntry) -> MigrationStatus:
    return MigrationStatus.UNMIGRATED_BLOCKED


def _input_source(raw: _RawEntry, roots: tuple[str, ...]) -> str:
    if any(root.startswith("WEB:") for root in roots):
        return "HTTP_REQUEST_OR_SERVICE_STATE"
    if any(root.startswith("CLI:") for root in roots):
        return "CLI_ARGUMENT_OR_CONFIG"
    if raw.kind in {
        WritePrimitiveKind.SQLITE_MUTATION,
        WritePrimitiveKind.SQLITE_DYNAMIC_SQL,
        WritePrimitiveKind.SQLITE_TRANSACTION,
    }:
        return "DATABASE_CONNECTION_AND_CALLER_DATA"
    if raw.function == "<module>" or raw.function == "<sql-script>":
        return "STATIC_SOURCE_DECLARATION"
    return "CALLER_ARGUMENT_OR_INTERNAL_DERIVATION"


def _risk_level(kind: WritePrimitiveKind) -> RiskLevel:
    if kind in {
        WritePrimitiveKind.FILESYSTEM_DELETE,
        WritePrimitiveKind.FILESYSTEM_MOVE_OR_REPLACE,
        WritePrimitiveKind.FILESYSTEM_LINK,
        WritePrimitiveKind.ARCHIVE_EXTRACT,
        WritePrimitiveKind.SQLITE_DYNAMIC_SQL,
        WritePrimitiveKind.SQLITE_BACKUP_OR_EXTENSION,
        WritePrimitiveKind.EXTERNAL_PROCESS,
        WritePrimitiveKind.NETWORK_REQUEST,
        WritePrimitiveKind.SYSTEM_STATE,
        WritePrimitiveKind.DURABLE_LEDGER_GATEWAY,
        WritePrimitiveKind.NATIVE_API_BINDING,
        WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY,
    }:
        return RiskLevel.P0
    return RiskLevel.P1


def _canonical_sha256(payload: Any) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _pretty_json_bytes(payload: Any) -> bytes:
    return (
        json.dumps(
            payload,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
