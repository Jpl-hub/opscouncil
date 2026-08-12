from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from sqlalchemy import delete, func, or_, select
from sqlalchemy.orm import Session

from backend.app.ai.client import BailianClient, model_invocation_scope
from backend.app.knowledge.chunking import split_document
from backend.app.knowledge.retrieval import (
    HybridKnowledgeRetriever,
    KnowledgeHit,
    KnowledgeRetrievalUnavailableError,
    tokenize_for_search,
)
from backend.app.models.entities import KnowledgeChunk, KnowledgeDocument
from backend.app.safety.content import scan_untrusted_content


class KnowledgeIngestionRejectedError(ValueError):
    pass


@dataclass(frozen=True)
class BuiltinKnowledgeDocument:
    title: str
    source_type: str
    source_uri: str
    trust_level: str
    content: str


class KnowledgeService:
    def __init__(self, session: Session, model_client: BailianClient | None = None) -> None:
        self.session = session
        self.model_client = model_client or BailianClient()
        self.retriever = HybridKnowledgeRetriever(session, self.model_client)

    def ingest_document(
        self,
        title: str,
        source_type: str,
        source_uri: str,
        content: str,
        trust_level: str = "internal",
    ) -> KnowledgeDocument:
        normalized = _normalize_content(content)
        assert_knowledge_content_safe(normalized)
        content_hash = _sha256(normalized)
        existing = self.session.execute(
            select(KnowledgeDocument).where(KnowledgeDocument.content_hash == content_hash)
        ).scalar_one_or_none()
        if existing is not None:
            self.ensure_document_index(
                existing,
                title=title,
                source_uri=source_uri,
                trust_level=trust_level,
                source_type=source_type,
                content=normalized,
            )
            return existing

        chunks = split_document(normalized, source_type)
        with model_invocation_scope(self.model_client, "knowledge_index_embedding"):
            embeddings = self.model_client.embed([chunk.content for chunk in chunks])
        document = KnowledgeDocument(
            title=title,
            source_type=source_type,
            source_uri=source_uri,
            trust_level=trust_level,
            content_hash=content_hash,
            version=1,
            status="ACTIVE",
        )
        self.session.add(document)
        self.session.flush()

        for index, chunk in enumerate(chunks):
            self.session.add(
                KnowledgeChunk(
                    document_id=document.id,
                    chunk_index=index,
                    content=chunk.content,
                    search_text=tokenize_for_search(chunk.content),
                    chunk_kind=chunk.kind,
                    embedding=embeddings[index],
                    metadata_json={"title": title, "source_uri": source_uri, "trust_level": trust_level},
                    content_hash=_sha256(f"{content_hash}:{index}:{chunk.content}"),
                )
            )
        self.session.flush()
        return document

    def ensure_document_index(
        self,
        document: KnowledgeDocument,
        *,
        title: str,
        source_uri: str,
        trust_level: str,
        source_type: str,
        content: str,
    ) -> int:
        chunks = list(
            self.session.execute(
                select(KnowledgeChunk)
                .where(KnowledgeChunk.document_id == document.id)
                .order_by(KnowledgeChunk.chunk_index.asc())
            ).scalars()
        )
        if not chunks:
            split_chunks = split_document(content, source_type)
            with model_invocation_scope(self.model_client, "knowledge_index_embedding"):
                embeddings = self.model_client.embed([chunk.content for chunk in split_chunks])
            for index, chunk in enumerate(split_chunks):
                self.session.add(
                    KnowledgeChunk(
                        document_id=document.id,
                        chunk_index=index,
                        content=chunk.content,
                        search_text=tokenize_for_search(chunk.content),
                        chunk_kind=chunk.kind,
                        embedding=embeddings[index],
                        metadata_json={"title": title, "source_uri": source_uri, "trust_level": trust_level},
                        content_hash=_sha256(f"{document.content_hash}:{index}:{chunk.content}"),
                    )
                )
            self.session.flush()
            return len(split_chunks)

        missing_embeddings = [chunk for chunk in chunks if chunk.embedding is None]
        with model_invocation_scope(self.model_client, "knowledge_index_embedding"):
            embeddings = self.model_client.embed([chunk.content for chunk in missing_embeddings])
        embedding_by_id = {
            chunk.id: embedding
            for chunk, embedding in zip(missing_embeddings, embeddings, strict=True)
        }
        repaired = 0
        for chunk in chunks:
            changed = False
            if chunk.id in embedding_by_id:
                chunk.embedding = embedding_by_id[chunk.id]
                changed = True
            if not getattr(chunk, "search_text", ""):
                chunk.search_text = tokenize_for_search(chunk.content)
                changed = True
            if not getattr(chunk, "chunk_kind", ""):
                chunk.chunk_kind = "content"
                changed = True
            if not changed:
                continue
            chunk.metadata_json = {
                **(chunk.metadata_json or {}),
                "title": title,
                "source_uri": source_uri,
                "trust_level": trust_level,
            }
            repaired += 1
        self.session.flush()
        return repaired

    def seed_builtin_documents(self) -> list[KnowledgeDocument]:
        return [
            self.upsert_builtin_document(document)
            for document in BUILTIN_KNOWLEDGE_DOCUMENTS
        ]

    def upsert_builtin_document(self, specification: BuiltinKnowledgeDocument) -> KnowledgeDocument:
        normalized = _normalize_content(specification.content)
        assert_knowledge_content_safe(normalized)
        content_hash = _sha256(normalized)
        existing = self.session.execute(
            select(KnowledgeDocument)
            .where(KnowledgeDocument.source_uri == specification.source_uri)
            .order_by(KnowledgeDocument.id.desc())
            .limit(1)
        ).scalar_one_or_none()
        if existing is None:
            return self.ingest_document(
                title=specification.title,
                source_type=specification.source_type,
                source_uri=specification.source_uri,
                content=normalized,
                trust_level=specification.trust_level,
            )
        if existing.content_hash == content_hash:
            self.ensure_document_index(
                existing,
                title=specification.title,
                source_uri=specification.source_uri,
                trust_level=specification.trust_level,
                source_type=specification.source_type,
                content=normalized,
            )
            return existing

        chunks = split_document(normalized, specification.source_type)
        with model_invocation_scope(self.model_client, "knowledge_index_embedding"):
            embeddings = self.model_client.embed([chunk.content for chunk in chunks])
        self.session.execute(
            delete(KnowledgeChunk).where(KnowledgeChunk.document_id == existing.id)
        )
        existing.title = specification.title
        existing.source_type = specification.source_type
        existing.trust_level = specification.trust_level
        existing.content_hash = content_hash
        existing.version = int(existing.version or 1) + 1
        existing.status = "ACTIVE"
        for index, chunk in enumerate(chunks):
            self.session.add(
                KnowledgeChunk(
                    document_id=existing.id,
                    chunk_index=index,
                    content=chunk.content,
                    search_text=tokenize_for_search(chunk.content),
                    chunk_kind=chunk.kind,
                    embedding=embeddings[index],
                    metadata_json={
                        "title": specification.title,
                        "source_uri": specification.source_uri,
                        "trust_level": specification.trust_level,
                        "document_version": existing.version,
                    },
                    content_hash=_sha256(f"{content_hash}:{index}:{chunk.content}"),
                )
            )
        self.session.flush()
        return existing

    def delete_document(self, document_id: int) -> int:
        document = self.session.get(KnowledgeDocument, document_id)
        if document is None:
            raise LookupError("knowledge document not found")
        chunk_count = self.session.scalar(
            select(func.count(KnowledgeChunk.id)).where(KnowledgeChunk.document_id == document_id)
        ) or 0
        self.session.execute(delete(KnowledgeChunk).where(KnowledgeChunk.document_id == document_id))
        self.session.delete(document)
        self.session.flush()
        return int(chunk_count)

    def index_status(self) -> dict[str, int | bool]:
        document_count = self.session.scalar(select(func.count(KnowledgeDocument.id))) or 0
        active_document_count = (
            self.session.scalar(
                select(func.count(KnowledgeDocument.id)).where(KnowledgeDocument.status == "ACTIVE")
            )
            or 0
        )
        active_chunks = (
            select(KnowledgeChunk.id)
            .join(KnowledgeDocument, KnowledgeDocument.id == KnowledgeChunk.document_id)
            .where(KnowledgeDocument.status == "ACTIVE")
            .subquery()
        )
        chunk_count = self.session.scalar(select(func.count()).select_from(active_chunks)) or 0
        indexed_chunk_count = (
            self.session.scalar(
                select(func.count(KnowledgeChunk.id))
                .join(KnowledgeDocument, KnowledgeDocument.id == KnowledgeChunk.document_id)
                .where(
                    KnowledgeDocument.status == "ACTIVE",
                    KnowledgeChunk.embedding.is_not(None),
                )
            )
            or 0
        )
        lexical_chunk_count = (
            self.session.scalar(
                select(func.count(KnowledgeChunk.id))
                .join(KnowledgeDocument, KnowledgeDocument.id == KnowledgeChunk.document_id)
                .where(
                    KnowledgeDocument.status == "ACTIVE",
                    KnowledgeChunk.search_text != "",
                )
            )
            or 0
        )
        missing_embedding_count = max(0, int(chunk_count) - int(indexed_chunk_count))
        missing_lexical_count = max(0, int(chunk_count) - int(lexical_chunk_count))
        return {
            "document_count": int(document_count),
            "active_document_count": int(active_document_count),
            "chunk_count": int(chunk_count),
            "indexed_chunk_count": int(indexed_chunk_count),
            "lexical_chunk_count": int(lexical_chunk_count),
            "missing_embedding_count": missing_embedding_count,
            "missing_lexical_count": missing_lexical_count,
            "ready": (
                int(active_document_count) > 0
                and int(chunk_count) > 0
                and missing_embedding_count == 0
                and missing_lexical_count == 0
            ),
        }

    def rebuild_missing_embeddings(self, limit: int = 100) -> int:
        chunks = list(
            self.session.execute(
                select(KnowledgeChunk)
                .where(
                    or_(
                        KnowledgeChunk.embedding.is_(None),
                        KnowledgeChunk.search_text == "",
                    )
                )
                .order_by(KnowledgeChunk.id.asc())
                .limit(max(1, limit))
            ).scalars()
        )
        if not chunks:
            return 0
        missing_embeddings = [chunk for chunk in chunks if chunk.embedding is None]
        embeddings = self.model_client.embed([chunk.content for chunk in missing_embeddings])
        embedding_by_id = {
            chunk.id: embedding
            for chunk, embedding in zip(missing_embeddings, embeddings, strict=True)
        }
        for chunk in chunks:
            if chunk.id in embedding_by_id:
                chunk.embedding = embedding_by_id[chunk.id]
            if not chunk.search_text:
                chunk.search_text = tokenize_for_search(chunk.content)
        self.session.flush()
        return len(chunks)

    def search(self, query: str, limit: int = 5) -> list[KnowledgeHit]:
        return self.retriever.search(query, limit=limit)


def _normalize_content(content: str) -> str:
    return re.sub(r"\n{3,}", "\n\n", content.strip())


def _detect_prompt_injection(content: str) -> list[str]:
    return [threat.label for threat in scan_untrusted_content(content)]


def assert_knowledge_content_safe(content: str) -> None:
    injection_hits = _detect_prompt_injection(content)
    if injection_hits:
        raise KnowledgeIngestionRejectedError(
            "知识内容疑似包含提示词注入，已拒绝入库：" + "、".join(injection_hits)
        )


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


BUILTIN_KNOWLEDGE_DOCUMENTS: tuple[BuiltinKnowledgeDocument, ...] = (
    BuiltinKnowledgeDocument(
        title="日志文件安全轮转规范",
        source_type="runbook",
        source_uri="builtin://ops/log-rotation",
        trust_level="verified",
        content=(
            "适用场景：/var/log、/tmp 或应用日志目录出现大文件，导致根分区、日志分区或临时目录容量压力。"
            "处置前必须确认文件类型、进程占用、最近写入时间、所属服务和业务影响。"
            "禁止删除数据库事务日志、审计日志、systemd-journald 活跃目录、包管理数据库和未知二进制文件。"
            "\n\n"
            "推荐流程：先执行只读容量分析和大文件定位；对候选日志执行 lsof 或等价句柄检查；"
            "若文件属于允许边界，优先采用复制备份、压缩归档、截断源文件的可逆轮转方式。"
            "轮转动作必须保留备份路径、释放空间、操作者和审批记录。"
            "\n\n"
            "回滚要求：如果服务异常或日志仍被业务依赖，应从备份恢复原文件内容，保留执行前后校验结果。"
            "任何 rm、递归删除或跨目录清理请求都必须被安全护栏重新评估。"
        ),
    ),
    BuiltinKnowledgeDocument(
        title="关键配置漂移核验规范",
        source_type="policy",
        source_uri="builtin://ops/config-drift",
        trust_level="verified",
        content=(
            "适用对象：/etc/hosts、/etc/resolv.conf、/etc/fstab、sshd 配置、系统服务单元和受控应用配置。"
            "配置漂移核验默认只采集路径存在性、权限、属主、大小、mtime 和 SHA256 摘要，不读取敏感正文。"
            "\n\n"
            "判断规则：文件不存在、权限放大、属主异常、哈希变化或时间戳异常都应形成漂移线索；"
            "不得直接覆盖配置正文。需要结合变更单、发布时间、服务状态和最近日志确认影响。"
            "\n\n"
            "权限恢复只适用于管理员明确请求、目标进入精确白名单、当前完整 SHA256 与已确认基线一致、"
            "UID/GID 未变化且目标为普通文件的场景。目标权限仅允许 0600、0640 或 0644；先执行 dry-run，"
            "再以 R3 风险进入人工审批，执行前后分别由独立配置扫描核验权限、属主和内容哈希。"
            "内容哈希或属主发生变化、目标为符号链接、路径敏感或基线不完整时只能报告并转人工，不得自动修复。"
            "涉及正文写入、属主修改、回滚、重载服务或重启服务时必须进入独立处置流程。"
            "配置正文、私钥、口令、token 和证书私密内容不得写入模型上下文或前端摘要。"
        ),
    ),
    BuiltinKnowledgeDocument(
        title="网络暴露面排查规范",
        source_type="runbook",
        source_uri="builtin://ops/network-exposure",
        trust_level="verified",
        content=(
            "排查目标：识别 TCP/UDP 监听端口、绑定地址、协议、进程归属和暴露范围。"
            "绑定 0.0.0.0、:: 或非回环地址的监听服务需要优先核查；仅绑定 127.0.0.1 的服务通常风险较低，"
            "但仍需结合代理、端口转发和容器网络判断。"
            "\n\n"
            "排查流程：先采集主机快照，再采集监听端口和进程信息；对未知进程记录 PID、命令名、用户和启动时间。"
            "不要自动关闭端口、修改防火墙或停止服务。"
            "\n\n"
            "建议输出：按端口列出暴露范围、进程线索、风险等级和下一步核查项。"
            "涉及防火墙变更、服务停止、配置修改时必须进入审批和受限执行。"
        ),
    ),
    BuiltinKnowledgeDocument(
        title="服务异常与日志根因排查规范",
        source_type="runbook",
        source_uri="builtin://ops/service-log-triage",
        trust_level="verified",
        content=(
            "适用场景：服务启动失败、频繁重启、系统日志出现错误、CPU 或内存异常升高。"
            "根因排查应优先使用只读方式采集 systemd 状态、最近 journal 日志、进程资源占用和系统负载。"
            "\n\n"
            "判断线索：failed 单元、exit code、OOM、权限拒绝、端口占用、配置解析失败和磁盘写满都属于高价值线索。"
            "摘要应给出证据来源和时间窗口，避免把大量日志原文直接推给用户。"
            "\n\n"
            "处置边界：重启服务、清理文件、变更配置、kill 进程都属于副作用动作，必须经安全校验和人工审批。"
            "如果证据不足，应建议继续采集指定服务日志，而不是直接执行修复。"
        ),
    ),
    BuiltinKnowledgeDocument(
        title="受限执行与最小权限规范",
        source_type="policy",
        source_uri="builtin://ops/least-privilege",
        trust_level="verified",
        content=(
            "Agent 默认应以只读感知为主，最小化系统权限、文件范围和命令能力。"
            "感知类工具可以读取系统状态、进程摘要、端口摘要和文件元数据；副作用工具只允许处理明确白名单路径和白名单动作。"
            "\n\n"
            "高风险动作包括递归删除、chmod 777、变更 root 属主、格式化磁盘、直接写块设备、关闭安全服务、绕开审批和导出敏感凭据。"
            "这些请求应由安全护栏拒绝或升级到人工复核，不能交给模型自行决定。"
            "\n\n"
            "审计要求：每个任务都要记录接收指令、环境感知、模型意图、计划、工具调用、安全校验、执行结果和封存哈希。"
            "出现异常时应能回放链路并证明未越权执行。"
        ),
    ),
    BuiltinKnowledgeDocument(
        title="SSH 暴露面收敛规范",
        source_type="runbook",
        source_uri="builtin://ops/ssh-exposure",
        trust_level="verified",
        content=(
            "适用场景：发现 sshd 监听在 0.0.0.0、:: 或生产网段，或出现弱口令、异常登录、暴力破解告警。"
            "Agent 可采集监听端口、sshd 服务状态、最近认证失败摘要和防火墙只读状态，但不得直接关闭 SSH 或改写配置。"
            "\n\n"
            "核查要点：确认业务入口、堡垒机策略、允许登录用户、PasswordAuthentication、PermitRootLogin、监听地址和最近登录来源。"
            "如需收敛暴露面，应先生成配置差异和回滚方案，再由管理员审批后执行。"
            "\n\n"
            "输出要求：明确当前监听范围、风险来源、是否需要立即处置，以及建议的最小变更集。"
            "任何会导致远程失联的操作必须提示二次确认并要求本地控制台兜底。"
        ),
    ),
    BuiltinKnowledgeDocument(
        title="数据库与中间件日志边界规范",
        source_type="policy",
        source_uri="builtin://ops/database-log-boundary",
        trust_level="verified",
        content=(
            "适用对象：MySQL、PostgreSQL、Redis、消息队列、搜索服务和业务中间件日志目录。"
            "数据库事务日志、WAL、binlog、redo、undo、AOF、RDB、审计日志和复制槽相关文件不得被 Agent 自动删除。"
            "\n\n"
            "处置原则：对数据库日志目录只能先做只读识别，记录文件类型、大小、mtime、进程占用和服务归属。"
            "确认为普通文本应用日志后，仍应优先执行归档、压缩、截断和备份保留，不使用递归删除。"
            "\n\n"
            "审批要求：涉及数据库目录的清理、保留策略变更、日志参数修改和服务重启均需升级到人工审批，"
            "并在执行记录中保留备份路径、前后空间变化和回滚路径。"
        ),
    ),
    BuiltinKnowledgeDocument(
        title="systemd 服务处置规范",
        source_type="runbook",
        source_uri="builtin://ops/systemd-service",
        trust_level="verified",
        content=(
            "适用场景：服务 failed、不断重启、端口占用、配置加载失败或资源消耗异常。"
            "Agent 可读取 systemctl status、journal 摘要、进程资源和端口占用，但默认不得 restart、stop、disable 或修改 unit 文件。"
            "\n\n"
            "排查顺序：先确认服务单元状态、最近失败时间、退出码、主进程 PID、关键日志、配置文件权限和依赖服务状态。"
            "如果日志显示配置解析失败，应建议先做配置语法检查和差异核验。"
            "\n\n"
            "执行边界：重启服务前必须说明业务影响、当前连接情况、回滚动作和审批人。"
            "只有用户明确提出重启、service_status 已真实观测目标、服务进入精确白名单且不属于 Agent 自身、"
            "数据库、审计、网络或远程接入保护单元时，才可生成 R3 dry-run 建议。审批后只提交一次重启，"
            "并由独立 service_status 复验 active 状态；复验失败不自动重试，直接转人工处理。"
            "对于安全组件、数据库、网络、存储和远程接入服务，应默认升级为高风险人工复核。"
        ),
    ),
    BuiltinKnowledgeDocument(
        title="Linux 资源压力判读规范",
        source_type="runbook",
        source_uri="https://docs.kernel.org/accounting/psi.html",
        trust_level="verified",
        content=(
            "适用场景：CPU、内存或 I/O 利用率看似正常，但业务仍出现延迟尖峰、吞吐下降或 OOM 风险。"
            "应读取 /proc/pressure/cpu、memory 和 io；some 表示至少部分任务因资源等待而停顿，"
            "full 表示全部非空闲任务同时停顿，avg10、avg60、avg300 分别描述短、中、长时间窗。"
            "\n\n"
            "判断规则：PSI 描述资源争用造成的停顿时间，不能与 CPU 使用率、内存占用率或磁盘利用率相互替代。"
            "单次高值只能形成压力线索，必须结合时间窗变化、进程或 cgroup 资源、日志和业务症状确认根因。"
            "系统级 cpu full 为兼容性字段，不能据其为零排除 CPU 压力。"
            "\n\n"
            "处置边界：先只读定位产生压力的工作负载和影响范围；限流、迁移、暂停或终止任务均属于系统变更，"
            "必须说明业务影响并进入审批。不得仅凭一个 PSI 数值自动 kill 进程或调整资源配额。"
        ),
    ),
    BuiltinKnowledgeDocument(
        title="cgroup v2 内存事件归因规范",
        source_type="runbook",
        source_uri="https://docs.kernel.org/admin-guide/cgroup-v2.html",
        trust_level="verified",
        content=(
            "适用场景：容器、systemd 服务或业务进程出现内存抖动、限流、分配失败和 OOM。"
            "memory.events 是只读事件计数，其中 high 表示超过高水位后被限流并进入直接回收，"
            "max 表示即将超过硬上限，oom 表示分配接近失败，oom_kill 表示已有进程被 OOM killer 终止。"
            "\n\n"
            "判断规则：memory.events 默认包含当前 cgroup 子树事件，定位本层工作负载时应同时查看"
            " memory.events.local。事件计数是累计值，调查必须比较采样窗口内的增量，"
            "并结合 memory.current、memory.stat、进程归属和内核日志，不能把历史累计值写成当前故障。"
            "\n\n"
            "处置边界：调整 memory.high、memory.max、迁移进程或重启服务会改变资源控制行为。"
            "执行前必须确认 cgroup 层级、父级约束、受影响进程和业务容量，执行后重新采样事件增量与服务健康。"
        ),
    ),
    BuiltinKnowledgeDocument(
        title="systemd 依赖与变更影响判读规范",
        source_type="runbook",
        source_uri="https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml",
        trust_level="verified",
        content=(
            "适用场景：预演服务 restart、stop 或配置重载时判断影响范围。"
            "Before 和 After 只定义启动与停止顺序，独立于 Requires、Wants、BindsTo 等需求关系，"
            "不能仅凭排序关系断言另一个服务会被停止或重启。"
            "\n\n"
            "判断规则：PartOf 是单向传播关系；其列出的单元被停止或重启时，动作会传播到声明 PartOf 的单元，"
            "反向变化不会影响被列出的单元。Requires 是较强需求关系，但也不等于依赖单元在任何时刻都必须保持 active。"
            "影响分析应分别展示确定传播、仅排序、弱依赖和采样到的当前连接，不得把它们合并为一个模糊的依赖数。"
            "\n\n"
            "执行边界：审批前冻结目标、关系类型、传播单元、当前连接和证据缺口。"
            "执行前必须重新采样 systemd 关系与连接；关系发生变化时原审批失效，需重新计算影响并再次审批。"
        ),
    ),
    BuiltinKnowledgeDocument(
        title="systemd-journald 空间治理规范",
        source_type="runbook",
        source_uri="https://github.com/systemd/systemd/blob/main/man/journald.conf.xml",
        trust_level="verified",
        content=(
            "适用场景：/var/log/journal 或 /run/log/journal 占用空间增长，引发根分区或运行时目录压力。"
            "SystemMaxUse 和 RuntimeMaxUse 限制日志最大空间，SystemKeepFree 和 RuntimeKeepFree 保留其他用途空间；"
            "journald 同时遵守两类约束并采用更小的可用值。"
            "\n\n"
            "判断规则：持久日志与运行时日志适用不同参数。空间回收只删除归档 journal 文件，活动文件会保留，"
            "因此回收完成后占用仍可能高于配置上限。必须同时核对当前目录、配置来源、实际磁盘用量和文件活动状态，"
            "不能把大文件数量直接等同于轮转失效。"
            "\n\n"
            "处置边界：不得直接 rm 活跃 journal 文件。需要回收时应使用 journald 支持的轮转与清理机制，"
            "先说明保留窗口、审计影响和预计释放空间，再进入审批；执行后复验日志可读性与磁盘空间。"
        ),
    ),
    BuiltinKnowledgeDocument(
        title="PostgreSQL WAL 空间压力处置规范",
        source_type="runbook",
        source_uri="https://www.postgresql.org/docs/current/wal-configuration.html",
        trust_level="verified",
        content=(
            "适用场景：PostgreSQL 数据目录或 pg_wal 快速增长并造成磁盘压力。"
            "WAL 用于崩溃恢复与复制，max_wal_size 不是硬上限；归档失败、归档速度不足、"
            "复制槽对应的从库缓慢或失联，都可能阻止旧 WAL 被回收并导致持续累积。"
            "\n\n"
            "判断规则：先核对文件系统余量、WAL 生成速率、检查点、归档状态、复制槽和从库追赶情况。"
            "不要仅根据 pg_wal 目录大小判断泄漏，也不能把普通日志轮转规则套用于 WAL。"
            "\n\n"
            "处置边界：Agent 不得直接删除 pg_wal 中的文件，也不得自动执行重置 WAL、删除复制槽或修改归档配置。"
            "应给出造成保留的具体证据、受影响复制关系、可用磁盘余量和官方数据库处置路径，"
            "由数据库管理员审批；处置后复验归档、复制和恢复连续性。"
        ),
    ),
    BuiltinKnowledgeDocument(
        title="Linux 多架构节点部署巡检规范",
        source_type="manual",
        source_uri="builtin://ops/linux-runtime-readiness",
        trust_level="verified",
        content=(
            "适用场景：Agent 部署在 x86_64、AArch64、LoongArch 或 RISC-V Linux 节点。"
            "巡检应记录操作系统发行版、内核、架构、Python 版本、PostgreSQL/pgvector 可用性、MCP 端点和受限执行账户。"
            "\n\n"
            "检查要点：确认服务以非 root 账户运行，sudo 权限仅授予白名单脚本；"
            "确认数据库连接、审计链写入、模型服务配置和只读感知工具均可用。"
            "\n\n"
            "异常处置：如果内核接口、工具链或向量扩展不满足要求，应阻止上线并输出缺口清单。"
            "不得跳过部署就绪检查或伪造系统环境。"
        ),
    ),
)
