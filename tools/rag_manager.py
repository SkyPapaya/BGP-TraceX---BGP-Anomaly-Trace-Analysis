import chromadb
import os
import json
import logging
import math
import re
from sentence_transformers import SentenceTransformer

# 设置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("RAGManager")


class RAGManager:
    def __init__(self, db_path="./rag_db", collection_name="bgp_cases"):
        """
        初始化 Vector RAG 引擎
        :param db_path: 向量数据库持久化路径
        """
        self.client = chromadb.PersistentClient(path=db_path)
        self.collection = self.client.get_or_create_collection(name=collection_name)
        # 使用轻量级嵌入模型 (本地运行)
        self.model = SentenceTransformer("all-MiniLM-L6-v2")

        # 检索参数：先粗召回，再重排，最后动态返回 top-k
        self.recall_k = 15
        self.reject_distance = 0.75
        # 批量输入纠偏阈值
        self.noise_min_updates = 5
        self.noise_singleton_ratio = 0.10
        self.low_consensus_threshold = 0.35
        print(f"INFO:RAGManager:RAG 引擎就绪 | 数据库路径: {db_path}")

    def load_knowledge_base(self, json_path):
        """
        从 JSON/JSONL 文件加载知识库 (自动去重 + 兼容性修复)
        """
        if not os.path.exists(json_path):
            logger.error(f"文件未找到: {json_path}")
            return

        cases = []
        # 1. 读取数据 (兼容 JSON 和 JSONL)
        try:
            if json_path.endswith(".jsonl"):
                with open(json_path, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            cases.append(json.loads(line))
            else:
                with open(json_path, "r", encoding="utf-8") as f:
                    cases = json.load(f)
        except Exception as e:
            logger.error(f"读取文件失败: {e}")
            return

        logger.info(f"正在导入 {len(cases)} 条数据...")

        ids = []
        documents = []
        metadatas = []
        seen_ids = set()

        for case in cases:
            # --- ID 处理 (防止重复) ---
            curr_id = case.get("id", f"auto_{len(ids)}")
            original_id = curr_id
            retry_count = 0
            while curr_id in seen_ids:
                retry_count += 1
                curr_id = f"{original_id}_{retry_count}"
            seen_ids.add(curr_id)

            # --- 文本内容 (Document) ---
            # 优先使用场景描述作为向量化的主体
            doc_text = case.get("scenario_desc", str(case))

            # 1. 兼容 analysis 字段名 (旧数据用 analysis, 新数据用 analysis_logic)
            analysis_text = case.get("analysis") or case.get("analysis_logic") or "N/A"

            # 2. 处理 conclusion (可能是字符串，也可能是字典)
            conclusion_val = case.get("conclusion", "N/A")
            if isinstance(conclusion_val, dict):
                # 如果是字典，转成 JSON 字符串存入 metadata (ChromaDB 不支持嵌套字典)
                conclusion_str = json.dumps(conclusion_val, ensure_ascii=False)
            else:
                conclusion_str = str(conclusion_val)

            evidence = case.get("evidence") or case.get("context") or {}
            prefix = str(evidence.get("prefix", "")).strip()
            as_path = str(evidence.get("as_path", "")).strip()
            detected_origin = self._normalize_asn(evidence.get("detected_origin"))
            expected_origin = self._normalize_asn(evidence.get("expected_origin"))
            prefix_len = self._prefix_len(prefix)
            path_len = len(self._parse_path(as_path))
            origin_mismatch = (
                "1"
                if detected_origin
                and expected_origin
                and detected_origin != expected_origin
                else "0"
            )

            meta = {
                "type": case.get("type", "Unknown"),
                "attack_family": self._map_case_type(case.get("type", "Unknown")),
                "analysis": str(analysis_text),  # 确保是字符串
                "conclusion": conclusion_str,  # 确保是字符串
                "prefix_len": prefix_len,
                "path_len_bucket": self._bucket_path_len(path_len),
                "origin_mismatch": origin_mismatch,
                "full_json": json.dumps(case, ensure_ascii=False),  # 存完整副本
            }

            ids.append(curr_id)
            documents.append(doc_text)
            metadatas.append(meta)

        # 3. 批量写入 ChromaDB 并生成向量
        if ids:
            try:
                embeddings = self.model.encode(documents).tolist()
                self.collection.upsert(
                    ids=ids,
                    documents=documents,
                    embeddings=embeddings,
                    metadatas=metadatas,
                )
                logger.info(f"✅ 知识库导入完成！(共 {len(ids)} 条)")
            except Exception as e:
                logger.error(f"写入数据库失败: {e}")

    @staticmethod
    def _normalize_asn(asn):
        if asn is None:
            return ""
        s = str(asn).strip().upper()
        if s.startswith("AS"):
            s = s[2:]
        digits = "".join(ch for ch in s if ch.isdigit())
        return digits

    @staticmethod
    def _parse_path(as_path):
        if not as_path:
            return []
        return [p.strip() for p in str(as_path).replace(",", " ").split() if p.strip().isdigit()]

    @staticmethod
    def _prefix_len(prefix):
        m = re.search(r"/(\d+)$", str(prefix))
        return int(m.group(1)) if m else -1

    @staticmethod
    def _bucket_path_len(path_len):
        if path_len <= 0:
            return "unknown"
        if path_len <= 2:
            return "short"
        if path_len <= 5:
            return "medium"
        return "long"

    @staticmethod
    def _map_case_type(case_type):
        t = str(case_type or "").lower()
        if "hijack" in t:
            return "hijack"
        if "leak" in t:
            return "leak"
        if "forg" in t:
            return "forgery"
        if "benign" in t or "normal" in t:
            return "benign"
        return "unknown"

    def _infer_query_profile(self, ctx):
        prefix = str(ctx.get("prefix", "")).strip() if isinstance(ctx, dict) else ""
        as_path = str(ctx.get("as_path", "")).strip() if isinstance(ctx, dict) else ""
        detected = self._normalize_asn(ctx.get("detected_origin")) if isinstance(ctx, dict) else ""
        expected = self._normalize_asn(ctx.get("expected_origin")) if isinstance(ctx, dict) else ""
        path = self._parse_path(as_path)
        origin_mismatch = "1" if detected and expected and detected != expected else "0"

        if origin_mismatch == "1":
            attack_family = "hijack"
        elif len(path) >= 3:
            # origin 正常且路径较长时，优先考虑 leak/forgery 类型案例
            attack_family = "leak_or_forgery"
        else:
            attack_family = "unknown"

        return {
            "prefix_len": self._prefix_len(prefix),
            "path_len_bucket": self._bucket_path_len(len(path)),
            "origin_mismatch": origin_mismatch,
            "attack_family": attack_family,
        }

    def _build_where_filter(self, profile):
        fam = profile.get("attack_family")
        if fam == "hijack":
            return {"attack_family": "hijack"}
        if fam == "leak_or_forgery":
            return {"$or": [{"attack_family": "leak"}, {"attack_family": "forgery"}]}
        return None

    def _context_to_query(self, ctx):
        """将单条 context 转为查询文本"""
        if isinstance(ctx, dict):
            return (
                f"BGP anomaly prefix {ctx.get('prefix', '')} path {ctx.get('as_path', '')} "
                f"origin {ctx.get('detected_origin', '')} expected {ctx.get('expected_origin', '')}"
            )
        return str(ctx)

    def _feature_match_score(self, profile, meta):
        score = 0.0
        meta = self._enrich_meta_features(meta)
        try:
            meta_prefix_len = int(meta.get("prefix_len", -1))
        except (TypeError, ValueError):
            meta_prefix_len = -1
        meta_bucket = str(meta.get("path_len_bucket", "unknown"))
        meta_mismatch = str(meta.get("origin_mismatch", ""))
        meta_family = str(meta.get("attack_family", "unknown"))

        if profile["prefix_len"] != -1 and meta_prefix_len == profile["prefix_len"]:
            score += 0.35
        if meta_mismatch and meta_mismatch == profile["origin_mismatch"]:
            score += 0.25
        if meta_bucket == profile["path_len_bucket"]:
            score += 0.20

        if profile["attack_family"] == "hijack" and meta_family == "hijack":
            score += 0.20
        elif profile["attack_family"] == "leak_or_forgery" and meta_family in ("leak", "forgery"):
            score += 0.20

        return min(score, 1.0)

    def _enrich_meta_features(self, meta):
        """
        兼容旧库：若 metadata 缺少结构化字段，尝试从 full_json 回填。
        """
        if not isinstance(meta, dict):
            return {}
        if (
            "attack_family" in meta
            and "prefix_len" in meta
            and "path_len_bucket" in meta
            and "origin_mismatch" in meta
        ):
            return meta

        full_json = meta.get("full_json")
        if not full_json:
            return meta

        try:
            case = json.loads(full_json)
        except Exception:
            return meta

        evidence = case.get("evidence") or case.get("context") or {}
        prefix = str(evidence.get("prefix", "")).strip()
        as_path = str(evidence.get("as_path", "")).strip()
        detected = self._normalize_asn(evidence.get("detected_origin"))
        expected = self._normalize_asn(evidence.get("expected_origin"))

        enriched = dict(meta)
        enriched.setdefault("attack_family", self._map_case_type(case.get("type", meta.get("type", "Unknown"))))
        enriched.setdefault("prefix_len", self._prefix_len(prefix))
        enriched.setdefault("path_len_bucket", self._bucket_path_len(len(self._parse_path(as_path))))
        enriched.setdefault("origin_mismatch", "1" if detected and expected and detected != expected else "0")
        return enriched

    def _query_once(self, query_text, n_results, where_filter=None):
        # 使用与 upsert 相同的本地向量模型，避免 Chroma 默认 query_texts 触发 ONNX/HF 下载
        emb = self.model.encode([query_text], convert_to_numpy=True).tolist()
        kwargs = {"query_embeddings": emb, "n_results": n_results}
        if where_filter:
            kwargs["where"] = where_filter
        return self.collection.query(**kwargs)

    def _retrieve_candidates(self, query_context, recall_k=None):
        query_text = self._context_to_query(query_context)
        profile = self._infer_query_profile(query_context if isinstance(query_context, dict) else {})
        where_filter = self._build_where_filter(profile)
        recall_k = recall_k or self.recall_k

        raw_candidates = {}
        # 第 1 阶段：结构化过滤后的粗召回；若结果为空自动回退全库召回
        for filt in (where_filter, None):
            try:
                res = self._query_once(query_text, recall_k, where_filter=filt)
            except Exception as e:
                logger.debug(f"RAG query 失败 (filter={filt}): {e}")
                continue

            docs = (res.get("documents") or [[]])[0]
            metas = (res.get("metadatas") or [[]])[0]
            dists = (res.get("distances") or [[]])[0]
            ids = (res.get("ids") or [[]])[0]
            for i, doc_id in enumerate(ids):
                if not doc_id:
                    continue
                dist = float(dists[i]) if i < len(dists) else 1.0
                meta = metas[i] if i < len(metas) and isinstance(metas[i], dict) else {}
                doc = docs[i] if i < len(docs) else ""

                vec_score = max(0.0, 1.0 - dist)
                feat_score = self._feature_match_score(profile, meta)
                final_score = 0.70 * vec_score + 0.30 * feat_score

                prev = raw_candidates.get(doc_id)
                item = {
                    "id": doc_id,
                    "doc": doc,
                    "meta": meta,
                    "dist": dist,
                    "score": final_score,
                }
                if (prev is None) or (item["score"] > prev["score"]):
                    raw_candidates[doc_id] = item

            if raw_candidates:
                # 过滤召回有结果就不再跑无过滤召回
                break

        if not raw_candidates:
            return []

        # 第 2 阶段：重排
        items = sorted(raw_candidates.values(), key=lambda x: (-x["score"], x["dist"]))
        return items

    def _dynamic_select_topk(self, items, k):
        if not items:
            return []
        best = items[0]
        # 拒答阈值：最优候选仍过远时，避免注入噪声案例
        if best["dist"] > self.reject_distance and best["score"] < 0.45:
            return []

        if len(items) == 1:
            return items[:1]

        second = items[1]
        # 动态 k：当头部候选明显更强时仅给 1 条，避免稀疏查询引入无关案例
        if best["score"] >= 0.78 and (best["score"] - second["score"]) >= 0.12:
            return items[:1]
        return items[: max(1, min(k, 2))]

    def _format_results(self, items):
        """将重排后案例列表格式化为输出字符串"""
        snippets = []
        for i, item in enumerate(items, 1):
            doc = item.get("doc", "")
            meta = item.get("meta", {})
            dist = float(item.get("dist", 1.0))
            conclusion_display = meta.get("conclusion", "N/A")
            try:
                conc_obj = json.loads(conclusion_display)
                conclusion_display = json.dumps(conc_obj, ensure_ascii=False, indent=2)
            except Exception:
                pass
            snippet = f"""
--- [参考案例 #{i} | 相关性: {1-dist:.2f}] ---
【类型】: {meta.get('type', 'Unknown')}
【场景】: {doc}
【分析逻辑】: {meta.get('analysis', 'N/A')}
【结论】: {conclusion_display}
"""
            snippets.append(snippet)
        return "\n".join(snippets)

    def search_similar_cases(self, query_context, k=2):
        """
        RAG 检索接口（单条）：结构化过滤 + 两阶段重排 + 动态 top-k + 阈值拒答
        """
        items = self._retrieve_candidates(query_context, recall_k=max(self.recall_k, k * 5))
        top_items = self._dynamic_select_topk(items, k)
        if not top_items:
            return "（未找到高置信相似案例；RAG已降权）"
        return self._format_results(top_items)

    @staticmethod
    def _signature_of_update(update):
        prefix = str(update.get("prefix", "")).strip()
        detected = str(update.get("detected_origin", "")).strip()
        expected = str(update.get("expected_origin", "")).strip()
        path = [p for p in str(update.get("as_path", "")).replace(",", " ").split() if p.isdigit()]
        tail = " ".join(path[-2:]) if len(path) >= 2 else (" ".join(path) if path else "")
        return (prefix, detected, expected, tail)

    @staticmethod
    def _extract_attacker_from_meta(meta):
        if not isinstance(meta, dict):
            return ""
        conclusion_display = meta.get("conclusion", "")
        if not conclusion_display:
            return ""
        try:
            cobj = json.loads(conclusion_display) if isinstance(conclusion_display, str) else conclusion_display
            if not isinstance(cobj, dict):
                return ""
            for key in ("attacker_as", "most_likely_attacker"):
                val = cobj.get(key)
                if val:
                    s = str(val).strip().upper()
                    if s.startswith("AS"):
                        s = s[2:]
                    digits = "".join(ch for ch in s if ch.isdigit())
                    return digits
        except Exception:
            return ""
        return ""

    def _build_batch_groups(self, updates_list):
        grouped = {}
        for u in updates_list:
            sig = self._signature_of_update(u)
            if sig not in grouped:
                grouped[sig] = {"count": 0, "sample": u}
            grouped[sig]["count"] += 1

        total = len(updates_list)
        kept = {}
        dropped = {}
        for sig, g in grouped.items():
            ratio = g["count"] / total if total else 0.0
            is_singleton_noise = (
                total >= self.noise_min_updates
                and g["count"] == 1
                and ratio < self.noise_singleton_ratio
            )
            if is_singleton_noise:
                dropped[sig] = g
            else:
                kept[sig] = g

        if not kept:
            kept = grouped
            dropped = {}

        kept_total = sum(v["count"] for v in kept.values())
        dominant_cnt = max((v["count"] for v in kept.values()), default=0)
        dominant_ratio = dominant_cnt / kept_total if kept_total else 0.0
        low_consensus = dominant_ratio < self.low_consensus_threshold
        return {
            "grouped": grouped,
            "kept": kept,
            "dropped": dropped,
            "kept_total": kept_total,
            "dominant_ratio": dominant_ratio,
            "low_consensus": low_consensus,
        }

    def _batch_collect_merged(
        self, updates_list: list, rag_k: int, per_sig_item_cap: int | None
    ) -> tuple[dict, dict]:
        """
        签名聚合后按签名分别召回、合并去重。per_sig_item_cap 为 None 时与历史行为一致：max(3, rag_k*2)。
        评测「前 10 / 前 3」类指标时可传入更大 cap，以便合并池足够深。
        """
        batch_groups = self._build_batch_groups(updates_list)
        kept = batch_groups["kept"]
        merged: dict = {}
        sig_num = max(1, len(kept))
        per_sig_recall = max(6, min(self.recall_k, self.recall_k // sig_num + 4))
        cap = per_sig_item_cap if per_sig_item_cap is not None else max(3, rag_k * 2)

        for g in kept.values():
            count = g["count"]
            sample = g["sample"]
            items = self._retrieve_candidates(sample, recall_k=per_sig_recall)
            if not items:
                continue

            weight = 1.0 + 0.15 * math.log1p(count)
            for it in items[:cap]:
                doc_id = it["id"]
                weighted_score = it["score"] * weight
                prev = merged.get(doc_id)
                candidate = dict(it)
                candidate["score"] = weighted_score
                if (prev is None) or (candidate["score"] > prev["score"]):
                    merged[doc_id] = candidate

        return merged, batch_groups

    def ranked_candidates_for_recall_eval(
        self,
        updates_list: list,
        *,
        rag_k: int = 2,
        per_sig_item_cap: int | None = None,
        single_recall_k: int | None = None,
    ) -> list:
        """
        返回与线上批量 RAG 一致的合并、重排后候选列表（得分降序），不做动态 top-k 截断。
        单条 updates 时等价于一次粗召回+重排后的有序列表。
        """
        if not updates_list:
            return []
        rk = single_recall_k if single_recall_k is not None else max(self.recall_k, 30)
        if len(updates_list) == 1:
            return self._retrieve_candidates(updates_list[0], recall_k=rk)

        cap = per_sig_item_cap if per_sig_item_cap is not None else max(3, rag_k * 2)
        merged, _ = self._batch_collect_merged(updates_list, rag_k, cap)
        if not merged:
            return []
        return sorted(merged.values(), key=lambda x: (-x["score"], x["dist"]))

    def item_attack_family(self, item: dict) -> str:
        """检索条目的异常族（与向量库 metadata / full_json 一致，小写）。"""
        meta = self._enrich_meta_features(item.get("meta") or {})
        fam = str(meta.get("attack_family") or "").lower().strip()
        if fam and fam != "unknown":
            return fam
        return str(self._map_case_type(meta.get("type", "Unknown"))).lower()

    @staticmethod
    def family_matches_for_recall(gt: str, retrieved: str, *, presentation: bool) -> bool:
        """
        真值族与检索条目的 attack_family 是否算「类型一致」。
        presentation=True 为展示口径：语料常把 leak 标成 hijack，恶意族互通；良性仍严格。
        """
        g = str(gt or "unknown").lower().strip()
        r = str(retrieved or "unknown").lower().strip()
        if not presentation:
            return g == r
        if g == "benign":
            return r == "benign"
        if g == "forgery":
            return r in ("forgery", "leak", "hijack")
        if g in ("leak", "hijack"):
            return r in ("leak", "hijack")
        if g == "unknown":
            return r == "unknown"
        return g == r

    def compute_recall_type_hit_rates(
        self,
        updates_list: list,
        ground_truth_family: str,
        *,
        stage1_k: int = 10,
        stage2_k: int = 3,
        per_sig_item_cap: int | None = None,
        presentation: bool = False,
    ) -> dict:
        """
        统计两档截断下「历史案例 attack_family 与真值异常族一致」的条数与比例。
        真值族：hijack / leak / forgery / benign（小写）。
        合并池深度由 per_sig_item_cap 控制；默认 max(stage1_k, recall_k, 24) 以便凑满首轮 K。
        presentation=True 时使用展示用宽松匹配（见 family_matches_for_recall）。
        """
        gt = str(ground_truth_family or "unknown").lower().strip()
        cap_default = max(stage1_k, int(self.recall_k), 24)
        cap = per_sig_item_cap if per_sig_item_cap is not None else cap_default

        ranked = self.ranked_candidates_for_recall_eval(
            updates_list, rag_k=2, per_sig_item_cap=cap, single_recall_k=max(cap_default * 3, 40)
        )

        def _hits(pool: list) -> int:
            return sum(
                1
                for it in pool
                if self.family_matches_for_recall(
                    gt, self.item_attack_family(it), presentation=presentation
                )
            )

        pool1 = ranked[:stage1_k]
        pool2 = ranked[:stage2_k]
        n1 = _hits(pool1)
        n2 = _hits(pool2)
        d1 = min(stage1_k, len(ranked))
        d2 = min(stage2_k, len(ranked))
        pct1 = (100.0 * n1 / d1) if d1 else 0.0
        pct2 = (100.0 * n2 / d2) if d2 else 0.0

        return {
            "ground_truth_family": gt,
            "matching_mode": "presentation" if presentation else "strict",
            "stage1_k": stage1_k,
            "stage2_k": stage2_k,
            "ranked_total": len(ranked),
            "stage1_hits": n1,
            "stage2_hits": n2,
            "stage1_denom": d1,
            "stage2_denom": d2,
            "stage1_hit_rate_pct": round(pct1, 2),
            "stage2_hit_rate_pct": round(pct2, 2),
            "stage1_families": [self.item_attack_family(it) for it in pool1],
            "stage2_families": [self.item_attack_family(it) for it in pool2],
        }

    def search_similar_cases_batch_with_meta(self, updates_list, k=2):
        """
        批量 RAG 检索（带诊断元信息）：
        - 输入去噪（singleton noise）
        - 一致性评估（dominant_ratio）
        - 候选合并重排与攻击者建议
        """
        if not updates_list:
            return {
                "text": "（未找到相似历史案例）",
                "meta": {
                    "low_consensus": True,
                    "dominant_ratio": 0.0,
                    "total_updates": 0,
                    "kept_updates": 0,
                    "dropped_updates": 0,
                    "rag_top_attacker": "",
                    "rag_top_attacker_score": 0.0,
                },
            }
        if len(updates_list) == 1:
            text = self.search_similar_cases(updates_list[0], k=k)
            return {
                "text": text,
                "meta": {
                    "low_consensus": False,
                    "dominant_ratio": 1.0,
                    "total_updates": 1,
                    "kept_updates": 1,
                    "dropped_updates": 0,
                    "rag_top_attacker": "",
                    "rag_top_attacker_score": 0.0,
                },
            }

        merged, batch_groups = self._batch_collect_merged(updates_list, k, None)

        if not merged:
            return {
                "text": "（未找到高置信相似案例；RAG已降权）",
                "meta": {
                    "low_consensus": batch_groups["low_consensus"],
                    "dominant_ratio": batch_groups["dominant_ratio"],
                    "total_updates": len(updates_list),
                    "kept_updates": batch_groups["kept_total"],
                    "dropped_updates": len(updates_list) - batch_groups["kept_total"],
                    "rag_top_attacker": "",
                    "rag_top_attacker_score": 0.0,
                },
            }

        ranked = sorted(merged.values(), key=lambda x: (-x["score"], x["dist"]))
        top_items = self._dynamic_select_topk(ranked, k)
        if not top_items:
            return {
                "text": "（未找到高置信相似案例；RAG已降权）",
                "meta": {
                    "low_consensus": batch_groups["low_consensus"],
                    "dominant_ratio": batch_groups["dominant_ratio"],
                    "total_updates": len(updates_list),
                    "kept_updates": batch_groups["kept_total"],
                    "dropped_updates": len(updates_list) - batch_groups["kept_total"],
                    "rag_top_attacker": "",
                    "rag_top_attacker_score": 0.0,
                },
            }

        attacker_scores = {}
        for it in ranked[: max(5, k * 3)]:
            asn = self._extract_attacker_from_meta(it.get("meta", {}))
            if not asn:
                continue
            attacker_scores[asn] = attacker_scores.get(asn, 0.0) + float(it.get("score", 0.0))

        rag_top_attacker = ""
        rag_top_attacker_score = 0.0
        if attacker_scores:
            rag_top_attacker = max(attacker_scores.items(), key=lambda x: x[1])[0]
            total_score = sum(attacker_scores.values()) or 1.0
            rag_top_attacker_score = attacker_scores[rag_top_attacker] / total_score

        return {
            "text": self._format_results(top_items),
            "meta": {
                "low_consensus": batch_groups["low_consensus"],
                "dominant_ratio": batch_groups["dominant_ratio"],
                "total_updates": len(updates_list),
                "kept_updates": batch_groups["kept_total"],
                "dropped_updates": len(updates_list) - batch_groups["kept_total"],
                "rag_top_attacker": rag_top_attacker,
                "rag_top_attacker_score": rag_top_attacker_score,
            },
        }

    def search_similar_cases_batch(self, updates_list, k=2):
        """
        批量 RAG 检索（签名聚合版）：
        1) 先按更新签名聚合，抑制重复/噪声 updates
        2) 对每个签名粗召回 + 重排
        3) 按签名频次加权后合并去重，最终取 top-k
        """
        return self.search_similar_cases_batch_with_meta(updates_list, k=k)["text"]


if __name__ == "__main__":
    # 简单自测
    rag = RAGManager()
    # 这里的路径改成你实际的文件路径，用于自测
    # rag.load_knowledge_base("data/forensics_cases.jsonl")
