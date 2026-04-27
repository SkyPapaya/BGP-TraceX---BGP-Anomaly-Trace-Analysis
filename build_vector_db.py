import os
import sys
import shutil
import argparse

# 确保能导入 tools 包
sys.path.append(os.getcwd())
from tools.rag_manager import RAGManager
from tools.project_paths import FULL_ATTACK_CASES_FILE, RAG_DB_DIR, RAG_CASES_FROM_EVENTS_FILE


def build_db(json_path: str | None = None):
    # ================= 配置区域 =================
    # 1. 输入数据: full_attack_cases.jsonl（合成）或 rag_cases_from_events.jsonl（真实 Step1 摘要）
    if json_path is None:
        json_path = str(FULL_ATTACK_CASES_FILE)

    # 2. 输出路径: 必须与 bgp_agent.py 里的设置一致
    db_path = str(RAG_DB_DIR)
    # ===========================================

    # 检查输入文件
    if not os.path.exists(json_path):
        print(f"❌ 错误: 找不到数据文件 {json_path}")
        print("   -> 合成语料: python auto_generator/auto_generator.py")
        print("   -> 真实语料: python scripts/build_rag_from_events.py && 使用 --input data/rag_cases_from_events.jsonl")
        return

    # 清理旧数据库 (强制删除旧文件夹，防止脏数据干扰)
    if os.path.exists(db_path):
        print(f"🧹 清理旧数据库: {db_path}")
        try:
            shutil.rmtree(db_path)
        except Exception as e:
            print(f"⚠️ 清理失败: {e}")

    # 初始化 RAG
    print(f"🔄 初始化数据库: {db_path}")
    rag = RAGManager(db_path=db_path)
    
    # 开始构建
    print(f"📖 读取并写入数据: {json_path} ...")
    try:
        rag.load_knowledge_base(json_path)
        
        # 验证一下数据量
        count = rag.collection.count()
        print(f"\n✅ 构建成功! 数据库现包含 {count} 条案例。")
        
        # 简单的检索测试
        print("🔎 自检测试 (Search Test):")
        test_res = rag.search_similar_cases({"prefix": "1.2.3.0/24", "as_path": "174 12389"}, k=1)
        print(test_res[:200] + "...") # 只打印前200字符

    except Exception as e:
        print(f"\n❌ 构建崩溃: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="构建 Chroma RAG 向量库")
    parser.add_argument(
        "--input",
        default=str(FULL_ATTACK_CASES_FILE),
        help=f"知识库 JSON/JSONL 路径。真实事件摘要默认: {RAG_CASES_FROM_EVENTS_FILE.name}",
    )
    args = parser.parse_args()
    build_db(json_path=args.input)
