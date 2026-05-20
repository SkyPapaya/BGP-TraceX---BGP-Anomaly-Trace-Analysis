# tools/graph_rag.py
from neo4j import GraphDatabase
import logging
import os
import subprocess
import time

# 配置日志
logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger("Neo4j_RAG")

NEO4J_CONTAINER = "neo4j-bgp"

def _ensure_neo4j_running():
    """检查 Neo4j Docker 容器是否在运行，没有则启动"""
    try:
        result = subprocess.run(
            ["docker", "ps", "--filter", f"name={NEO4J_CONTAINER}", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=5
        )
        if NEO4J_CONTAINER in result.stdout:
            return True  # 容器已在运行

        # 检查容器是否存在但停止了
        result = subprocess.run(
            ["docker", "ps", "-a", "--filter", f"name={NEO4J_CONTAINER}", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=5
        )
        if NEO4J_CONTAINER in result.stdout:
            print(f"⚡ [Neo4j] 容器存在但未运行，正在启动...")
            subprocess.run(["docker", "start", NEO4J_CONTAINER], check=True, timeout=30)
        else:
            print(f"⚡ [Neo4j] 容器不存在，正在创建并启动...")
            subprocess.run([
                "docker", "run", "-d", "--name", NEO4J_CONTAINER,
                "-p", "7474:7474", "-p", "7687:7687",
                "-e", f"NEO4J_AUTH=neo4j/{os.getenv('NEO4J_PASSWORD', 'bgptracex2024')}",
                "neo4j:latest"
            ], check=True, timeout=120)

        # 等待 Neo4j 就绪
        for _ in range(15):
            time.sleep(2)
            try:
                from neo4j import GraphDatabase as GD
                pwd = os.getenv("NEO4J_PASSWORD", "bgptracex2024")
                d = GD.driver("bolt://localhost:7687", auth=("neo4j", pwd))
                d.verify_connectivity()
                d.close()
                return True
            except Exception:
                pass
        return False
    except Exception as e:
        print(f"⚠️ [Neo4j] 自动启动失败: {e}")
        return False


class BGPGraphRAG:
    def __init__(self, uri="bolt://localhost:7687", user="neo4j", password=None):
        """
        初始化 Neo4j 连接并注入初始数据
        """
        self.driver = None
        neo4j_password = password if password is not None else os.getenv("NEO4J_PASSWORD", "bgptracex2024")

        # 自动检查并启动 Docker 容器
        _ensure_neo4j_running()

        try:
            self.driver = GraphDatabase.driver(uri, auth=(user, neo4j_password))
            self.driver.verify_connectivity()
            print("✅ [Neo4j] 数据库连接成功！")
            self._seed_database()
        except Exception as e:
            print(f"❌ [Neo4j] 连接失败: {e}")
            print("   -> 请检查 Docker 是否启动: docker ps")

    def close(self):
        if self.driver:
            self.driver.close()

    def _seed_database(self):
        """
        使用 Cypher 语句构建知识图谱
        """
        seed_query = """
        // 1. 清理旧数据 (仅测试用)
        MATCH (n) DETACH DELETE n;
        """
        
        insert_query = """
        // 2. 创建 AS 节点
        CREATE (twitter:AS {asn: '13414', name: 'Twitter', country: 'US', type: 'Content'})
        CREATE (cogent:AS {asn: '174', name: 'Cogent', country: 'US', type: 'Tier-1'})
        CREATE (rostelecom:AS {asn: '12389', name: 'Rostelecom', country: 'RU', type: 'ISP'})
        CREATE (telia:AS {asn: '1299', name: 'Telia', country: 'SE', type: 'Tier-1'})
        CREATE (google:AS {asn: '15169', name: 'Google', country: 'US', type: 'Content'})

        // 3. 创建关系 (商业拓扑)
        // Twitter 是 Cogent 的客户
        CREATE (twitter)-[:CUSTOMER_OF]->(cogent)
        CREATE (cogent)-[:PROVIDER_TO]->(twitter)
        
        // Rostelecom 是 Telia 的客户
        CREATE (rostelecom)-[:CUSTOMER_OF]->(telia)
        CREATE (telia)-[:PROVIDER_TO]->(rostelecom)

        // 4. 创建前缀节点并关联
        CREATE (p_twitter:Prefix {cidr: '104.244.42.0/24'})
        CREATE (twitter)-[:ORIGINATES]->(p_twitter)

        CREATE (p_google:Prefix {cidr: '8.8.8.0/24'})
        CREATE (google)-[:ORIGINATES]->(p_google)
        """
        
        with self.driver.session() as session:
            # 分步执行，确保清理和插入都成功
            session.run(seed_query)
            session.run(insert_query)
            print("✅ [Neo4j] 知识图谱数据注入完成 (Twitter/Rostelecom 拓扑已构建)。")

    def run(self, context):
        """
        Graph RAG 核心查询接口
        """
        prefix = context.get('prefix')
        as_path = context.get('as_path', "").split(" ")
        origin_as = as_path[-1] if as_path else None

        if not self.driver:
            return "SYSTEM_ERROR: Neo4j 数据库未连接，无法执行图分析。"

        if not origin_as:
            return "GRAPH_ERROR: 无法从路径提取 Origin AS。"

        with self.driver.session() as session:
            # --- 步骤 1: 验证前缀归属 ---
            # Cypher: 查找该 Prefix 节点的 ORIGINATES 关系来自于哪个 AS
            owner_query = """
            MATCH (p:Prefix {cidr: $prefix})<-[:ORIGINATES]-(owner:AS)
            RETURN owner.asn AS owner_asn, owner.name AS owner_name
            """
            result = session.run(owner_query, prefix=prefix).single()

            if not result:
                return f"GRAPH_MISSING: 图谱中未收录前缀 {prefix} 的归属信息，无法验证。"

            owner_asn = result["owner_asn"]
            owner_name = result["owner_name"]

            if origin_as == owner_asn:
                return f"GRAPH_VALID: [图验证通过] Origin AS{origin_as} 与图谱记录的拥有者 ({owner_name}) 一致。"

            # --- 步骤 2: 拓扑路径分析 (Shortest Path) ---
            # Cypher: 查找 Origin 和 Owner 之间的最短路径
            path_query = """
            MATCH (origin:AS {asn: $origin_as}), (owner:AS {asn: $owner_asn})
            MATCH p = shortestPath((origin)-[*]-(owner))
            RETURN length(p) AS hops, [n IN nodes(p) | n.asn] AS path_nodes
            """
            path_res = session.run(path_query, origin_as=origin_as, owner_asn=owner_asn).single()

            if path_res:
                hops = path_res["hops"]
                nodes = path_res["path_nodes"]
                return (f"GRAPH_SUSPICIOUS: [拓扑异常] Origin AS{origin_as} 不是合法拥有者 AS{owner_asn} ({owner_name})。\n"
                        f"    - 图谱距离: {hops} 跳\n"
                        f"    - 拓扑路径: {nodes}\n"
                        f"    - 结论: 两个 AS 在物理拓扑上相距甚远，直接宣告属于“拓扑瞬移”，判定为劫持。")
            else:
                return (f"GRAPH_ANOMALY: [严重拓扑隔离] Origin AS{origin_as} 与合法拥有者 AS{owner_asn} ({owner_name}) 在图谱中完全不连通！\n"
                        f"    - 结论: 物理上不可能直接宣告，判定为伪造连接。")
