"""
Pure Python SVG diagram generator for BGP-TraceX user manual.
Uses only built-in xml.etree.ElementTree - no external dependencies.
"""
from xml.etree import ElementTree as ET
from xml.dom import minidom
import os

OUTPUT_DIR = "/home/haomin_wang/code/BGP-TraceX---BGP-Anomaly-Trace-Analysis/docs/images"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Color palette — deep blue + light gray scheme
C_BG = '#ffffff'
C_PRIMARY = '#1e3a5f'      # deep navy — headers, primary borders
C_SECONDARY = '#2b5f8e'    # medium slate blue — secondary accents
C_ACCENT = '#1e3a5f'       # deep navy — unified with primary
C_SUCCESS = '#1e3a5f'      # deep navy — success/start/end nodes
C_WARNING = '#1e3a5f'      # deep navy — unified with primary
C_DANGER = '#1e3a5f'       # deep navy
C_GRAY = '#64748b'         # medium gray — arrows, secondary text
C_LIGHT = '#f1f5f9'        # very light gray — neutral backgrounds
C_LIGHT_BLUE = '#f1f5f9'   # light gray — unified container fill
C_LIGHT_GREEN = '#f1f5f9'  # light gray — unified container fill
C_LIGHT_PURPLE = '#f1f5f9' # light gray — unified container fill
C_LIGHT_ORANGE = '#f1f5f9' # light gray — unified container fill
C_BORDER = '#cbd5e1'       # slate gray — box borders
C_TEXT = '#1e293b'         # dark slate — main text
C_WHITE = '#ffffff'

FONT = 'SimHei, Microsoft YaHei, sans-serif'

def text_width_est(text, size):
    """Estimate pixel width of text. Chinese chars ~= size*1.0, ASCII ~= size*0.6."""
    w = 0.0
    for ch in text:
        if '一' <= ch <= '鿿' or '　' <= ch <= '〿' or '＀' <= ch <= '￯':
            w += size * 1.05
        elif ch.isascii():
            w += size * 0.58
        else:
            w += size * 0.9
    return w

def wrap_text(text, max_width, size):
    """Wrap text to fit within max_width. Returns list of lines."""
    if text_width_est(text, size) <= max_width:
        return [text]
    lines = []
    current = ''
    for ch in text:
        trial = current + ch
        if text_width_est(trial, size) > max_width and current:
            lines.append(current)
            current = ch
        else:
            current = trial
    if current:
        lines.append(current)
    return lines if lines else [text]

def prettify(elem):
    rough = ET.tostring(elem, 'utf-8')
    reparsed = minidom.parseString(rough)
    return reparsed.toprettyxml(indent="  ")

def add_text(svg, x, y, text, size=13, color=C_TEXT, bold=False, anchor='start', family=FONT):
    attrs = {'x': str(x), 'y': str(y), 'fill': color, 'font-family': family,
             'font-size': str(size), 'text-anchor': anchor}
    if bold:
        attrs['font-weight'] = 'bold'
    el = ET.SubElement(svg, 'text', attrs)
    el.text = text
    return el

def add_rect(svg, x, y, w, h, fill=C_WHITE, stroke=C_BORDER, rx=6, **extra):
    attrs = {'x': str(x), 'y': str(y), 'width': str(w), 'height': str(h),
             'fill': fill, 'stroke': stroke, 'rx': str(rx), 'stroke-width': '1.5'}
    attrs.update(extra)
    return ET.SubElement(svg, 'rect', attrs)

def add_rounded_rect(svg, x, y, w, h, fill=C_WHITE, stroke=C_BORDER, rx=6, **extra):
    return add_rect(svg, x, y, w, h, fill, stroke, rx, **extra)

def add_arrow(svg, x1, y1, x2, y2, color=C_TEXT, dashed=False):
    attrs = {'x1': str(x1), 'y1': str(y1), 'x2': str(x2), 'y2': str(y2),
             'stroke': color, 'stroke-width': '1.5'}
    if dashed:
        attrs['stroke-dasharray'] = '6,4'
    line = ET.SubElement(svg, 'line', attrs)
    # arrowhead
    dx, dy = x2 - x1, y2 - y1
    length = (dx**2 + dy**2) ** 0.5
    if length < 1:
        length = 1
    ux, uy = dx/length, dy/length
    # arrowhead points
    arrow_len = 8
    px, py = x2 - ux * arrow_len, y2 - uy * arrow_len
    a1x, a1y = px - uy * 4, py + ux * 4
    a2x, a2y = px + uy * 4, py - ux * 4
    poly = ET.SubElement(svg, 'polygon', {
        'points': f'{x2},{y2} {a1x},{a1y} {a2x},{a2y}',
        'fill': color
    })
    return line

def add_label_arrow(svg, x1, y1, x2, y2, label, color=C_TEXT):
    """Arrow with a text label along the middle"""
    add_arrow(svg, x1, y1, x2, y2, color)
    mx, my = (x1 + x2) / 2, (y1 + y2) / 2 - 8
    add_text(svg, mx, my, label, size=10, color=color, anchor='middle')

def add_box_with_text(svg, x, y, w, h, lines, fill=C_WHITE, stroke=C_BORDER,
                      text_color=C_TEXT, size=12, bold_first=False):
    """Draw a box with multi-line centered text. Auto-wraps long lines."""
    add_rounded_rect(svg, x, y, w, h, fill, stroke)
    total_text_h = len(lines) * (size + 4)
    start_y = y + (h - total_text_h) / 2 + size
    for i, line in enumerate(lines):
        is_bold = bold_first and i == 0
        add_text(svg, x + w/2, start_y + i * (size + 4), line,
                 size=size, color=text_color, bold=is_bold, anchor='middle')


# ============================================================
# Diagram 1: System Architecture (整体架构图)
# ============================================================
def draw_architecture():
    W, H = 1060, 800
    svg = ET.Element('svg', {
        'xmlns': 'http://www.w3.org/2000/svg',
        'viewBox': f'0 0 {W} {H}',
        'width': str(W), 'height': str(H),
        'style': f'background:{C_BG}'
    })

    # Title
    add_text(svg, W/2, 25, 'BGP-TraceX 3.0 系统整体架构', size=16, bold=True, color=C_TEXT, anchor='middle')

    # === Unified layer dimensions ===
    lx = 12          # left edge of all layers
    lw = W - 24      # full width = 1036
    box_h = 42       # standard internal box height
    y_gap = 8        # gap between layers

    # ---- Input Layer (输入层) ----
    y = 38
    h = 75
    add_rounded_rect(svg, lx, y, lw, h, fill=C_LIGHT_BLUE, stroke=C_PRIMARY, rx=8)
    add_text(svg, 22, y + 18, '输入层', size=12, bold=True, color=C_TEXT)
    iboxes = [
        (lx+20, y+28, 210, ['真实 BGP 事件', 'test_events.json']),
        (lx+260, y+28, 230, ['合成案例生成', 'benchmark_synthetic_cases.json']),
    ]
    for bx, by, bw, lines in iboxes:
        add_box_with_text(svg, bx, by, bw, box_h, lines, C_WHITE, C_BORDER, size=10, bold_first=True)
    add_arrow(svg, lx+230, y+28+box_h/2, lx+258, y+28+box_h/2, C_GRAY)

    # Arrow: input -> data collection
    y_input = y + h
    y_next = y_input + y_gap

    # ---- Data Collection Layer (数据采集层) ----
    y = y_next
    h = 75
    add_rounded_rect(svg, lx, y, lw, h, fill=C_LIGHT_GREEN, stroke=C_SUCCESS, rx=8)
    add_text(svg, 22, y + 18, '数据采集层', size=12, bold=True, color=C_TEXT)
    dboxes = [
        (lx+20, y+28, 220, ['step1_collect_events.py', 'RIS MRT / BGPlay 数据源']),
        (lx+270, y+28, 200, ['四步筛选法', '前缀→Origin→时间→VF']),
        (lx+500, y+28, 230, ['data/events/<id>/', 'meta + suspicious_updates']),
    ]
    for bx, by, bw, lines in dboxes:
        add_box_with_text(svg, bx, by, bw, box_h, lines, C_WHITE, C_BORDER, size=10, bold_first=True)
    add_arrow(svg, lx+240, y+28+box_h/2, lx+268, y+28+box_h/2, C_GRAY)
    add_arrow(svg, lx+470, y+28+box_h/2, lx+498, y+28+box_h/2, C_GRAY)
    add_arrow(svg, W/2, y_input, W/2, y, C_GRAY)  # from input layer

    # Arrow: data collection -> knowledge / reasoning
    y_dc = y + h
    y_next = y_dc + y_gap

    # ---- Knowledge Layer (知识层) [full width] ----
    y = y_next
    h = 72
    add_rounded_rect(svg, lx, y, lw, h, fill=C_LIGHT_PURPLE, stroke=C_ACCENT, rx=8)
    add_text(svg, 22, y + 18, '知识层 (预构建)', size=12, bold=True, color=C_TEXT)
    kboxes = [
        (lx+20, y+25, 170, ['auto_generator.py'], C_WHITE, C_BORDER),
        (lx+210, y+25, 180, ['full_attack_cases.jsonl'], C_WHITE, C_BORDER),
        (lx+410, y+25, 160, ['build_vector_db.py'], C_WHITE, C_BORDER),
        (lx+590, y+25, 140, ['ChromaDB 向量库'], C_WHITE, C_BORDER),
        (lx+750, y+25, 140, ['config_loader.py'], C_WHITE, C_BORDER),
        (lx+910, y+25, 115, ['风险AS / Tier-1'], C_WHITE, C_BORDER),
    ]
    for bx, by, bw, lines, fill, stroke in kboxes:
        add_box_with_text(svg, bx, by, bw, 38, lines, fill, stroke, size=9, bold_first=True)
    add_arrow(svg, lx+190, y+25+19, lx+208, y+25+19, C_GRAY)
    add_arrow(svg, lx+390, y+25+19, lx+408, y+25+19, C_GRAY)
    add_arrow(svg, lx+570, y+25+19, lx+588, y+25+19, C_GRAY)
    add_arrow(svg, W/2, y_dc, W/2, y, C_GRAY)  # from dc layer

    # Arrow: knowledge -> reasoning
    y_kl = y + h
    y_next = y_kl + y_gap

    # ---- Reasoning Layer (推理层) [full width] ----
    y = y_next
    h = 70
    add_rounded_rect(svg, lx, y, lw, h, fill=C_LIGHT_BLUE, stroke=C_PRIMARY, rx=8)
    add_text(svg, 22, y + 18, '推理层 - BGPAgent', size=12, bold=True, color=C_TEXT)
    rboxes = [
        (lx+20, y+25, 160, ['diagnose / diagnose_batch'], C_WHITE, C_BORDER),
        (lx+200, y+25, 130, ['RAG 相似案例检索'], C_WHITE, C_BORDER),
        (lx+350, y+25, 130, ['动态 Prompt 构造'], C_WHITE, C_BORDER),
        (lx+500, y+25, 130, ['LLM 三轮推理循环'], C_WHITE, C_BORDER),
        (lx+650, y+25, 120, ['工具调用分发'], C_WHITE, C_BORDER),
        (lx+790, y+25, 140, ['批量纠偏 Gate'], C_WHITE, C_BORDER),
        (lx+950, y+25, 75, ['final'], C_WHITE, C_BORDER),
    ]
    for bx, by, bw, lines, fill, stroke in rboxes:
        add_box_with_text(svg, bx, by, bw, 38, lines, fill, stroke, size=9, bold_first=True)
    # arrows between reasoning boxes
    for i in range(len(rboxes)-1):
        bx1 = rboxes[i][0] + rboxes[i][2]
        bx2 = rboxes[i+1][0]
        add_arrow(svg, bx1, y+25+19, bx2, y+25+19, C_GRAY)
    add_arrow(svg, W/2, y_kl, W/2, y, C_GRAY)  # from knowledge layer

    # Arrow: reasoning -> tool
    y_rl = y + h
    y_next = y_rl + y_gap

    # ---- Tool Layer (工具层) ----
    y = y_next
    h = 110
    add_rounded_rect(svg, lx, y, lw, h, fill=C_LIGHT_ORANGE, stroke=C_WARNING, rx=8)
    add_text(svg, 22, y + 18, '工具层 - BGPToolKit (7 个取证工具)', size=12, bold=True, color=C_TEXT)

    tool_names = [
        'path_forensics\nAS_PATH 取证',
        'authority_check\nRPKI 授权验证',
        'forgery_check\n路径伪造检测',
        'graph_analysis\nNeo4j 拓扑分析',
        'topology_check\nValley-Free 检测',
        'geo_check\n地理位置冲突',
        'neighbor_check\n邻居信誉',
    ]
    # Calculate tool box widths evenly
    tool_gap = 10
    tool_area_w = lw - 30  # margins inside layer
    tool_w = (tool_area_w - tool_gap * 6) // 7
    tool_x0 = lx + 16

    for i, tlabel in enumerate(tool_names):
        tx = tool_x0 + i * (tool_w + tool_gap)
        add_box_with_text(svg, tx, y+28, tool_w, 72, tlabel.split('\n'), C_WHITE, C_BORDER, size=9, bold_first=True)
        # Dashed arrow from reasoning to each tool
        add_arrow(svg, tx + tool_w/2, y_rl, tx + tool_w/2, y, C_GRAY, dashed=True)

    # Arrow: tool -> output
    y_tl = y + h
    y_next = y_tl + y_gap

    # ---- Output Layer (输出层) ----
    y = y_next
    h = 110
    add_rounded_rect(svg, lx, y, lw, h, fill=C_LIGHT_GREEN, stroke=C_SUCCESS, rx=8)
    add_text(svg, 22, y + 18, '输出层', size=12, bold=True, color=C_TEXT)
    oboxes = [
        (lx+20, y+28, 230, ['report/forensics/*.json', '溯源过程报告'], C_WHITE, C_BORDER),
        (lx+270, y+28, 200, ['控制台准确率统计', '命中/未命中 + 总体准确率'], C_WHITE, C_BORDER),
        (lx+490, y+28, 250, ['comparative_experiment.py', 'M1/M2/M3/M4 四方法对比评估'], C_WHITE, C_BORDER),
        (lx+760, y+28, 250, ['report/evaluation/*.json', '评估统计报告 + 图表输出'], C_WHITE, C_BORDER),
    ]
    for bx, by, bw, lines, fill, stroke in oboxes:
        add_box_with_text(svg, bx, by, bw, box_h, lines, fill, stroke, size=10, bold_first=True)
    add_arrow(svg, lx+250, y+28+box_h/2, lx+268, y+28+box_h/2, C_GRAY)
    add_arrow(svg, lx+470, y+28+box_h/2, lx+488, y+28+box_h/2, C_GRAY)
    add_arrow(svg, lx+740, y+28+box_h/2, lx+758, y+28+box_h/2, C_GRAY)
    add_arrow(svg, W/2, y_tl, W/2, y, C_GRAY)  # from tool layer

    # Legend
    add_text(svg, 22, H - 8, '实线: 数据流  |  虚线: 工具调用  |  蓝色: 推理核心  |  橙色: 工具/配置  |  紫色: 知识/预构建', size=9, color=C_TEXT)

    return prettify(svg)


# ============================================================
# Diagram 2: Data Flow Overview (数据流总览)
# ============================================================
def draw_dataflow():
    W, H = 900, 180
    svg = ET.Element('svg', {
        'xmlns': 'http://www.w3.org/2000/svg',
        'viewBox': f'0 0 {W} {H}',
        'width': str(W), 'height': str(H),
        'style': f'background:{C_BG}'
    })

    add_text(svg, W/2, 25, '端到端数据流总览', size=16, bold=True, color=C_TEXT, anchor='middle')

    steps = [
        ('Step0\nRAG 预构建', C_WHITE, C_ACCENT),
        ('Step1\n告警配置', C_WHITE, C_PRIMARY),
        ('Step2\n数据抓取筛选', C_WHITE, C_SUCCESS),
        ('Step3\nAgent 溯源评估', C_WHITE, C_WARNING),
        ('Step4\n对比实验绘图', C_WHITE, C_GRAY),
    ]

    box_w, box_h = 130, 60
    start_x = 55
    gap = 40
    y = 70

    for i, (label, fill, stroke) in enumerate(steps):
        x = start_x + i * (box_w + gap)
        add_box_with_text(svg, x, y, box_w, box_h, label.split('\n'), fill, stroke, size=12, bold_first=True)
        if i < len(steps) - 1:
            add_arrow(svg, x + box_w + 2, y + box_h/2, x + box_w + gap - 2, y + box_h/2, C_GRAY)

    # Dashed line from Step0 to Step3 (RAG dependency)
    x0 = start_x + box_w/2
    x3 = start_x + 3 * (box_w + gap) + box_w/2
    add_arrow(svg, x0, y + box_h + 15, x3, y + box_h + 15, C_ACCENT, dashed=True)
    add_text(svg, (x0+x3)/2, y + box_h + 12, '提供历史案例检索', size=10, color=C_TEXT, anchor='middle')

    return prettify(svg)


# ============================================================
# Diagram 3: Installation Flow (安装流程图)
# ============================================================
def draw_installation():
    W, H = 520, 520
    svg = ET.Element('svg', {
        'xmlns': 'http://www.w3.org/2000/svg',
        'viewBox': f'0 0 {W} {H}',
        'width': str(W), 'height': str(H),
        'style': f'background:{C_BG}'
    })

    add_text(svg, W/2, 25, '安装流程', size=16, bold=True, color=C_TEXT, anchor='middle')

    # Flowchart nodes arranged vertically
    cx = W/2
    bw, bh = 200, 40

    steps = [
        (40, '克隆仓库', C_WHITE, C_BORDER),
        (95, '安装 Python 依赖', C_WHITE, C_BORDER),
        (150, '配置环境变量 (.env)', C_WHITE, C_BORDER),
    ]

    for y, label, fill, stroke in steps:
        add_box_with_text(svg, cx-bw/2, y, bw, bh, [label], fill, stroke, size=12)
        if y > 50:
            add_arrow(svg, cx, y-10, cx, y-2, C_GRAY)

    # Decision diamond: HuggingFace mirror?
    dy = 215
    add_box_with_text(svg, cx-bw/2, dy, bw, 40, ['需要 HuggingFace 镜像?'], C_WHITE, C_WARNING, size=11)

    # Yes branch - repositioned to stay within bounds (main_left=160, so yes_left=30)
    yes_left = 30
    yes_w = 160
    add_box_with_text(svg, yes_left, 285, yes_w, 36, ['设置 HF_ENDPOINT'], C_WHITE, C_PRIMARY, size=11)
    add_arrow(svg, cx-bw/2, dy+20, yes_left+yes_w/2, 285, C_GRAY)
    add_text(svg, cx-bw/2-30, dy+40, '是', size=10, color=C_TEXT, anchor='middle')

    # No branch
    no_left = cx + 40
    add_box_with_text(svg, no_left, 280, 90, 30, ['跳过'], C_WHITE, C_BORDER, size=11)
    add_arrow(svg, cx+bw/2, dy+20, no_left+45, 280, C_GRAY)
    add_text(svg, cx+bw/2+15, dy+10, '否', size=10, color=C_TEXT, anchor='middle')

    # Merge back
    add_arrow(svg, yes_left+yes_w/2, 321, cx-bw/2+60, 350, C_GRAY)
    add_arrow(svg, no_left+45, 310, cx, 350, C_GRAY)

    # Verify install
    add_box_with_text(svg, cx-bw/2, 355, bw, 36, ['验证安装 (test-api.py)'], C_WHITE, C_BORDER, size=11)
    add_arrow(svg, cx, 350, cx, 355, C_GRAY)

    # Decision: Neo4j?
    add_box_with_text(svg, cx-bw/2, 415, bw, 40, ['需要 Neo4j?'], C_WHITE, C_WARNING, size=11)

    # Yes branch - repositioned
    add_box_with_text(svg, yes_left, 480, yes_w, 30, ['启动 Neo4j 并配置密码'], C_WHITE, C_PRIMARY, size=11)
    add_arrow(svg, cx-bw/2, 435, yes_left+yes_w/2, 480, C_GRAY)
    add_text(svg, cx-bw/2-30, 450, '是', size=10, color=C_TEXT, anchor='middle')

    # No branch
    add_box_with_text(svg, no_left, 480, 90, 30, ['跳过'], C_WHITE, C_BORDER, size=11)
    add_arrow(svg, cx+bw/2, 435, no_left+45, 480, C_GRAY)
    add_text(svg, cx+bw/2+15, 430, '否', size=10, color=C_TEXT, anchor='middle')

    return prettify(svg)


# ============================================================
# Diagram 4: Use Case (用例图)
# ============================================================
def draw_usecase():
    W, H = 820, 520
    svg = ET.Element('svg', {
        'xmlns': 'http://www.w3.org/2000/svg',
        'viewBox': f'0 0 {W} {H}',
        'width': str(W), 'height': str(H),
        'style': f'background:{C_BG}'
    })

    add_text(svg, W/2, 25, 'BGP-TraceX 用例图', size=16, bold=True, color=C_TEXT, anchor='middle')

    # System boundary
    sys_x, sys_y, sys_w, sys_h = 170, 50, 630, 400
    add_rounded_rect(svg, sys_x, sys_y, sys_w, sys_h, fill=C_LIGHT_BLUE, stroke=C_PRIMARY, rx=10)
    add_text(svg, 180, sys_y + 20, 'BGP-TraceX 系统', size=13, bold=True, color=C_TEXT)

    # Actor (stick figure simplified as circle + text)
    actor_x, actor_y = 55, 230
    ET.SubElement(svg, 'circle', {'cx': str(actor_x), 'cy': str(actor_y-25), 'r': '12', 'fill': 'none', 'stroke': C_TEXT, 'stroke-width': '2'})
    ET.SubElement(svg, 'line', {'x1': str(actor_x), 'y1': str(actor_y-13), 'x2': str(actor_x), 'y2': str(actor_y+30), 'stroke': C_TEXT, 'stroke-width': '2'})
    ET.SubElement(svg, 'line', {'x1': str(actor_x), 'y1': str(actor_y+2), 'x2': str(actor_x-20), 'y2': str(actor_y+20), 'stroke': C_TEXT, 'stroke-width': '1.5'})
    ET.SubElement(svg, 'line', {'x1': str(actor_x), 'y1': str(actor_y+2), 'x2': str(actor_x+20), 'y2': str(actor_y+20), 'stroke': C_TEXT, 'stroke-width': '1.5'})
    add_text(svg, actor_x, actor_y+48, '研究人员', size=12, bold=True, anchor='middle')

    # Use cases
    use_cases = [
        (200, 75, '构建 RAG 知识库'),
        (200, 145, '抓取真实 BGP 事件'),
        (200, 215, '单条告警溯源'),
        (200, 285, '批量告警溯源'),
        (450, 75, '生成合成基准案例'),
        (450, 145, '运行四方法对比实验'),
        (450, 215, '运行指标评估实验'),
        (450, 285, '生成评估图表'),
        (620, 340, '单案例全系统重跑'),
    ]

    ucx, ucy, ucw, uch = 0, 0, 160, 50
    erx, ery = 85, 20  # ellipse radii
    for ux, uy, label in use_cases:
        # Ellipse for use case
        ET.SubElement(svg, 'ellipse', {
            'cx': str(ux + erx), 'cy': str(uy + uch/2),
            'rx': str(erx), 'ry': str(ery),
            'fill': C_WHITE, 'stroke': C_BORDER, 'stroke-width': '1.5'
        })
        add_text(svg, ux + erx, uy + uch/2 + 5, label, size=10, color=C_TEXT, anchor='middle')

    # Calculate intersection of line from actor to ellipse edge
    def ellipse_intersect(ax, ay, ecx, ecy):
        """Return point on ellipse edge along line from (ax,ay) to center (ecx,ecy)."""
        import math
        px = ax - ecx
        py = ay - ecy
        # Guard against degenerate case
        d = math.sqrt(px*px/(erx*erx) + py*py/(ery*ery))
        if d < 0.001:
            return ecx, ecy
        s = 1.0 / d  # (1-t) = s, factor to reach ellipse edge from center
        return ecx + s * px, ecy + s * py

    # Lines from actor to use cases (stop at ellipse edge)
    a_src_y_1 = actor_y + 15
    a_src_y_2 = actor_y + 20
    for ux, uy, label in use_cases[:4]:
        ecx, ecy = ux + erx, uy + uch/2
        ex, ey = ellipse_intersect(actor_x+12, a_src_y_1, ecx, ecy)
        add_arrow(svg, actor_x+12, a_src_y_1, ex, ey, C_GRAY)
    for ux, uy, label in use_cases[4:8]:
        ecx, ecy = ux + erx, uy + uch/2
        ex, ey = ellipse_intersect(actor_x+12, a_src_y_2, ecx, ecy)
        add_arrow(svg, actor_x+12, a_src_y_2, ex, ey, C_GRAY)
    # Last use case (index 8)
    if len(use_cases) > 8:
        ux, uy, label = use_cases[8]
        ecx, ecy = ux + erx, uy + uch/2
        ex, ey = ellipse_intersect(actor_x+12, a_src_y_2, ecx, ecy)
        add_arrow(svg, actor_x+12, a_src_y_2, ex, ey, C_GRAY)

    # Notes
    note_x, note_y = 510, 385
    add_rounded_rect(svg, note_x, note_y, 290, 60, fill=C_LIGHT, stroke=C_BORDER, rx=4, **{'stroke-dasharray': '4,2'})
    add_text(svg, note_x+8, note_y+18, 'M1: RAG+LLM+Tools  M2: 仅 LLM', size=9, color=C_TEXT)
    add_text(svg, note_x+8, note_y+33, 'M3: 规则检测  M4: RAG+LLM (无工具)', size=9, color=C_TEXT)
    add_text(svg, note_x+8, note_y+48, '批量模式推荐使用 diagnose_batch', size=9, color=C_TEXT)

    return prettify(svg)


# ============================================================
# Diagram 5: Batch Diagnosis Flow (批量溯源内部流程)
# ============================================================
def draw_batch_flow():
    W, H = 740, 730
    svg = ET.Element('svg', {
        'xmlns': 'http://www.w3.org/2000/svg',
        'viewBox': f'0 0 {W} {H}',
        'width': str(W), 'height': str(H),
        'style': f'background:{C_BG}'
    })

    add_text(svg, W/2, 22, '批量溯源内部流程', size=16, bold=True, color=C_TEXT, anchor='middle')

    cx = W/2
    bw, bh = 280, 40

    # Start
    y = 38
    add_rounded_rect(svg, cx-50, y, 100, 30, fill=C_PRIMARY, stroke=C_PRIMARY, rx=15)
    add_text(svg, cx, y+20, '开始', size=11, color=C_WHITE, bold=True, anchor='middle')

    # Input box
    y = 80
    add_box_with_text(svg, cx-bw/2, y, bw, 50, ['输入: alert_batch', '{time_window, updates[]}'], C_WHITE, C_PRIMARY, size=11, bold_first=True)
    add_arrow(svg, cx, y-10, cx, y-2, C_GRAY)

    # Precheck diamond
    y = 150
    diamond_w, diamond_h = 240, 55
    pts = f'{cx},{y} {cx+diamond_w/2},{y+diamond_h/2} {cx},{y+diamond_h} {cx-diamond_w/2},{y+diamond_h/2}'
    ET.SubElement(svg, 'polygon', {
        'points': pts, 'fill': C_LIGHT_ORANGE, 'stroke': C_WARNING, 'stroke-width': '1.5'
    })
    add_text(svg, cx, y+diamond_h/2+5, '预检: 路径长度≤2', size=10, anchor='middle')
    add_text(svg, cx, y+diamond_h/2+18, '+ 合法Origin?', size=10, anchor='middle')
    add_arrow(svg, cx, y-10, cx, y-2, C_GRAY)

    # Fast BENIGN (left) — stops here, no further processing
    add_box_with_text(svg, cx-bw-80, 230, 150, 50, ['快速判定: BENIGN', '直接输出结论'], C_WHITE, C_SUCCESS, size=10, bold_first=True)
    add_arrow(svg, cx-diamond_w/2, y+diamond_h/2, cx-bw-80+75, 230, C_GRAY)
    add_text(svg, cx-diamond_w/2-20, y+diamond_h/2+15, '是', size=10, color=C_TEXT, anchor='middle')

    # Continue (right) - suspected FORGERY → continues to Phase 1
    forgery_lx = cx + bw - 80
    forgery_w = 150
    add_box_with_text(svg, forgery_lx, 230, forgery_w, 50, ['快速标记: 疑似 FORGERY', '进入完整流程'], C_WHITE, C_WARNING, size=10, bold_first=True)
    add_arrow(svg, cx+diamond_w/2, y+diamond_h/2, forgery_lx + forgery_w/2, 230, C_GRAY)
    add_text(svg, cx+diamond_w/2+15, y+diamond_h/2+15, '否', size=10, color=C_TEXT, anchor='middle')

    # Phase 1: RAG
    y = 310
    add_rounded_rect(svg, cx-bw/2-20, y, bw+40, 80, fill=C_LIGHT_PURPLE, stroke=C_ACCENT, rx=6)
    add_text(svg, cx-bw/2-12, y+18, 'Phase 1: 批量 RAG 检索', size=12, bold=True, color=C_TEXT)
    add_text(svg, cx-bw/2-4, y+38, 'search_similar_cases_batch', size=10, color=C_TEXT)
    add_text(svg, cx-bw/2-4, y+55, '签名聚合 → 加权合并 → 动态 Top-K → 阈值拒绝', size=10, color=C_TEXT)
    add_text(svg, cx-bw/2-4, y+72, '输出: 历史案例参考文本 + 共识诊断信息', size=10, color=C_TEXT)
    # Arrow from FORGERY box bottom to Phase 1 top (L-shaped path)
    phase1_right = cx + bw/2 + 20  # Phase 1 right edge = 530
    add_arrow(svg, forgery_lx + forgery_w/2, 280, forgery_lx + forgery_w/2, 290, C_GRAY)
    add_arrow(svg, forgery_lx + forgery_w/2, 290, phase1_right, 290, C_GRAY)
    add_arrow(svg, phase1_right, 290, phase1_right, 308, C_GRAY)

    # Phase 2: Prompt
    y = 420
    add_rounded_rect(svg, cx-bw/2-20, y, bw+40, 50, fill=C_LIGHT_BLUE, stroke=C_PRIMARY, rx=6)
    add_text(svg, cx-bw/2-12, y+18, 'Phase 2: 动态 Prompt 构造', size=12, bold=True, color=C_TEXT)
    add_text(svg, cx-bw/2-4, y+38, 'System Prompt + RAG 参考文本 + updates 列表', size=10, color=C_TEXT)
    add_arrow(svg, cx, 395, cx, 418, C_GRAY)

    # Phase 3: LLM loop
    y = 500
    add_rounded_rect(svg, cx-bw/2-20, y, bw+40, 48, fill=C_LIGHT_ORANGE, stroke=C_WARNING, rx=6)
    add_text(svg, cx-bw/2-12, y+18, 'Phase 3: LLM 推理循环 (最多 3 轮)', size=12, bold=True, color=C_TEXT)
    add_text(svg, cx-bw/2-4, y+38, '思考 → 请求工具 → 工具返回 → 再思考 → ... → 输出结论', size=10, color=C_TEXT)
    add_arrow(svg, cx, 473, cx, 498, C_GRAY)

    # Tools box with loop back arrow
    add_box_with_text(svg, cx-bw/2+320, y+5, 150, 38, ['调用取证工具', 'path_forensics 等'], C_WHITE, C_BORDER, size=9, bold_first=True)
    # Loop arrow from LLM to tools (arrow stops at box edge)
    tool_left = cx - bw/2 + 320
    add_arrow(svg, cx+bw/2+18, y+24, tool_left - 2, y+24, C_GRAY, dashed=True)

    # Phase 4: Gate
    y = 580
    add_rounded_rect(svg, cx-bw/2-60, y, bw+120, 70, fill=C_LIGHT_GREEN, stroke=C_SUCCESS, rx=6)
    add_text(svg, cx-bw/2-52, y+18, 'Phase 4: 批量纠偏 Gate (5道门控)', size=12, bold=True, color=C_TEXT)
    gate_rules = [
        'G1:低共识→降级BENIGN    G2:工具冲突→拒绝LLM    G3:RAG过加权校正',
        'G4:强证据→覆盖    G5:无证据→Uncertain',
    ]
    for gi, rule_line in enumerate(gate_rules):
        add_text(svg, cx-bw/2-52, y+40+gi*16, rule_line, size=9, color=C_TEXT)
    add_text(svg, cx-bw/2-52, y+70, '输出: 校正后的 final_decision', size=10, color=C_TEXT)
    add_arrow(svg, cx, 553, cx, 578, C_GRAY)

    # Final
    y = 680
    add_rounded_rect(svg, cx-60, y, 120, 35, fill=C_SUCCESS, stroke=C_SUCCESS, rx=15)
    add_text(svg, cx, y+23, '结束', size=11, color=C_WHITE, bold=True, anchor='middle')
    add_arrow(svg, cx, 653, cx, 678, C_GRAY)
    # Arrow from BENIGN box to End (BENIGN skips phases, goes directly to end)
    add_arrow(svg, cx-bw-80+75, 280, cx-60+60, 678, C_GRAY, dashed=True)

    return prettify(svg)


# ============================================================
# Diagram 6: Experiment Overview (实验体系总览)
# ============================================================
def draw_experiment():
    W, H = 800, 380
    svg = ET.Element('svg', {
        'xmlns': 'http://www.w3.org/2000/svg',
        'viewBox': f'0 0 {W} {H}',
        'width': str(W), 'height': str(H),
        'style': f'background:{C_BG}'
    })

    add_text(svg, W/2, 25, '实验体系总览', size=16, bold=True, color=C_TEXT, anchor='middle')

    # Benchmark preparation (top center)
    add_box_with_text(svg, W/2-100, 40, 200, 36, ['基准数据准备'], C_WHITE, C_PRIMARY, size=12, bold_first=True)

    # Two branches
    add_box_with_text(svg, 60, 110, 240, 50, ['合成基准生成', 'generate_benchmark_synthetic_cases.py'], C_WHITE, C_BORDER, size=10, bold_first=True)
    add_box_with_text(svg, 500, 110, 240, 50, ['真实事件采集', 'step1_collect_events.py'], C_WHITE, C_BORDER, size=10, bold_first=True)

    add_arrow(svg, W/2-100+100, 76, 60+120, 110, C_GRAY)
    add_arrow(svg, W/2+100, 76, 500+120, 110, C_GRAY)

    # Experiment boxes
    exp_y = 200
    add_box_with_text(svg, 30, exp_y, 180, 50, ['四方法对比实验 (合成)', 'run_comparative_synthetic.py'], C_WHITE, C_ACCENT, size=9, bold_first=True)
    add_box_with_text(svg, 250, exp_y, 180, 50, ['真实事件对比实验', 'run_comparative_real_pipeline.py'], C_WHITE, C_ACCENT, size=9, bold_first=True)
    add_box_with_text(svg, 470, exp_y, 200, 50, ['指标实验', 'run_synthetic_metrics_experiment.py'], C_WHITE, C_WARNING, size=9, bold_first=True)

    add_arrow(svg, 60+120, 160, 30+90, exp_y, C_GRAY)
    add_arrow(svg, 60+120, 160, 250+90, exp_y, C_GRAY)
    add_arrow(svg, 60+120, 160, 470+100, exp_y, C_GRAY)
    add_arrow(svg, 500+120, 160, 250+90, exp_y, C_GRAY)

    # Plot generation
    add_box_with_text(svg, 230, 290, 240, 50, ['图表生成', 'plot_real_synthetic_method_figures.py'], C_WHITE, C_SUCCESS, size=10, bold_first=True)
    for ex, ey, ew in [(30, exp_y, 180), (250, exp_y, 180), (470, exp_y, 200)]:
        add_arrow(svg, ex+ew/2, ey+50, 230+120, 290, C_GRAY)

    # Output
    add_box_with_text(svg, 550, 310, 220, 36, ['report/evaluation/figures/'], C_WHITE, C_BORDER, size=10, bold_first=True)
    add_arrow(svg, 470, 315, 548, 328, C_GRAY)

    # Legend
    add_text(svg, 30, 370, '四方法: M1(RAG+LLM+Tools)  M2(仅LLM)  M3(规则检测)  M4(RAG+LLM)', size=9, color=C_TEXT)

    return prettify(svg)


# ============================================================
# Generate all diagrams
# ============================================================
if __name__ == "__main__":
    diagrams = [
        ('01_system_architecture.svg', draw_architecture),
        ('02_data_flow.svg', draw_dataflow),
        ('03_installation_flow.svg', draw_installation),
        ('04_use_case.svg', draw_usecase),
        ('05_batch_diagnosis_flow.svg', draw_batch_flow),
        ('06_experiment_overview.svg', draw_experiment),
    ]

    for filename, draw_func in diagrams:
        print(f"Drawing {filename}...")
        svg_content = draw_func()
        filepath = os.path.join(OUTPUT_DIR, filename)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(svg_content)
        size_kb = len(svg_content) / 1024
        print(f"  -> Saved {filepath} ({size_kb:.1f} KB)")

    print(f"\nAll {len(diagrams)} diagrams generated in {OUTPUT_DIR}/")
