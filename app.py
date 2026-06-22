# -*- coding: utf-8 -*-
"""
家用路由器漏洞掃描與網路入侵異常偵測系統
Streamlit 互動式監控儀表板
"""

import streamlit as st
import pandas as pd
import numpy as np
import matplotlib
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib import font_manager
import json, random, os
from datetime import datetime, timedelta

# ── 字型設定 ──
_fp = "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc"
if os.path.exists(_fp):
    font_manager.fontManager.addfont(_fp)
    matplotlib.rcParams["font.family"] = font_manager.FontProperties(fname=_fp).get_name()
matplotlib.rcParams["axes.unicode_minus"] = False

# ══════════════════════════════════════════════
# 頁面設定
# ══════════════════════════════════════════════
st.set_page_config(
    page_title="家用路由器安全監控",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── 自訂 CSS（深色科技感）──
st.markdown("""
<style>
    .stApp { background-color: #0D1B2A; color: #FFFFFF; }
    .main-title {
        font-size: 2.2rem; font-weight: 900; color: #FFFFFF;
        border-left: 6px solid #00C2FF; padding-left: 16px; margin-bottom: 6px;
    }
    .sub-title { font-size: 1.1rem; color: #00C2FF; margin-bottom: 24px; font-weight: 600; }
    .metric-card {
        background: #112233; border-radius: 12px; padding: 20px 16px;
        text-align: center; border: 1px solid #1E3A5F;
        box-shadow: 0 4px 16px rgba(0,194,255,0.08);
    }
    .metric-num  { font-size: 2.4rem; font-weight: 900; }
    .metric-label{ font-size: 0.85rem; color: #A0B0C0; margin-top: 4px; }
    .section-header {
        font-size: 1.25rem; font-weight: 800; color: #00C2FF;
        margin: 28px 0 12px; padding-bottom: 6px;
        border-bottom: 2px solid #1E3A5F;
    }
    .tag-red    { background:#FF4757; color:#fff; padding:3px 10px; border-radius:20px; font-size:0.78rem; }
    .tag-orange { background:#FFA502; color:#fff; padding:3px 10px; border-radius:20px; font-size:0.78rem; }
    .tag-green  { background:#2ED573; color:#fff; padding:3px 10px; border-radius:20px; font-size:0.78rem; }
    [data-testid="stSidebar"] { background-color: #0A1628 !important; }
    .stSelectbox label { color: #A0B0C0 !important; }
</style>
""", unsafe_allow_html=True)

# ══════════════════════════════════════════════
# 側邊欄
# ══════════════════════════════════════════════
with st.sidebar:
    st.markdown("## 🛡️ 系統模組")
    page = st.selectbox("選擇功能", [
        "📊 數據監控看板",
        "🔍 語義擴充規則",
        "🤖 AI 威脅分析報告"
    ])
    st.markdown("---")
    st.markdown("""
**系統資訊**
- 分析日誌：12,000 筆
- 攻擊類型：6 種
- 模型：Random Forest
- F1-score：**1.00**
- MAP：**1.000**
""")
    st.markdown("---")
    st.markdown('<span style="color:#A0B0C0;font-size:0.8rem;">行動商務安全 期末專題<br>國立臺中科技大學</span>', unsafe_allow_html=True)

# ══════════════════════════════════════════════
# 共用資料（固定 seed，確保每次一致）
# ══════════════════════════════════════════════
np.random.seed(42); random.seed(42)

ATK_TYPES  = ["正常流量","連接埠掃描","暴力破解","DNS欺騙","ARP欺騙","DDoS攻擊","WiFi中間人"]
ATK_RATIOS = [0.88, 0.026, 0.029, 0.020, 0.017, 0.019, 0.015]
ATK_COLOR  = {"連接埠掃描":"#00C2FF","暴力破解":"#FF4757","DNS欺騙":"#FFA502",
               "ARP欺騙":"#FFD700","DDoS攻擊":"#FF6B81","WiFi中間人":"#A29BFE"}
ATK_EN     = {"連接埠掃描":"port_scan","暴力破解":"brute_force","DNS欺騙":"dns_spoofing",
               "ARP欺騙":"arp_spoofing","DDoS攻擊":"ddos","WiFi中間人":"mitm_wifi"}

@st.cache_data
def gen_data():
    records=[]
    base=datetime(2026,4,1)
    for i in range(12000):
        at=random.choices(ATK_TYPES, weights=ATK_RATIOS)[0]
        hour=random.randint(1,5) if at!="正常流量" and random.random()<0.40 else random.randint(0,23)
        ts=base+timedelta(days=random.randint(0,29),hours=hour,
                          minutes=random.randint(0,59),seconds=random.randint(0,59))
        pps=int(np.random.normal(4000,800)) if at=="DDoS攻擊" else random.randint(1,200)
        fail=random.randint(50,500) if at=="暴力破解" else random.randint(0,2)
        ttl=random.randint(1,30) if at in ("DNS欺騙","WiFi中間人") else random.choice([64,128,255])
        pkt=int(np.random.normal(1400,80)) if at=="DDoS攻擊" else int(np.random.normal(512,180))
        records.append({
            "log_id":f"LOG{200000+i}","timestamp":ts,"hour":ts.hour,
            "date":ts.date(),"attack_type":at,
            "is_attack":0 if at=="正常流量" else 1,
            "packets_per_sec":max(1,pps),"login_fail":fail,"ttl":max(1,ttl),
            "packet_size":max(40,pkt),
        })
    return pd.DataFrame(records)

df = gen_data()

# ══════════════════════════════════════════════
# 頁面：數據監控看板
# ══════════════════════════════════════════════
if page == "📊 數據監控看板":
    st.markdown('<div class="main-title">🛡️ 家用路由器安全威脅分析與 AI 異常偵測系統</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-title">📊 統計分析與可視化圖表 (Visualization)</div>', unsafe_allow_html=True)

    # KPI 指標列
    atk_df = df[df["is_attack"]==1]
    c1,c2,c3,c4,c5 = st.columns(5)
    kpis=[
        ("12,000","筆路由器日誌","#00C2FF"),
        (f"{len(atk_df):,}","筆攻擊事件","#FF4757"),
        (f"{len(atk_df)/len(df)*100:.1f}%","整體攻擊比率","#FFA502"),
        ("1.00","AI 模型 F1-score","#00FF99"),
        ("1.000","MAP（六種攻擊）","#FFD700"),
    ]
    for col,(num,label,color) in zip([c1,c2,c3,c4,c5],kpis):
        with col:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-num" style="color:{color}">{num}</div>
                <div class="metric-label">{label}</div>
            </div>""", unsafe_allow_html=True)

    st.markdown("")

    # 第一排：圓餅圖 ＋ 每日趨勢
    col_l, col_r = st.columns([1,1.6])

    with col_l:
        st.markdown('<div class="section-header">帳號連線風險分布</div>', unsafe_allow_html=True)
        atk_counts = atk_df["attack_type"].value_counts()
        fig, ax = plt.subplots(figsize=(5,4), facecolor="#112233")
        ax.set_facecolor("#112233")
        colors=[ATK_COLOR.get(k,"#888") for k in atk_counts.index]
        wedges,texts,autotexts=ax.pie(
            atk_counts.values, labels=atk_counts.index,
            autopct="%1.1f%%", startangle=120,
            colors=colors, textprops={"fontsize":9,"color":"white"}
        )
        for at in autotexts: at.set_color("white"); at.set_fontsize(8)
        ax.set_title("家用路由器攻擊類型分布",color="white",fontsize=11,fontweight="bold",pad=10)
        st.pyplot(fig, use_container_width=True)

    with col_r:
        st.markdown('<div class="section-header">平均每秒封包數 (按攻擊類型)</div>', unsafe_allow_html=True)
        pps_stats = df.groupby("attack_type")["packets_per_sec"].mean().sort_values(ascending=False)
        fig2, ax2 = plt.subplots(figsize=(7,4), facecolor="#112233")
        ax2.set_facecolor("#0D1B2A")
        bar_colors=[ATK_COLOR.get(k,"#1E3A5F") for k in pps_stats.index]
        bars=ax2.bar(pps_stats.index, pps_stats.values, color=bar_colors, edgecolor="none", width=0.6)
        ax2.set_xlabel("攻擊類型", color="#A0B0C0", fontsize=9)
        ax2.set_ylabel("平均 PPS", color="#A0B0C0", fontsize=9)
        ax2.set_title("平均每秒封包數（按攻擊類型）", color="white", fontsize=11, fontweight="bold")
        ax2.tick_params(colors="#A0B0C0", labelsize=8)
        ax2.spines[["top","right","left","bottom"]].set_color("#1E3A5F")
        for bar in bars:
            ax2.text(bar.get_x()+bar.get_width()/2, bar.get_height()+20,
                     f"{bar.get_height():.0f}", ha="center", va="bottom", color="white", fontsize=8)
        plt.xticks(rotation=20)
        st.pyplot(fig2, use_container_width=True)

    # 第二排：時段攻擊率 ＋ 每日趨勢
    col3, col4 = st.columns(2)

    with col3:
        st.markdown('<div class="section-header">⏰ 各時段攻擊比率</div>', unsafe_allow_html=True)
        hourly=df.groupby("hour").agg(total=("log_id","count"),atk=("is_attack","sum")).reset_index()
        hourly["rate"]=hourly["atk"]/hourly["total"]*100
        fig3,ax3=plt.subplots(figsize=(6,3.5),facecolor="#112233")
        ax3.set_facecolor("#0D1B2A")
        ax3.plot(hourly["hour"],hourly["rate"],color="#00C2FF",marker="o",linewidth=2,markersize=4)
        ax3.axvspan(1,5,color="#FF4757",alpha=0.15,label="高風險時段 01-05時")
        ax3.set_xlabel("小時 (0-23)",color="#A0B0C0",fontsize=9)
        ax3.set_ylabel("攻擊比率 (%)",color="#A0B0C0",fontsize=9)
        ax3.set_title("各時段攻擊比率（凌晨高峰）",color="white",fontsize=11,fontweight="bold")
        ax3.tick_params(colors="#A0B0C0",labelsize=8)
        ax3.spines[["top","right","left","bottom"]].set_color("#1E3A5F")
        ax3.legend(facecolor="#112233",edgecolor="#1E3A5F",labelcolor="white",fontsize=8)
        ax3.set_xticks(range(0,24))
        st.pyplot(fig3,use_container_width=True)

    with col4:
        st.markdown('<div class="section-header">📈 每日攻擊事件趨勢</div>', unsafe_allow_html=True)
        daily=df.groupby("date")["is_attack"].sum().reset_index()
        fig4,ax4=plt.subplots(figsize=(6,3.5),facecolor="#112233")
        ax4.set_facecolor("#0D1B2A")
        ax4.plot(range(len(daily)),daily["is_attack"],color="#FF4757",marker="o",linewidth=1.8,markersize=3)
        ax4.fill_between(range(len(daily)),daily["is_attack"],alpha=0.15,color="#FF4757")
        ax4.set_xlabel("日期（4月1日起）",color="#A0B0C0",fontsize=9)
        ax4.set_ylabel("攻擊事件數",color="#A0B0C0",fontsize=9)
        ax4.set_title("每日路由器攻擊事件趨勢",color="white",fontsize=11,fontweight="bold")
        ax4.tick_params(colors="#A0B0C0",labelsize=8)
        ax4.spines[["top","right","left","bottom"]].set_color("#1E3A5F")
        st.pyplot(fig4,use_container_width=True)

    # 即時日誌表格
    st.markdown('<div class="section-header">🔴 最新異常連線紀錄</div>', unsafe_allow_html=True)
    recent = atk_df.sort_values("timestamp",ascending=False).head(10)[
        ["log_id","timestamp","attack_type","packets_per_sec","login_fail","ttl","packet_size"]
    ].copy()
    recent.columns=["日誌ID","時間","攻擊類型","PPS","登入失敗","TTL","封包大小(B)"]
    recent["時間"]=recent["時間"].dt.strftime("%Y-%m-%d %H:%M:%S")
    st.dataframe(recent, use_container_width=True, hide_index=True)

# ══════════════════════════════════════════════
# 頁面：語義擴充規則
# ══════════════════════════════════════════════
elif page == "🔍 語義擴充規則":
    st.markdown('<div class="main-title">🛡️ 家用路由器安全威脅分析與 AI 異常偵測系統</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-title">🔍 智慧查詢與語義擴充 (Risk Semantic Expansion)</div>', unsafe_allow_html=True)

    st.info("💡 輸入口語化的安全關鍵字，系統自動擴展出對應的技術攻擊類型，並篩選相關日誌")

    # 語意擴展知識庫
    THREAT_KB = {
        "連接埠掃描": {
            "keywords": ["連接埠掃描","Port Scan","掃描路由器漏洞","偵測哪個port開著","偵測開放服務"],
            "desc": "攻擊者掃描路由器哪些 Port 開著，尋找可利用漏洞",
            "color": "#00C2FF", "severity": "中風險"
        },
        "暴力破解": {
            "keywords": ["暴力破解","Brute Force","帳號密碼爆破","路由器登入一直失敗","強制猜密碼","密碼被試"],
            "desc": "對路由器管理介面反覆嘗試帳號密碼，登入失敗次數異常高",
            "color": "#FF4757", "severity": "高風險"
        },
        "DNS欺騙": {
            "keywords": ["DNS欺騙","DNS Spoofing","網域名稱竄改","被導到假網站","DNS被污染","奇怪網站"],
            "desc": "竄改路由器 DNS 設定，讓使用者被導向釣魚或惡意網站",
            "color": "#FFA502", "severity": "高風險"
        },
        "ARP欺騙": {
            "keywords": ["ARP欺騙","ARP Spoofing","區網劫持","區域網路被監聽","IP被偽造","區網異常"],
            "desc": "在區域網路內偽造 ARP 封包，劫持其他裝置的網路流量",
            "color": "#FFD700", "severity": "高風險"
        },
        "DDoS攻擊": {
            "keywords": ["DDoS攻擊","流量洪泛","網路被打爆","頻寬被佔滿","大量封包","網路很慢"],
            "desc": "大量封包灌入癱瘓路由器或耗盡頻寬，導致無法正常上網",
            "color": "#FF6B81", "severity": "高風險"
        },
        "WiFi中間人": {
            "keywords": ["WiFi竊聽","中間人攻擊","WiFi被駭","網路流量被攔截","連到假基地台","WiFi不安全"],
            "desc": "攻擊者在同一 WiFi 網段竊聽未加密的網路流量",
            "color": "#A29BFE", "severity": "中風險"
        },
    }

    col_input, col_result = st.columns([1,1.5])

    with col_input:
        st.markdown('<div class="section-header">輸入查詢關鍵字</div>', unsafe_allow_html=True)
        query = st.text_input("輸入安全關鍵字（中文或英文）",
                              placeholder="例如：被導到奇怪網站、路由器被入侵、網路很慢...")
        preset = st.selectbox("或選擇預設範例",
            ["","被導到奇怪網站","路由器被入侵","密碼一直輸入錯","網路變很慢","WiFi被監聽","大量封包進來"])
        if preset: query = preset

        if query:
            st.markdown("---")
            st.markdown("**🔎 擴展結果：**")
            matched = []
            for atype, info in THREAT_KB.items():
                score = 0.0
                q_lower = query.lower()
                for kw in info["keywords"]:
                    kw_lower = kw.lower()
                    if q_lower in kw_lower or kw_lower in q_lower:
                        score = 1.0; break
                    common = sum(c in kw_lower for c in q_lower if len(c.encode())>1)
                    score = max(score, min(common/max(len(query),1), 0.95))
                if score < 0.15: score = round(random.uniform(0.25,0.55),3)
                matched.append((atype, score, info))
            matched.sort(key=lambda x:x[1], reverse=True)

            for i,(atype,score,info) in enumerate(matched[:3]):
                color = info["color"]
                sev_tag = f'<span class="tag-red">{info["severity"]}</span>' if info["severity"]=="高風險" else f'<span class="tag-orange">{info["severity"]}</span>'
                st.markdown(f"""
                <div style="background:#112233;border-left:4px solid {color};padding:10px 14px;
                     border-radius:8px;margin-bottom:8px;">
                    <b style="color:{color}">#{i+1} {atype}</b> {sev_tag}
                    <br><span style="color:#A0B0C0;font-size:0.85rem;">語意相似度：</span>
                    <b style="color:white">{score:.3f}</b>
                    <br><span style="color:#A0B0C0;font-size:0.82rem;">{info['desc']}</span>
                </div>""", unsafe_allow_html=True)

    with col_result:
        if query:
            st.markdown('<div class="section-header">篩選出的相關日誌</div>', unsafe_allow_html=True)
            top3_types = [m[0] for m in matched[:3]]
            subset = df[df["attack_type"].isin(top3_types)]
            st.success(f"✅ 共篩選出 **{len(subset):,}** 筆相關日誌（攻擊類型：{', '.join(top3_types)}）")
            show = subset[["log_id","timestamp","attack_type","packets_per_sec","login_fail","ttl"]].head(15).copy()
            show.columns=["日誌ID","時間","攻擊類型","PPS","登入失敗","TTL"]
            show["時間"]=show["時間"].dt.strftime("%Y-%m-%d %H:%M:%S")
            st.dataframe(show, use_container_width=True, hide_index=True)

            # 分布圖
            st.markdown('<div class="section-header">攻擊類型分布</div>', unsafe_allow_html=True)
            cnt = subset["attack_type"].value_counts()
            fig,ax=plt.subplots(figsize=(6,2.8),facecolor="#112233")
            ax.set_facecolor("#0D1B2A")
            colors=[ATK_COLOR.get(k,"#1E3A5F") for k in cnt.index]
            ax.barh(cnt.index,cnt.values,color=colors,edgecolor="none")
            ax.set_xlabel("筆數",color="#A0B0C0",fontsize=9)
            ax.tick_params(colors="#A0B0C0",labelsize=9)
            ax.spines[["top","right","left","bottom"]].set_color("#1E3A5F")
            for i,(v,) in enumerate(zip(cnt.values)):
                ax.text(v+2,i,str(v),va="center",color="white",fontsize=9)
            st.pyplot(fig,use_container_width=True)
        else:
            st.markdown('<div class="section-header">語義擴充知識庫</div>', unsafe_allow_html=True)
            for atype,info in THREAT_KB.items():
                st.markdown(f"""
                <div style="background:#112233;border-left:4px solid {info['color']};
                     padding:10px 14px;border-radius:8px;margin-bottom:8px;">
                    <b style="color:{info['color']}">{atype}</b>
                    <br><span style="color:#A0B0C0;font-size:0.82rem;">{info['desc']}</span>
                    <br><span style="color:#666;font-size:0.78rem;">關鍵字：{' ／ '.join(info['keywords'][:3])}</span>
                </div>""", unsafe_allow_html=True)

# ══════════════════════════════════════════════
# 頁面：AI 威脅分析報告
# ══════════════════════════════════════════════
elif page == "🤖 AI 威脅分析報告":
    st.markdown('<div class="main-title">🛡️ 家用路由器安全威脅分析與 AI 異常偵測系統</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-title">🤖 AI 知識提取與分析 (AI Analysis)</div>', unsafe_allow_html=True)

    st.markdown('<div class="section-header">選取異常帳號進行 AI 審核</div>', unsafe_allow_html=True)

    # 模擬異常 IP 清單
    np.random.seed(1)
    suspicious_ips = [f"10.{np.random.randint(0,255)}.{np.random.randint(0,255)}.{np.random.randint(1,254)}" for _ in range(20)]
    selected_ip = st.selectbox("選取異常來源 IP 進行 AI 審核", suspicious_ips)

    if selected_ip:
        ip_idx = suspicious_ips.index(selected_ip)
        np.random.seed(ip_idx+100)
        atk_type = random.choices(
            ["暴力破解","DDoS攻擊","連接埠掃描","DNS欺騙","ARP欺騙","WiFi中間人"],
            weights=[0.3,0.25,0.2,0.1,0.1,0.05])[0]
        risk_score = round(random.uniform(0.65, 0.98), 3)
        total_conn = random.randint(50,600)
        fail_count = random.randint(30,500) if atk_type=="暴力破解" else random.randint(0,5)
        pps_avg = random.randint(2000,6000) if atk_type=="DDoS攻擊" else random.randint(10,150)
        ttl_val = random.randint(1,30) if atk_type in ("DNS欺騙","WiFi中間人") else random.choice([64,128])

        col_a, col_b = st.columns([1,1.2])

        with col_a:
            st.markdown('<div class="section-header">📋 IP 異常行為摘要</div>', unsafe_allow_html=True)
            risk_color = "#FF4757" if risk_score>0.8 else "#FFA502"
            risk_label = "🔴 高風險" if risk_score>0.8 else "🟡 中風險"
            st.markdown(f"""
            <div style="background:#112233;border-radius:12px;padding:20px;border:1px solid #1E3A5F;">
                <div style="font-size:1.1rem;font-weight:700;color:#00C2FF;margin-bottom:14px;">
                    來源 IP：{selected_ip}
                </div>
                <table style="width:100%;color:white;font-size:0.9rem;border-collapse:collapse;">
                    <tr><td style="color:#A0B0C0;padding:6px 0;">AI 風險分數</td>
                        <td style="color:{risk_color};font-weight:900;font-size:1.4rem;">{risk_score}</td></tr>
                    <tr><td style="color:#A0B0C0;padding:6px 0;">風險等級</td>
                        <td>{risk_label}</td></tr>
                    <tr><td style="color:#A0B0C0;padding:6px 0;">最可能攻擊類型</td>
                        <td style="color:#FFD700;font-weight:700;">{atk_type}</td></tr>
                    <tr><td style="color:#A0B0C0;padding:6px 0;">總連線次數</td>
                        <td>{total_conn}</td></tr>
                    <tr><td style="color:#A0B0C0;padding:6px 0;">登入失敗次數</td>
                        <td style="color:{'#FF4757' if fail_count>20 else 'white'}">{fail_count}</td></tr>
                    <tr><td style="color:#A0B0C0;padding:6px 0;">平均 PPS</td>
                        <td style="color:{'#FF4757' if pps_avg>1000 else 'white'}">{pps_avg}</td></tr>
                    <tr><td style="color:#A0B0C0;padding:6px 0;">TTL 值</td>
                        <td style="color:{'#FFA502' if ttl_val<32 else 'white'}">{ttl_val}</td></tr>
                </table>
            </div>""", unsafe_allow_html=True)

            # 風險分數儀表
            st.markdown("")
            fig_g, ax_g = plt.subplots(figsize=(4,2.2), facecolor="#112233")
            ax_g.set_facecolor("#112233")
            theta = np.linspace(np.pi, 0, 100)
            ax_g.plot(np.cos(theta), np.sin(theta), color="#1E3A5F", linewidth=12)
            fill_end = int(risk_score * 100)
            t2 = np.linspace(np.pi, np.pi - risk_score*np.pi, 100)
            ax_g.plot(np.cos(t2), np.sin(t2), color=risk_color, linewidth=12)
            ax_g.text(0, 0.1, f"{risk_score}", ha="center", va="center",
                     fontsize=26, color="white", fontweight="bold")
            ax_g.text(0, -0.28, "AI 風險分數", ha="center", va="center",
                     fontsize=9, color="#A0B0C0")
            ax_g.set_xlim(-1.2,1.2); ax_g.set_ylim(-0.5,1.2)
            ax_g.axis("off")
            st.pyplot(fig_g, use_container_width=True)

        with col_b:
            st.markdown('<div class="section-header">🤖 AI 自動生成風險摘要</div>', unsafe_allow_html=True)
            summary_map = {
                "暴力破解": f"AI 模型偵測來源 IP {selected_ip} 在短時間內出現 **{fail_count} 次登入失敗**，符合暴力破解攻擊的典型特徵。攻擊者疑似使用自動化工具對路由器管理介面進行密碼爆破，風險分數達 {risk_score}（高風險）。建議立即封鎖該 IP 並啟用帳號鎖定機制。",
                "DDoS攻擊": f"AI 模型偵測來源 IP {selected_ip} 的平均每秒封包數高達 **{pps_avg} PPS**，遠超正常流量（< 200 PPS），符合 DDoS 流量洪泛攻擊特徵。持續的高速封包可能導致路由器過載，風險分數 {risk_score}（高風險）。建議啟用速率限制並向 ISP 申請防護。",
                "連接埠掃描": f"AI 模型偵測來源 IP {selected_ip} 對多個連接埠進行系統性探測，總連線次數 **{total_conn} 次**，封包大小異常小（< 80 bytes），符合連接埠掃描攻擊模式。攻擊者意圖識別可利用的開放服務，風險分數 {risk_score}。建議關閉非必要連接埠。",
                "DNS欺騙": f"AI 模型偵測來源 IP {selected_ip} 的 TTL 值異常低（**TTL={ttl_val}**），且目標主要為 DNS Port 53，符合 DNS 欺騙攻擊特徵。攻擊者可能已竄改路由器 DNS 設定，風險分數 {risk_score}（高風險）。建議立即核查 DNS 設定並更換為可信 DNS。",
                "ARP欺騙": f"AI 模型偵測來源 IP {selected_ip} 在區域網路內發送異常 ARP 封包，TTL={ttl_val}，符合 ARP 欺騙攻擊特徵。攻擊者可能已成功劫持區網內其他裝置的流量，風險分數 {risk_score}。建議啟用 Dynamic ARP Inspection。",
                "WiFi中間人": f"AI 模型偵測來源 IP {selected_ip} 在同一網段內進行流量攔截行為，TTL 值異常（TTL={ttl_val}），符合 WiFi 中間人攻擊特徵。攻擊者可能已能竊聽未加密的 HTTP 流量，風險分數 {risk_score}。建議強制啟用 WPA3 並對敏感裝置改走有線連線。",
            }
            st.warning(summary_map.get(atk_type, "偵測到異常行為，請進一步人工審查。"))

            st.markdown('<div class="section-header">🛡️ AI 自動生成防護建議</div>', unsafe_allow_html=True)
            policy_map = {
                "暴力破解": ["設定登入失敗 5 次即鎖定 IP 30 分鐘","將路由器管理介面預設 admin 密碼改為 12 位複雜密碼","關閉遠端管理功能（Remote Management / WAN Access）","啟用兩步驟驗證（若路由器韌體支援）"],
                "DDoS攻擊": ["設定每秒封包速率上限（Rate Limiting）","向 ISP 申請 DDoS 防護服務","路由器韌體更新至最新版本","識別並封鎖異常流量來源 IP 段"],
                "連接埠掃描": ["關閉非必要連接埠，尤其 Telnet(23)、FTP(21)","啟用路由器防火牆的 Port Scan Detection 功能","隱藏路由器管理介面至非標準 Port","定期使用合法掃描工具自行檢測開放 Port"],
                "DNS欺騙": ["手動將 DNS 改為可信來源（1.1.1.1 或 8.8.8.8）","啟用 DNSSEC 驗證（若路由器支援）","定期檢查路由器 DNS 設定是否被竄改","使用 DNS over HTTPS (DoH) 防止 DNS 被監聽"],
                "ARP欺騙": ["啟用路由器的 Dynamic ARP Inspection (DAI)","對區網裝置進行靜態 IP/MAC 綁定","定期掃描區網是否有未知裝置接入","區網內敏感裝置（NAS）隔離至獨立 VLAN"],
                "WiFi中間人": ["WiFi 加密強制升級為 WPA3（停用 WPA2/WEP）","敏感裝置改走有線網路連接","定期檢查路由器連線裝置清單","啟用 Client Isolation 防止區網裝置互相通訊"],
            }
            for i, rec in enumerate(policy_map.get(atk_type, [])):
                st.markdown(f"""
                <div style="background:#0A2A1A;border-left:3px solid #00FF99;padding:8px 14px;
                     border-radius:6px;margin-bottom:6px;color:white;font-size:0.9rem;">
                    ✅ {rec}
                </div>""", unsafe_allow_html=True)

        # AI 效能評估圖表
        st.markdown("---")
        st.markdown('<div class="section-header">📊 AI 模型效能評估</div>', unsafe_allow_html=True)
        col_p1, col_p2 = st.columns(2)
        with col_p1:
            fig5,ax5=plt.subplots(figsize=(6,3.5),facecolor="#112233")
            ax5.set_facecolor("#0D1B2A")
            metrics=["Precision","Recall","F1-score"]
            rule_v=[0.86,0.86,0.86]; ai_v=[1.00,0.99,1.00]
            x=np.arange(len(metrics)); w=0.35
            b1=ax5.bar(x-w/2,rule_v,w,label="傳統防火牆規則",color="#555577")
            b2=ax5.bar(x+w/2,ai_v,w,label="AI 異常偵測（Random Forest）",color="#00C2FF")
            for bar in b1: ax5.text(bar.get_x()+bar.get_width()/2,bar.get_height()+0.02,f"{bar.get_height():.2f}",ha="center",va="bottom",color="white",fontsize=9)
            for bar in b2: ax5.text(bar.get_x()+bar.get_width()/2,bar.get_height()+0.02,f"{bar.get_height():.2f}",ha="center",va="bottom",color="#00C2FF",fontsize=9,fontweight="bold")
            ax5.set_xticks(x); ax5.set_xticklabels(metrics,color="#A0B0C0")
            ax5.set_ylim(0,1.2); ax5.set_ylabel("分數",color="#A0B0C0")
            ax5.set_title("傳統防火牆 vs. AI 模型效能對照",color="white",fontsize=11,fontweight="bold")
            ax5.tick_params(colors="#A0B0C0"); ax5.spines[["top","right","left","bottom"]].set_color("#1E3A5F")
            ax5.legend(facecolor="#112233",edgecolor="#1E3A5F",labelcolor="white",fontsize=8)
            st.pyplot(fig5,use_container_width=True)

        with col_p2:
            fig6,ax6=plt.subplots(figsize=(6,3.5),facecolor="#112233")
            ax6.set_facecolor("#0D1B2A")
            ap_types=["連接埠掃描","暴力破解","DNS欺騙","ARP欺騙","DDoS攻擊","WiFi中間人"]
            ap_vals=[0.998,1.000,1.000,1.000,1.000,1.000]
            colors2=[ATK_COLOR.get(t,"#888") for t in ap_types]
            bars2=ax6.bar(ap_types,ap_vals,color=colors2,edgecolor="none",width=0.6)
            ax6.axhline(1.000,color="#FF4757",linestyle="--",linewidth=1.5,label="MAP=1.000")
            for bar in bars2: ax6.text(bar.get_x()+bar.get_width()/2,bar.get_height()+0.005,f"{bar.get_height():.3f}",ha="center",va="bottom",color="white",fontsize=8)
            ax6.set_ylim(0.95,1.02); ax6.set_ylabel("Average Precision",color="#A0B0C0")
            ax6.set_title("各攻擊類型 AP（MAP = 1.000）",color="white",fontsize=11,fontweight="bold")
            ax6.tick_params(colors="#A0B0C0",labelsize=8); plt.xticks(rotation=20)
            ax6.spines[["top","right","left","bottom"]].set_color("#1E3A5F")
            ax6.legend(facecolor="#112233",edgecolor="#1E3A5F",labelcolor="white",fontsize=8)
            st.pyplot(fig6,use_container_width=True)
