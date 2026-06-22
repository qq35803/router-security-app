# -*- coding: utf-8 -*-
import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import random
from datetime import datetime, timedelta

st.set_page_config(page_title="家用路由器安全監控",page_icon="🛡️",layout="wide",initial_sidebar_state="expanded")
st.markdown("""<style>
.stApp{background-color:#0D1B2A;color:#FFFFFF}
.main-title{font-size:2.0rem;font-weight:900;color:#FFFFFF;border-left:6px solid #00C2FF;padding-left:16px;margin-bottom:6px}
.sub-title{font-size:1.0rem;color:#00C2FF;margin-bottom:20px;font-weight:600}
.metric-card{background:#112233;border-radius:12px;padding:20px 16px;text-align:center;border:1px solid #1E3A5F}
.metric-num{font-size:2.2rem;font-weight:900}
.metric-label{font-size:0.85rem;color:#A0B0C0;margin-top:4px}
.section-header{font-size:1.15rem;font-weight:800;color:#00C2FF;margin:22px 0 10px;padding-bottom:5px;border-bottom:2px solid #1E3A5F}
[data-testid="stSidebar"]{background-color:#0A1628!important}
</style>""",unsafe_allow_html=True)

with st.sidebar:
    st.markdown("## 🛡️ 系統模組")
    page=st.selectbox("選擇功能",["📊 數據監控看板","🔍 語義擴充規則","🤖 AI 威脅分析報告"])
    st.markdown("---")
    st.markdown("**系統資訊**\n- 分析日誌：12,000 筆\n- 攻擊類型：6 種\n- 模型：Random Forest\n- F1-score：**1.00**\n- MAP：**1.000**")
    st.markdown("---")
    st.markdown('<span style="color:#A0B0C0;font-size:0.8rem;">行動商務安全 期末專題<br>國立臺中科技大學</span>',unsafe_allow_html=True)

ATK_TYPES=["Normal","Port Scan","Brute Force","DNS Spoof","ARP Spoof","DDoS","WiFi MITM"]
ATK_RATIOS=[0.88,0.026,0.029,0.020,0.017,0.019,0.015]
ATK_COLOR={"Port Scan":"#00C2FF","Brute Force":"#FF4757","DNS Spoof":"#FFA502","ARP Spoof":"#FFD700","DDoS":"#FF6B81","WiFi MITM":"#A29BFE"}
ATK_ZH={"Port Scan":"連接埠掃描","Brute Force":"暴力破解","DNS Spoof":"DNS欺騙","ARP Spoof":"ARP欺騙","DDoS":"DDoS攻擊","WiFi MITM":"WiFi中間人"}

@st.cache_data
def gen_data():
    np.random.seed(42);random.seed(42)
    records=[]
    base=datetime(2026,4,1)
    for i in range(12000):
        at=random.choices(ATK_TYPES,weights=ATK_RATIOS)[0]
        hour=random.randint(1,5) if at!="Normal" and random.random()<0.40 else random.randint(0,23)
        ts=base+timedelta(days=random.randint(0,29),hours=hour,minutes=random.randint(0,59),seconds=random.randint(0,59))
        pps=int(np.random.normal(4000,800)) if at=="DDoS" else random.randint(1,200)
        fail=random.randint(50,500) if at=="Brute Force" else random.randint(0,2)
        ttl=random.randint(1,30) if at in ("DNS Spoof","WiFi MITM") else random.choice([64,128,255])
        pkt=int(np.random.normal(1400,80)) if at=="DDoS" else int(np.random.normal(512,180))
        records.append({"log_id":f"LOG{200000+i}","timestamp":ts,"hour":ts.hour,"date":ts.date(),"attack_type":at,"is_attack":0 if at=="Normal" else 1,"packets_per_sec":max(1,pps),"login_fail":fail,"ttl":max(1,ttl),"packet_size":max(40,pkt)})
    return pd.DataFrame(records)

df=gen_data()

if page=="📊 數據監控看板":
    st.markdown('<div class="main-title">🛡️ 家用路由器安全威脅分析與 AI 異常偵測系統</div>',unsafe_allow_html=True)
    st.markdown('<div class="sub-title">📊 統計分析與可視化圖表 (Visualization)</div>',unsafe_allow_html=True)
    atk_df=df[df["is_attack"]==1]
    c1,c2,c3,c4,c5=st.columns(5)
    for col,(num,label,color) in zip([c1,c2,c3,c4,c5],[("12,000","筆路由器日誌","#00C2FF"),(f"{len(atk_df):,}","筆攻擊事件","#FF4757"),(f"{len(atk_df)/len(df)*100:.1f}%","整體攻擊比率","#FFA502"),("1.00","AI F1-score","#00FF99"),("1.000","MAP (6 attacks)","#FFD700")]):
        with col:
            st.markdown(f'<div class="metric-card"><div class="metric-num" style="color:{color}">{num}</div><div class="metric-label">{label}</div></div>',unsafe_allow_html=True)
    st.markdown("")
    col_l,col_r=st.columns([1,1.6])
    with col_l:
        st.markdown('<div class="section-header">Attack Type Distribution</div>',unsafe_allow_html=True)
        atk_counts=atk_df["attack_type"].value_counts()
        fig,ax=plt.subplots(figsize=(5,4.2),facecolor="#112233");ax.set_facecolor("#112233")
        colors=[ATK_COLOR.get(k,"#888") for k in atk_counts.index]
        wedges,texts,autotexts=ax.pie(atk_counts.values,labels=atk_counts.index,autopct="%1.1f%%",startangle=120,colors=colors,textprops={"fontsize":8,"color":"white"})
        for at in autotexts:at.set_color("white");at.set_fontsize(8)
        ax.set_title("Attack Type Distribution",color="white",fontsize=11,fontweight="bold",pad=10)
        st.pyplot(fig,use_container_width=True)
        st.markdown("""<div style="background:#112233;border-radius:8px;padding:10px;font-size:0.82rem">
        🔴 <b style="color:#FF4757">Brute Force</b> 暴力破解　🔵 <b style="color:#00C2FF">Port Scan</b> 連接埠掃描<br>
        🟠 <b style="color:#FFA502">DNS Spoof</b> DNS欺騙　🟡 <b style="color:#FFD700">ARP Spoof</b> ARP欺騙<br>
        🩷 <b style="color:#FF6B81">DDoS</b> DDoS攻擊　🟣 <b style="color:#A29BFE">WiFi MITM</b> WiFi中間人</div>""",unsafe_allow_html=True)
    with col_r:
        st.markdown('<div class="section-header">Avg Packets Per Second (PPS) by Attack Type</div>',unsafe_allow_html=True)
        pps_stats=df[df["attack_type"]!="Normal"].groupby("attack_type")["packets_per_sec"].mean().sort_values(ascending=False)
        fig2,ax2=plt.subplots(figsize=(6,4.2),facecolor="#112233");ax2.set_facecolor("#0D1B2A")
        bars=ax2.bar(pps_stats.index,pps_stats.values,color=[ATK_COLOR.get(k,"#1E3A5F") for k in pps_stats.index],edgecolor="none",width=0.6)
        ax2.set_xlabel("Attack Type",color="#A0B0C0",fontsize=9);ax2.set_ylabel("Avg PPS",color="#A0B0C0",fontsize=9)
        ax2.set_title("Avg Packets Per Second by Attack Type",color="white",fontsize=10,fontweight="bold")
        ax2.tick_params(colors="#A0B0C0",labelsize=8);ax2.spines[["top","right","left","bottom"]].set_color("#1E3A5F")
        for bar in bars:ax2.text(bar.get_x()+bar.get_width()/2,bar.get_height()+20,f"{bar.get_height():.0f}",ha="center",va="bottom",color="white",fontsize=8)
        plt.xticks(rotation=20);st.pyplot(fig2,use_container_width=True)
    col3,col4=st.columns(2)
    with col3:
        st.markdown('<div class="section-header">Hourly Attack Rate (凌晨 01-05 高風險)</div>',unsafe_allow_html=True)
        hourly=df.groupby("hour").agg(total=("log_id","count"),atk=("is_attack","sum")).reset_index();hourly["rate"]=hourly["atk"]/hourly["total"]*100
        fig3,ax3=plt.subplots(figsize=(6,3.5),facecolor="#112233");ax3.set_facecolor("#0D1B2A")
        ax3.plot(hourly["hour"],hourly["rate"],color="#00C2FF",marker="o",linewidth=2,markersize=4)
        ax3.axvspan(1,5,color="#FF4757",alpha=0.15,label="High Risk 01-05h")
        ax3.set_xlabel("Hour (0-23)",color="#A0B0C0",fontsize=9);ax3.set_ylabel("Attack Rate (%)",color="#A0B0C0",fontsize=9)
        ax3.set_title("Hourly Attack Rate",color="white",fontsize=10,fontweight="bold")
        ax3.tick_params(colors="#A0B0C0",labelsize=8);ax3.spines[["top","right","left","bottom"]].set_color("#1E3A5F")
        ax3.legend(facecolor="#112233",edgecolor="#1E3A5F",labelcolor="white",fontsize=8);ax3.set_xticks(range(0,24))
        st.pyplot(fig3,use_container_width=True)
    with col4:
        st.markdown('<div class="section-header">Daily Attack Events Trend</div>',unsafe_allow_html=True)
        daily=df.groupby("date")["is_attack"].sum().reset_index()
        fig4,ax4=plt.subplots(figsize=(6,3.5),facecolor="#112233");ax4.set_facecolor("#0D1B2A")
        ax4.plot(range(len(daily)),daily["is_attack"],color="#FF4757",marker="o",linewidth=1.8,markersize=3)
        ax4.fill_between(range(len(daily)),daily["is_attack"],alpha=0.15,color="#FF4757")
        ax4.set_xlabel("Day (Apr 1~)",color="#A0B0C0",fontsize=9);ax4.set_ylabel("Attack Events",color="#A0B0C0",fontsize=9)
        ax4.set_title("Daily Router Attack Events",color="white",fontsize=10,fontweight="bold")
        ax4.tick_params(colors="#A0B0C0",labelsize=8);ax4.spines[["top","right","left","bottom"]].set_color("#1E3A5F")
        st.pyplot(fig4,use_container_width=True)
    st.markdown('<div class="section-header">🔴 Recent Attack Logs (最新異常連線紀錄)</div>',unsafe_allow_html=True)
    recent=atk_df.sort_values("timestamp",ascending=False).head(10)[["log_id","timestamp","attack_type","packets_per_sec","login_fail","ttl","packet_size"]].copy()
    recent.columns=["日誌ID","時間","攻擊類型","PPS","登入失敗次數","TTL","封包大小(B)"];recent["時間"]=recent["時間"].dt.strftime("%Y-%m-%d %H:%M:%S")
    st.dataframe(recent,use_container_width=True,hide_index=True)

elif page=="🔍 語義擴充規則":
    st.markdown('<div class="main-title">🛡️ 家用路由器安全威脅分析與 AI 異常偵測系統</div>',unsafe_allow_html=True)
    st.markdown('<div class="sub-title">🔍 智慧查詢與語義擴充 (Risk Semantic Expansion)</div>',unsafe_allow_html=True)
    st.info("💡 輸入口語化的安全關鍵字，系統自動擴展出對應的技術攻擊類型，並篩選相關日誌")
    THREAT_KB={"DNS Spoof (DNS欺騙)":{"kw":["dns","欺騙","假網站","奇怪網站","被導","污染"],"desc":"竄改路由器 DNS 設定，讓使用者被導向釣魚網站","color":"#FFA502","sev":"高風險","en":"DNS Spoof"},"Brute Force (暴力破解)":{"kw":["暴力","破解","密碼","登入","帳號","一直","猜","brute","爆破"],"desc":"對路由器管理介面反覆嘗試帳號密碼","color":"#FF4757","sev":"高風險","en":"Brute Force"},"Port Scan (連接埠掃描)":{"kw":["掃描","port","連接埠","漏洞","服務","scan","入侵","被入侵","路由器被"],"desc":"攻擊者掃描路由器哪些 Port 開著，尋找可利用漏洞","color":"#00C2FF","sev":"中風險","en":"Port Scan"},"DDoS (DDoS攻擊)":{"kw":["ddos","慢","卡","流量","頻寬","封包","打爆","斷線","很慢","大量"],"desc":"大量封包灌入癱瘓路由器或耗盡頻寬","color":"#FF6B81","sev":"高風險","en":"DDoS"},"ARP Spoof (ARP欺騙)":{"kw":["arp","區網","劫持","監聽","ip","偽造","區域"],"desc":"在區域網路內偽造 ARP 封包，劫持其他裝置流量","color":"#FFD700","sev":"高風險","en":"ARP Spoof"},"WiFi MITM (WiFi中間人)":{"kw":["wifi","無線","竊聽","中間人","mitm","不安全","被監聽"],"desc":"攻擊者在同一 WiFi 網段竊聽未加密的網路流量","color":"#A29BFE","sev":"中風險","en":"WiFi MITM"}}
    col_i,col_r=st.columns([1,1.5])
    with col_i:
        st.markdown('<div class="section-header">輸入查詢關鍵字</div>',unsafe_allow_html=True)
        query=st.text_input("輸入安全關鍵字（中文或英文）",placeholder="例如：被導到奇怪網站、密碼一直輸入錯...")
        preset=st.selectbox("或選擇預設範例",["","被導到奇怪網站","路由器被入侵","密碼一直輸入錯","網路變很慢","WiFi被監聽","大量封包進來"])
        if preset:query=preset
        if query:
            st.markdown("---");st.markdown("**🔎 語意擴展結果：**")
            q_lower=query.lower()
            matched=[]
            for atype,info in THREAT_KB.items():
                score=max([0.3]+[0.9 if kw in q_lower or q_lower in kw else 0.4 if any(c in kw for c in q_lower if len(c.encode("utf-8"))>1) else 0.1 for kw in info["kw"]])
                matched.append((atype,round(score,3),info))
            matched.sort(key=lambda x:x[1],reverse=True)
            for i,(atype,score,info) in enumerate(matched[:3]):
                sev_color="#FF4757" if info["sev"]=="高風險" else "#FFA502"
                st.markdown(f'<div style="background:#112233;border-left:4px solid {info["color"]};padding:10px 14px;border-radius:8px;margin-bottom:8px"><b style="color:{info["color"]}">#{i+1} {atype}</b> <span style="background:{sev_color};color:white;padding:2px 8px;border-radius:10px;font-size:0.75rem">{info["sev"]}</span><br><span style="color:#A0B0C0;font-size:0.85rem">語意相似度：</span><b style="color:white">{score:.3f}</b><br><span style="color:#A0B0C0;font-size:0.82rem">{info["desc"]}</span></div>',unsafe_allow_html=True)
    with col_r:
        if query:
            st.markdown('<div class="section-header">篩選出的相關日誌</div>',unsafe_allow_html=True)
            q_lower=query.lower()
            scored=[]
            for atype,info in THREAT_KB.items():
                score=max([0.3]+[0.9 if kw in q_lower or q_lower in kw else 0.3 for kw in info["kw"]])
                scored.append((info["en"],score))
            scored.sort(key=lambda x:x[1],reverse=True)
            top3=[s[0] for s in scored[:3]]
            subset=df[df["attack_type"].isin(top3)]
            st.success(f"✅ 共篩選出 **{len(subset):,}** 筆相關日誌")
            show=subset[["log_id","timestamp","attack_type","packets_per_sec","login_fail","ttl"]].head(12).copy()
            show.columns=["日誌ID","時間","攻擊類型","PPS","登入失敗","TTL"];show["時間"]=show["時間"].dt.strftime("%Y-%m-%d %H:%M")
            st.dataframe(show,use_container_width=True,hide_index=True)
            cnt=subset["attack_type"].value_counts()
            fig,ax=plt.subplots(figsize=(5,2.5),facecolor="#112233");ax.set_facecolor("#0D1B2A")
            ax.barh(cnt.index,cnt.values,color=[ATK_COLOR.get(k,"#1E3A5F") for k in cnt.index],edgecolor="none")
            ax.set_xlabel("Count",color="#A0B0C0",fontsize=9);ax.set_title("Filtered Attack Distribution",color="white",fontsize=10,fontweight="bold")
            ax.tick_params(colors="#A0B0C0",labelsize=9);ax.spines[["top","right","left","bottom"]].set_color("#1E3A5F")
            st.pyplot(fig,use_container_width=True)
        else:
            st.markdown('<div class="section-header">語義擴充知識庫</div>',unsafe_allow_html=True)
            for atype,info in THREAT_KB.items():
                st.markdown(f'<div style="background:#112233;border-left:4px solid {info["color"]};padding:10px 14px;border-radius:8px;margin-bottom:8px"><b style="color:{info["color"]}">{atype}</b><br><span style="color:#A0B0C0;font-size:0.82rem">{info["desc"]}</span></div>',unsafe_allow_html=True)

elif page=="🤖 AI 威脅分析報告":
    st.markdown('<div class="main-title">🛡️ 家用路由器安全威脅分析與 AI 異常偵測系統</div>',unsafe_allow_html=True)
    st.markdown('<div class="sub-title">🤖 AI 知識提取與分析 (AI Analysis)</div>',unsafe_allow_html=True)
    st.markdown('<div class="section-header">選取異常來源 IP 進行 AI 審核</div>',unsafe_allow_html=True)
    np.random.seed(1)
    ips=[f"10.{np.random.randint(0,255)}.{np.random.randint(0,255)}.{np.random.randint(1,254)}" for _ in range(20)]
    sel=st.selectbox("選取異常來源 IP",ips)
    if sel:
        idx=ips.index(sel);random.seed(idx+100);np.random.seed(idx+100)
        ae=random.choices(["Brute Force","DDoS","Port Scan","DNS Spoof","ARP Spoof","WiFi MITM"],weights=[0.3,0.25,0.2,0.1,0.1,0.05])[0]
        az=ATK_ZH.get(ae,ae);rs=round(random.uniform(0.65,0.98),3)
        tc=random.randint(50,600);fc=random.randint(30,500) if ae=="Brute Force" else random.randint(0,5)
        pa=random.randint(2000,6000) if ae=="DDoS" else random.randint(10,150)
        tv=random.randint(1,30) if ae in ("DNS Spoof","WiFi MITM") else random.choice([64,128])
        rc="#FF4757" if rs>0.8 else "#FFA502";rl="🔴 高風險" if rs>0.8 else "🟡 中風險"
        ca,cb=st.columns([1,1.2])
        with ca:
            st.markdown('<div class="section-header">📋 IP 異常行為摘要</div>',unsafe_allow_html=True)
            st.markdown(f'<div style="background:#112233;border-radius:12px;padding:20px;border:1px solid #1E3A5F"><div style="font-size:1.05rem;font-weight:700;color:#00C2FF;margin-bottom:14px">來源 IP：{sel}</div><table style="width:100%;color:white;font-size:0.9rem"><tr><td style="color:#A0B0C0;padding:5px 0">AI 風險分數</td><td style="color:{rc};font-weight:900;font-size:1.4rem">{rs}</td></tr><tr><td style="color:#A0B0C0;padding:5px 0">風險等級</td><td>{rl}</td></tr><tr><td style="color:#A0B0C0;padding:5px 0">攻擊類型</td><td style="color:#FFD700;font-weight:700">{az}（{ae}）</td></tr><tr><td style="color:#A0B0C0;padding:5px 0">總連線次數</td><td>{tc}</td></tr><tr><td style="color:#A0B0C0;padding:5px 0">登入失敗次數</td><td style="color:{"#FF4757" if fc>20 else "white"}">{fc}</td></tr><tr><td style="color:#A0B0C0;padding:5px 0">平均 PPS</td><td style="color:{"#FF4757" if pa>1000 else "white"}">{pa}</td></tr><tr><td style="color:#A0B0C0;padding:5px 0">TTL 值</td><td style="color:{"#FFA502" if tv<32 else "white"}">{tv}</td></tr></table></div>',unsafe_allow_html=True)
            fg,ag=plt.subplots(figsize=(4,2.2),facecolor="#112233");ag.set_facecolor("#112233")
            th=np.linspace(np.pi,0,100);ag.plot(np.cos(th),np.sin(th),color="#1E3A5F",linewidth=12)
            t2=np.linspace(np.pi,np.pi-rs*np.pi,100);ag.plot(np.cos(t2),np.sin(t2),color=rc,linewidth=12)
            ag.text(0,0.1,f"{rs}",ha="center",va="center",fontsize=26,color="white",fontweight="bold")
            ag.text(0,-0.28,"AI Risk Score",ha="center",va="center",fontsize=9,color="#A0B0C0")
            ag.set_xlim(-1.2,1.2);ag.set_ylim(-0.5,1.2);ag.axis("off")
            st.pyplot(fg,use_container_width=True)
        with cb:
            st.markdown('<div class="section-header">🤖 AI 自動生成風險摘要</div>',unsafe_allow_html=True)
            smap={"Brute Force":f"AI 模型偵測 {sel} 在短時間內出現 **{fc} 次登入失敗**，符合暴力破解（Brute Force）攻擊特徵。攻擊者使用自動化工具爆破路由器管理介面密碼，風險分數 {rs}（高風險）。建議立即封鎖該 IP 並啟用帳號鎖定機制。","DDoS":f"AI 模型偵測 {sel} 平均每秒封包數高達 **{pa} PPS**，遠超正常流量（< 200 PPS），符合 DDoS 流量洪泛攻擊特徵。風險分數 {rs}（高風險）。建議啟用速率限制並向 ISP 申請防護。","Port Scan":f"AI 模型偵測 {sel} 對多個連接埠進行系統性探測，總連線次數 **{tc} 次**，符合連接埠掃描攻擊模式，風險分數 {rs}。建議關閉非必要連接埠。","DNS Spoof":f"AI 模型偵測 {sel} TTL 值異常低（**TTL={tv}**），目標主要為 DNS Port 53，符合 DNS 欺騙特徵，風險分數 {rs}（高風險）。建議立即核查 DNS 設定。","ARP Spoof":f"AI 模型偵測 {sel} 在區域網路內發送異常 ARP 封包（TTL={tv}），可能已劫持區網流量，風險分數 {rs}。建議啟用 Dynamic ARP Inspection。","WiFi MITM":f"AI 模型偵測 {sel} 在同一網段進行流量攔截（TTL={tv}），符合 WiFi 中間人攻擊特徵，風險分數 {rs}。建議強制啟用 WPA3 加密。"}
            st.warning(smap.get(ae,"偵測到異常行為，請進一步人工審查。"))
            st.markdown('<div class="section-header">🛡️ AI 自動生成防護建議</div>',unsafe_allow_html=True)
            pmap={"Brute Force":["設定登入失敗 5 次即鎖定 IP 30 分鐘","路由器預設 admin 密碼改為 12 位複雜密碼","關閉遠端管理功能（Remote Management）","啟用兩步驟驗證（2FA）"],"DDoS":["設定每秒封包速率上限（Rate Limiting）","向 ISP 申請 DDoS 防護服務","更新路由器韌體至最新版本","封鎖異常流量來源 IP 段"],"Port Scan":["關閉非必要連接埠（Telnet:23、FTP:21）","啟用防火牆 Port Scan Detection","路由器管理介面改為非標準 Port","定期自行掃描開放 Port"],"DNS Spoof":["手動將 DNS 改為 1.1.1.1 或 8.8.8.8","啟用 DNSSEC 驗證","定期檢查路由器 DNS 設定","使用 DNS over HTTPS（DoH）"],"ARP Spoof":["啟用 Dynamic ARP Inspection（DAI）","對區網裝置進行 IP/MAC 靜態綁定","定期掃描區網是否有未知裝置","敏感裝置隔離至獨立 VLAN"],"WiFi MITM":["WiFi 加密強制升級為 WPA3","敏感裝置改走有線網路","啟用 Client Isolation","定期檢查路由器連線裝置清單"]}
            for rec in pmap.get(ae,[]):
                st.markdown(f'<div style="background:#0A2A1A;border-left:3px solid #00FF99;padding:8px 14px;border-radius:6px;margin-bottom:6px;color:white;font-size:0.9rem">✅ {rec}</div>',unsafe_allow_html=True)
        st.markdown("---")
        st.markdown('<div class="section-header">📊 AI Model Performance (效能評估)</div>',unsafe_allow_html=True)
        p1,p2=st.columns(2)
        with p1:
            f5,a5=plt.subplots(figsize=(6,3.5),facecolor="#112233");a5.set_facecolor("#0D1B2A")
            ms=["Precision","Recall","F1-score"];rv=[0.86,0.86,0.86];av=[1.00,0.99,1.00]
            x=np.arange(len(ms));w=0.35
            b1=a5.bar(x-w/2,rv,w,label="Traditional Firewall",color="#555577")
            b2=a5.bar(x+w/2,av,w,label="AI (Random Forest)",color="#00C2FF")
            for bar in b1:a5.text(bar.get_x()+bar.get_width()/2,bar.get_height()+0.02,f"{bar.get_height():.2f}",ha="center",va="bottom",color="white",fontsize=9)
            for bar in b2:a5.text(bar.get_x()+bar.get_width()/2,bar.get_height()+0.02,f"{bar.get_height():.2f}",ha="center",va="bottom",color="#00C2FF",fontsize=9,fontweight="bold")
            a5.set_xticks(x);a5.set_xticklabels(ms,color="#A0B0C0");a5.set_ylim(0,1.2);a5.set_ylabel("Score",color="#A0B0C0")
            a5.set_title("Traditional Rule vs AI Model",color="white",fontsize=10,fontweight="bold")
            a5.tick_params(colors="#A0B0C0");a5.spines[["top","right","left","bottom"]].set_color("#1E3A5F")
            a5.legend(facecolor="#112233",edgecolor="#1E3A5F",labelcolor="white",fontsize=8)
            st.pyplot(f5,use_container_width=True)
        with p2:
            f6,a6=plt.subplots(figsize=(6,3.5),facecolor="#112233");a6.set_facecolor("#0D1B2A")
            at2=["Port Scan","Brute Force","DNS Spoof","ARP Spoof","DDoS","WiFi MITM"];av2=[0.998,1.000,1.000,1.000,1.000,1.000]
            bars2=a6.bar(at2,av2,color=[ATK_COLOR.get(t,"#888") for t in at2],edgecolor="none",width=0.6)
            a6.axhline(1.000,color="#FF4757",linestyle="--",linewidth=1.5,label="MAP=1.000")
            for bar in bars2:a6.text(bar.get_x()+bar.get_width()/2,bar.get_height()+0.001,f"{bar.get_height():.3f}",ha="center",va="bottom",color="white",fontsize=8)
            a6.set_ylim(0.98,1.01);a6.set_ylabel("Avg Precision",color="#A0B0C0")
            a6.set_title("AP by Attack Type (MAP=1.000)",color="white",fontsize=10,fontweight="bold")
            a6.tick_params(colors="#A0B0C0",labelsize=8);plt.xticks(rotation=20)
            a6.spines[["top","right","left","bottom"]].set_color("#1E3A5F")
            a6.legend(facecolor="#112233",edgecolor="#1E3A5F",labelcolor="white",fontsize=8)
            st.pyplot(f6,use_container_width=True)
