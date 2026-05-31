// Surge & Shadowrocket Rule Dashboard & Simulator
// Core Application Logic

// Default custom config provided by user (Vietnamese Premium Rules)
const DEFAULT_CONFIG = `#!name=👑 Phan Doãn Hoàng 🌸 ⁕ Ultimate Premium ⁕
#!desc=🚀 Mở khóa 67+ App VIP (Spotify, Locket...). 🛡️ Chặn sạch Ads & Tracking. ⚡ Tối ưu DNS, AI & Gaming. 🏦 27+ Banking VN. 🎬 Streaming & Social.
#!version=1.6.0
#!date=2026-05-29
#!author=Phan Doãn Hoàng (z3rokaze)
#!homepage=https://github.com/wududegw/ytpre
#!icon=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/VIP.png
#!system=ios

[General]
# === PHẢN 1: TỐI ƯU HÓA HTTP ENGINE ===
# Bổ sung các host quan trọng để ép giải mã HTTP Engine cho Script hoạt động mượt mà
force-http-engine-hosts = *youtube.com:443, *googlevideo.com:443, youtubei.googleapis.com:443, api.revenuecat.com:443, api.rc-backup.com:443, spclient.wg.spotify.com:443, i.instagram.com:443, api.twitter.com:443, api.x.com:443, api.picsart.com:443

# === DNS MÃ HÓA (DoH) - Pomelo520 ===
dns-server = https://dns.google/dns-query, https://cloudflare-dns.com/dns-query, https://dns.quad9.net/dns-query, system

# === TỐI ƯU MẠNG NỘI BỘ ===
skip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 100.64.0.0/10, 17.0.0.0/8, localhost, *.local
tun-excluded-routes = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12

# === REAL IP (Captive Portal & Gaming) ===
always-real-ip = *.lan, *.local, *.msftconnecttest.com, *.msftncsi.com, detectportal.firefox.com, captive.apple.com, *.srv.nintendo.net, *.stun.playstation.net, xbox.*.microsoft.com, *.xboxlive.com

[Rule]
# === BLOCK QUIC FOR YOUTUBE MITM ===
AND,((DOMAIN-SUFFIX,googlevideo.com), (PROTOCOL,UDP)),REJECT
AND,((DOMAIN,youtubei.googleapis.com), (PROTOCOL,UDP)),REJECT

# === BLOCK WEBRTC LEAK (Specific servers) ===
DOMAIN-SUFFIX,stun.l.google.com,REJECT
DOMAIN-SUFFIX,stun1.l.google.com,REJECT
DOMAIN-SUFFIX,stun2.l.google.com,REJECT
DOMAIN-SUFFIX,stun3.l.google.com,REJECT
DOMAIN-SUFFIX,stun4.l.google.com,REJECT

# === SPOTIFY ADS ===
DOMAIN-SUFFIX,audio-ak-spotify-com.akamaized.net,REJECT
DOMAIN-SUFFIX,audio4-ak-spotify-com.akamaized.net,REJECT
DOMAIN-SUFFIX,heads-ak-spotify-com.akamaized.net,REJECT
DOMAIN-SUFFIX,heads4-ak-spotify-com.akamaized.net,REJECT
DOMAIN,spclient.wg.spotify.com,DIRECT
DOMAIN-KEYWORD,spotify-ads,REJECT
DOMAIN-SUFFIX,ads-fa.spotify.com,REJECT
DOMAIN-SUFFIX,analytics.spotify.com,REJECT
DOMAIN-SUFFIX,adeventtracker.spotify.com,REJECT
DOMAIN-SUFFIX,log.spotify.com,REJECT
DOMAIN-SUFFIX,creativeservice-production.scdn.co,REJECT

# ===========================================================
# === CHẶN QUẢNG CÁO + CỜ BẠC/CÁ ĐỘ TỔNG HỢP (Ad Block) ===
# === by z3rokaze - 2026-05-27 (Ultimate Edition)            ===
# ===========================================================

# --- 1.1 Google Ads / AdMob / DoubleClick ---
DOMAIN-SUFFIX,adservice.google.com,REJECT
DOMAIN-SUFFIX,adservice.google.com.vn,REJECT
DOMAIN-SUFFIX,admob.com,REJECT
DOMAIN-SUFFIX,app-measurement.com,REJECT
DOMAIN-SUFFIX,googleadservices.com,REJECT
DOMAIN-SUFFIX,googlesyndication.com,REJECT
DOMAIN-SUFFIX,doubleclick.net,REJECT
DOMAIN-SUFFIX,ads.google.com,REJECT
DOMAIN-SUFFIX,pagead-googlehosted.l.google.com,REJECT
DOMAIN-SUFFIX,googletagmanager.com,REJECT
DOMAIN-KEYWORD,googleads,REJECT
DOMAIN-KEYWORD,google-analytics,REJECT

# --- 1.2 Facebook / Meta Ads ---
DOMAIN-SUFFIX,an.facebook.com,REJECT
DOMAIN-SUFFIX,ads.facebook.com,REJECT
DOMAIN-SUFFIX,adtago.s3.amazonaws.com,REJECT
DOMAIN-SUFFIX,pixel.facebook.com,REJECT

# --- 1.3 Unity Ads ---
DOMAIN-SUFFIX,unityads.unity3d.com,REJECT
DOMAIN-SUFFIX,ads.unity3d.com,REJECT
DOMAIN-KEYWORD,unityads,REJECT

# --- 1.4 AppLovin / MAX ---
DOMAIN-SUFFIX,applovin.com,REJECT
DOMAIN-SUFFIX,applvn.com,REJECT
DOMAIN-KEYWORD,applovin,REJECT

# --- 1.5 IronSource / LevelPlay ---
DOMAIN-SUFFIX,ironsrc.com,REJECT
DOMAIN-SUFFIX,supersonicads.com,REJECT
DOMAIN-KEYWORD,ironsource,REJECT

# --- 1.6 Vungle / Liftoff ---
DOMAIN-SUFFIX,vungle.com,REJECT
DOMAIN-SUFFIX,liftoff.io,REJECT
DOMAIN-KEYWORD,vungle,REJECT

# --- 1.7 Chartboost ---
DOMAIN-SUFFIX,chartboost.com,REJECT
DOMAIN-KEYWORD,chartboost,REJECT

# --- 1.8 InMobi ---
DOMAIN-SUFFIX,inmobi.com,REJECT
DOMAIN-KEYWORD,inmobi,REJECT

# --- 1.9 Mintegral / Mobvista ---
DOMAIN-SUFFIX,mintegral.com,REJECT
DOMAIN-SUFFIX,rayjump.com,REJECT
DOMAIN-SUFFIX,mobvista.com,REJECT
DOMAIN-KEYWORD,mintegral,REJECT

# --- 1.10 AdColony / Digital Turbine ---
DOMAIN-SUFFIX,adcolony.com,REJECT
DOMAIN-SUFFIX,digitalturbine.com,REJECT
DOMAIN-KEYWORD,adcolony,REJECT

# --- 1.11 MoPub (Twitter) ---
DOMAIN-SUFFIX,mopub.com,REJECT
DOMAIN-KEYWORD,mopub,REJECT

# --- 1.12 Fyber / Digital Turbine ---
DOMAIN-SUFFIX,fyber.com,REJECT
DOMAIN-SUFFIX,inner-active.mobi,REJECT

# --- 1.13 Smaato ---
DOMAIN-SUFFIX,smaato.com,REJECT
DOMAIN-SUFFIX,smaato.net,REJECT

# --- 1.14 Tapjoy ---
DOMAIN-SUFFIX,tapjoy.com,REJECT
DOMAIN-KEYWORD,tapjoy,REJECT

# --- 1.15 Pangle (TikTok Ads / ByteDance) ---
DOMAIN-SUFFIX,pangleglobal.com,REJECT
DOMAIN-SUFFIX,pglstatp-toutiao.com,REJECT
DOMAIN-KEYWORD,pangleglobal,REJECT

# --- 1.16 Amazon Ads ---
DOMAIN-SUFFIX,amazon-adsystem.com,REJECT
DOMAIN-SUFFIX,aan.amazon.com,REJECT

# --- 1.17 StartApp / Start.io ---
DOMAIN-SUFFIX,startapp.com,REJECT
DOMAIN-SUFFIX,start.io,REJECT
DOMAIN-KEYWORD,startapp,REJECT

# --- 1.18 Ogury ---
DOMAIN-SUFFIX,ogury.com,REJECT

# --- 1.19 Yahoo / Flurry ---
DOMAIN-SUFFIX,flurry.com,REJECT
DOMAIN-SUFFIX,ads.yahoo.com,REJECT
DOMAIN-SUFFIX,analytics.yahoo.com,REJECT

# --- 1.20 Criteo ---
DOMAIN-SUFFIX,criteo.com,REJECT
DOMAIN-SUFFIX,criteo.net,REJECT
DOMAIN-SUFFIX,emailretargeting.com,REJECT

# --- 1.21 Teads (Video Ads) ---
DOMAIN-SUFFIX,teads.tv,REJECT
DOMAIN-SUFFIX,teads.com,REJECT

# --- 1.22 PubMatic ---
DOMAIN-SUFFIX,pubmatic.com,REJECT

# --- 1.23 OpenX ---
DOMAIN-SUFFIX,openx.net,REJECT
DOMAIN-SUFFIX,openx.com,REJECT

# --- 1.24 Index Exchange ---
DOMAIN-SUFFIX,casalemedia.com,REJECT

# --- 1.25 SmartAdServer ---
DOMAIN-SUFFIX,smartadserver.com,REJECT
DOMAIN-SUFFIX,sascdn.com,REJECT

# --- 1.26 AdRoll ---
DOMAIN-SUFFIX,adroll.com,REJECT

# --- 1.27 Media.net ---
DOMAIN-SUFFIX,media.net,REJECT

# --- 1.28 RevContent / MGID / Content Ads ---
DOMAIN-SUFFIX,revcontent.com,REJECT
DOMAIN-SUFFIX,mgid.com,REJECT
DOMAIN-SUFFIX,contentad.net,REJECT

# --- 1.29 ShareThrough / TripleLift / Nativo ---
DOMAIN-SUFFIX,sharethrough.com,REJECT
DOMAIN-SUFFIX,triplelift.com,REJECT
DOMAIN-SUFFIX,nativo.com,REJECT

# --- 1.30 Yandex Ads ---
DOMAIN-SUFFIX,an.yandex.ru,REJECT
DOMAIN-SUFFIX,yandexadexchange.net,REJECT

# --- 1.31 Baidu / Tencent Ads ---
DOMAIN-SUFFIX,pos.baidu.com,REJECT
DOMAIN-SUFFIX,cpro.baidu.com,REJECT
DOMAIN-SUFFIX,e.qq.com,REJECT
DOMAIN-SUFFIX,gdt.qq.com,REJECT

# --- 1.32 Ad Verification / Viewability ---
DOMAIN-SUFFIX,moat.com,REJECT
DOMAIN-SUFFIX,moatads.com,REJECT
DOMAIN-SUFFIX,doubleverify.com,REJECT
DOMAIN-SUFFIX,integralads.com,REJECT
DOMAIN-SUFFIX,adsafeprotected.com,REJECT

# --- 1.33 TikTok Ads ---
DOMAIN-SUFFIX,ads.tiktok.com,REJECT
DOMAIN-SUFFIX,analytics.tiktok.com,REJECT
DOMAIN-SUFFIX,ct.tiktok.com,REJECT

# --- 1.34 Additional Ad Networks ---
DOMAIN-SUFFIX,adform.net,REJECT
DOMAIN-SUFFIX,adnxs.com,REJECT
DOMAIN-SUFFIX,adzerk.net,REJECT
DOMAIN-SUFFIX,adtech.com,REJECT
DOMAIN-SUFFIX,adition.com,REJECT
DOMAIN-SUFFIX,adzerk.com,REJECT

# --- 1.35 New Ad Networks (2025-2026) ---
DOMAIN-SUFFIX,verve.com,REJECT
DOMAIN-SUFFIX,pubnative.net,REJECT
DOMAIN-SUFFIX,appmetrica.yandex.com,REJECT
DOMAIN-SUFFIX,report.appmetrica.yandex.net,REJECT
DOMAIN-SUFFIX,moloco.com,REJECT
DOMAIN-KEYWORD,moloco,REJECT
DOMAIN-SUFFIX,bigoads.com,REJECT
DOMAIN-SUFFIX,ad.xiaomi.com,REJECT

# ┌──────────────────────────────────────┐
# │  PHẦN 2: TRACKING & ANALYTICS SDKs  │
# └──────────────────────────────────────┘

# --- 2.1 Attribution / Mobile Measurement ---
DOMAIN-SUFFIX,adjust.com,REJECT-DROP
DOMAIN-SUFFIX,adjust.io,REJECT-DROP
DOMAIN-SUFFIX,appsflyer.com,REJECT-DROP
DOMAIN-SUFFIX,kochava.com,REJECT-DROP
DOMAIN-SUFFIX,singular.net,REJECT-DROP
DOMAIN-SUFFIX,tenjin.com,REJECT-DROP
DOMAIN-SUFFIX,airbridge.io,REJECT-DROP

# --- 2.2 Analytics Platforms ---
DOMAIN-SUFFIX,mixpanel.com,REJECT-DROP
DOMAIN-SUFFIX,amplitude.com,REJECT-DROP
DOMAIN-SUFFIX,segment.io,REJECT-DROP
DOMAIN-SUFFIX,segment.com,REJECT-DROP
DOMAIN-SUFFIX,heapanalytics.com,REJECT-DROP
DOMAIN-SUFFIX,fullstory.com,REJECT-DROP
DOMAIN-SUFFIX,hotjar.com,REJECT-DROP
DOMAIN-SUFFIX,mouseflow.com,REJECT-DROP
DOMAIN-SUFFIX,crazyegg.com,REJECT-DROP
DOMAIN-SUFFIX,kissmetrics.com,REJECT-DROP

# --- 2.3 General Web Tracking ---
DOMAIN-SUFFIX,scorecardresearch.com,REJECT-DROP
DOMAIN-SUFFIX,omtrdc.net,REJECT-DROP
DOMAIN-SUFFIX,demdex.net,REJECT-DROP
DOMAIN-SUFFIX,adsrvr.org,REJECT-DROP
DOMAIN-SUFFIX,crashlytics.com,REJECT-DROP
DOMAIN-SUFFIX,braze.com,REJECT-DROP
DOMAIN-SUFFIX,clevertap.com,REJECT-DROP
DOMAIN-SUFFIX,intercom.io,REJECT-DROP
DOMAIN-SUFFIX,intercom.com,REJECT-DROP
DOMAIN-SUFFIX,mookie1.com,REJECT-DROP
DOMAIN-SUFFIX,taboola.com,REJECT-DROP
DOMAIN-SUFFIX,outbrain.com,REJECT-DROP
DOMAIN-SUFFIX,bluekai.com,REJECT-DROP
DOMAIN-SUFFIX,everesttech.net,REJECT-DROP
DOMAIN-SUFFIX,mathtag.com,REJECT-DROP
DOMAIN-SUFFIX,bidswitch.net,REJECT-DROP
DOMAIN-SUFFIX,exelator.com,REJECT-DROP
DOMAIN-SUFFIX,crwdcntrl.net,REJECT-DROP
DOMAIN-SUFFIX,dotomi.com,REJECT-DROP
DOMAIN-SUFFIX,serving-sys.com,REJECT-DROP
DOMAIN-SUFFIX,eyeota.net,REJECT-DROP
DOMAIN-SUFFIX,agkn.com,REJECT-DROP
DOMAIN-SUFFIX,rlcdn.com,REJECT-DROP
DOMAIN-SUFFIX,turn.com,REJECT-DROP
DOMAIN-SUFFIX,rubiconproject.com,REJECT-DROP
DOMAIN-SUFFIX,contextweb.com,REJECT-DROP
DOMAIN-SUFFIX,spotxchange.com,REJECT-DROP

# ┌─────────────────────────────────────┐
# │  PHẦN 3: QUẢNG CÁO VIỆT NAM        │
# └─────────────────────────────────────┘
DOMAIN-SUFFIX,adservice.zaloapp.com,REJECT
DOMAIN-SUFFIX,admicro.vn,REJECT
DOMAIN-SUFFIX,adsplay.net,REJECT
DOMAIN-SUFFIX,adtima.vn,REJECT
DOMAIN-SUFFIX,eclick.vn,REJECT
DOMAIN-SUFFIX,novaon.vn,REJECT
DOMAIN-SUFFIX,nativex.vn,REJECT
DOMAIN-SUFFIX,adpia.vn,REJECT
DOMAIN-SUFFIX,ants.vn,REJECT
DOMAIN-SUFFIX,accesstrade.vn,REJECT
DOMAIN-SUFFIX,younetmedia.com,REJECT

# ┌─────────────────────────────────────┐
# │  PHẦN 4: POPUP / REDIRECT / SCAM    │
# └─────────────────────────────────────┘
DOMAIN-SUFFIX,popads.net,REJECT
DOMAIN-SUFFIX,popcash.net,REJECT
DOMAIN-SUFFIX,propellerads.com,REJECT
DOMAIN-SUFFIX,propellerclick.com,REJECT
DOMAIN-SUFFIX,trafficjunky.com,REJECT
DOMAIN-SUFFIX,revenuehits.com,REJECT
DOMAIN-SUFFIX,exoclick.com,REJECT
DOMAIN-SUFFIX,clickadu.com,REJECT
DOMAIN-SUFFIX,hilltopads.com,REJECT
DOMAIN-SUFFIX,richpush.com,REJECT
DOMAIN-SUFFIX,pushengage.com,REJECT
DOMAIN-SUFFIX,adsterra.com,REJECT
DOMAIN-SUFFIX,adsterratools.com,REJECT
DOMAIN-SUFFIX,trafficstars.com,REJECT
DOMAIN-SUFFIX,juicyads.com,REJECT
DOMAIN-SUFFIX,trafficfactory.biz,REJECT
DOMAIN-SUFFIX,clickaine.com,REJECT
DOMAIN-SUFFIX,evadav.com,REJECT
DOMAIN-SUFFIX,galaksion.com,REJECT
DOMAIN-SUFFIX,onclickmx.com,REJECT

# ┌──────────────────────────────────────────────────────────┐
# │  PHẦN 5: CHẶN WEB CÁ ĐỘ / CỜ BẠC / CASINO (GAMBLING)  │
# └──────────────────────────────────────────────────────────┘
DOMAIN-SUFFIX,1xbet.com,REJECT
DOMAIN-SUFFIX,1xbet.vn,REJECT
DOMAIN-SUFFIX,fun88.com,REJECT
DOMAIN-SUFFIX,fun88asia.com,REJECT
DOMAIN-SUFFIX,fun88vietnam.com,REJECT
DOMAIN-SUFFIX,w88.com,REJECT
DOMAIN-SUFFIX,w88vn.com,REJECT
DOMAIN-SUFFIX,w88top.com,REJECT
DOMAIN-SUFFIX,188bet.com,REJECT
DOMAIN-SUFFIX,188betasia.com,REJECT
DOMAIN-SUFFIX,m88.com,REJECT
DOMAIN-SUFFIX,m88a.com,REJECT
DOMAIN-SUFFIX,m88vn.com,REJECT
DOMAIN-SUFFIX,bk8.com,REJECT
DOMAIN-SUFFIX,bk8vn.com,REJECT
DOMAIN-SUFFIX,fb88.com,REJECT
DOMAIN-SUFFIX,fb88vn.com,REJECT
DOMAIN-SUFFIX,sv388.com,REJECT
DOMAIN-SUFFIX,sv388vn.com,REJECT
DOMAIN-SUFFIX,sin88.com,REJECT
DOMAIN-SUFFIX,sin88.club,REJECT
DOMAIN-SUFFIX,hi88.com,REJECT
DOMAIN-SUFFIX,hi88.bio,REJECT
DOMAIN-SUFFIX,hi88.club,REJECT
DOMAIN-SUFFIX,new88.com,REJECT
DOMAIN-SUFFIX,new88.club,REJECT
DOMAIN-SUFFIX,new88vn.com,REJECT
DOMAIN-SUFFIX,8xbet.com,REJECT
DOMAIN-SUFFIX,8xbet.gg,REJECT
DOMAIN-SUFFIX,jun88.com,REJECT
DOMAIN-SUFFIX,jun88.bio,REJECT
DOMAIN-SUFFIX,jun88.club,REJECT
DOMAIN-SUFFIX,vn88.com,REJECT
DOMAIN-SUFFIX,vn88.club,REJECT
DOMAIN-SUFFIX,789bet.com,REJECT
DOMAIN-SUFFIX,789bet.gg,REJECT
DOMAIN-SUFFIX,789bet.club,REJECT
DOMAIN-SUFFIX,kubet.com,REJECT
DOMAIN-SUFFIX,kubet.io,REJECT
DOMAIN-SUFFIX,kubet.club,REJECT
DOMAIN-SUFFIX,sobet.io,REJECT
DOMAIN-SUFFIX,sunwin.com,REJECT
DOMAIN-SUFFIX,sunwin.club,REJECT
DOMAIN-SUFFIX,sunwin.gg,REJECT
DOMAIN-SUFFIX,iwin.com,REJECT
DOMAIN-SUFFIX,iwin.club,REJECT
DOMAIN-SUFFIX,iwin68.club,REJECT
DOMAIN-SUFFIX,go88.com,REJECT
DOMAIN-SUFFIX,go88.club,REJECT
DOMAIN-SUFFIX,go88.gg,REJECT
DOMAIN-SUFFIX,rikvip.com,REJECT
DOMAIN-SUFFIX,rikvip.club,REJECT
DOMAIN-SUFFIX,rik.vip,REJECT
DOMAIN-SUFFIX,8day.com,REJECT
DOMAIN-SUFFIX,8day.club,REJECT
DOMAIN-SUFFIX,ta88.com,REJECT
DOMAIN-SUFFIX,ta88.club,REJECT
DOMAIN-SUFFIX,tf88.com,REJECT
DOMAIN-SUFFIX,shbet.com,REJECT
DOMAIN-SUFFIX,shbet.club,REJECT
DOMAIN-SUFFIX,luck8.com,REJECT
DOMAIN-SUFFIX,luck8.club,REJECT
DOMAIN-SUFFIX,mb66.com,REJECT
DOMAIN-SUFFIX,mb66.club,REJECT
DOMAIN-SUFFIX,five88.com,REJECT
DOMAIN-SUFFIX,five88.gg,REJECT
DOMAIN-SUFFIX,zbet.com,REJECT
DOMAIN-SUFFIX,zbet.club,REJECT
DOMAIN-SUFFIX,oxbet.com,REJECT
DOMAIN-SUFFIX,oxbet.club,REJECT
DOMAIN-SUFFIX,ae888.com,REJECT
DOMAIN-SUFFIX,ae888.club,REJECT
DOMAIN-SUFFIX,taya365.com,REJECT
DOMAIN-SUFFIX,taya365.club,REJECT
DOMAIN-SUFFIX,66bet.com,REJECT
DOMAIN-SUFFIX,77bet.com,REJECT
DOMAIN-SUFFIX,33win.com,REJECT
DOMAIN-SUFFIX,33win.club,REJECT
DOMAIN-SUFFIX,f8bet.com,REJECT
DOMAIN-SUFFIX,f8bet.club,REJECT
DOMAIN-SUFFIX,bet88.com,REJECT
DOMAIN-SUFFIX,bet88.club,REJECT
DOMAIN-SUFFIX,qh88.com,REJECT
DOMAIN-SUFFIX,qh88.club,REJECT
DOMAIN-SUFFIX,78win.com,REJECT
DOMAIN-SUFFIX,78win.club,REJECT
DOMAIN-SUFFIX,abc8.com,REJECT
DOMAIN-SUFFIX,abc8.club,REJECT
DOMAIN-SUFFIX,debet.com,REJECT
DOMAIN-SUFFIX,debet.club,REJECT
DOMAIN-SUFFIX,mu88.com,REJECT
DOMAIN-SUFFIX,mu88.club,REJECT
DOMAIN-SUFFIX,gg8.com,REJECT
DOMAIN-SUFFIX,gg8.club,REJECT
DOMAIN-SUFFIX,b52.com,REJECT
DOMAIN-SUFFIX,b52.club,REJECT
DOMAIN-SUFFIX,uy88.com,REJECT
DOMAIN-SUFFIX,top88.com,REJECT
DOMAIN-SUFFIX,top88.club,REJECT
DOMAIN-SUFFIX,betvisa.com,REJECT
DOMAIN-SUFFIX,betvisa.vn,REJECT
DOMAIN-SUFFIX,bong88.com,REJECT
DOMAIN-SUFFIX,bong88.net,REJECT

# --- 5.2 Trang cá độ quốc tế ---
DOMAIN-SUFFIX,bet365.com,REJECT
DOMAIN-SUFFIX,22bet.com,REJECT
DOMAIN-SUFFIX,mostbet.com,REJECT
DOMAIN-SUFFIX,melbet.com,REJECT
DOMAIN-SUFFIX,stake.com,REJECT
DOMAIN-SUFFIX,1win.com,REJECT
DOMAIN-SUFFIX,betwinner.com,REJECT
DOMAIN-SUFFIX,parimatch.com,REJECT
DOMAIN-SUFFIX,pin-up.com,REJECT
DOMAIN-SUFFIX,linebet.com,REJECT
DOMAIN-SUFFIX,megapari.com,REJECT
DOMAIN-SUFFIX,betway.com,REJECT
DOMAIN-SUFFIX,dafabet.com,REJECT
DOMAIN-SUFFIX,sbobet.com,REJECT
DOMAIN-SUFFIX,12bet.com,REJECT
DOMAIN-SUFFIX,10bet.com,REJECT
DOMAIN-SUFFIX,betfair.com,REJECT
DOMAIN-SUFFIX,888casino.com,REJECT
DOMAIN-SUFFIX,unibet.com,REJECT
DOMAIN-SUFFIX,leovegas.com,REJECT
DOMAIN-SUFFIX,vulkanvegas.com,REJECT
DOMAIN-SUFFIX,vulkanbet.com,REJECT
DOMAIN-SUFFIX,bcgame.com,REJECT

# --- 5.2b Trang cá độ mới (2025-2026) ---
DOMAIN-SUFFIX,ok9.com,REJECT
DOMAIN-SUFFIX,ok9.club,REJECT
DOMAIN-SUFFIX,v9bet.com,REJECT
DOMAIN-SUFFIX,nohu.club,REJECT
DOMAIN-SUFFIX,nohu90.com,REJECT
DOMAIN-SUFFIX,hitclub.com,REJECT
DOMAIN-SUFFIX,hitclub.gg,REJECT
DOMAIN-SUFFIX,57k.com,REJECT

# --- 5.3 Keyword chặn cá độ phổ biến ---
DOMAIN-KEYWORD,1xbet,REJECT
DOMAIN-KEYWORD,fun88,REJECT
DOMAIN-KEYWORD,w88vn,REJECT
DOMAIN-KEYWORD,8xbet,REJECT
DOMAIN-KEYWORD,jun88,REJECT
DOMAIN-KEYWORD,789bet,REJECT
DOMAIN-KEYWORD,kubet,REJECT
DOMAIN-KEYWORD,new88,REJECT

# ┌──────────────────────────────────────────────────────┐
# │  PHẦN 6: AI SERVICES ROUTING (PROXY)                │
# └──────────────────────────────────────────────────────┘
# --- 6.1 OpenAI / ChatGPT ---
DOMAIN-SUFFIX,openai.com,PROXY
DOMAIN-SUFFIX,chatgpt.com,PROXY
DOMAIN-SUFFIX,oaistatic.com,PROXY
DOMAIN-SUFFIX,oaiusercontent.com,PROXY
DOMAIN-SUFFIX,chat.openai.com.cdn.cloudflare.net,PROXY
DOMAIN-KEYWORD,openai,PROXY

# --- 6.2 Anthropic / Claude ---
DOMAIN-SUFFIX,claude.ai,PROXY
DOMAIN-SUFFIX,anthropic.com,PROXY

# --- 6.3 Google AI ---
DOMAIN-SUFFIX,gemini.google.com,PROXY
DOMAIN-SUFFIX,bard.google.com,PROXY
DOMAIN-SUFFIX,makersuite.google.com,PROXY
DOMAIN-SUFFIX,generativelanguage.googleapis.com,PROXY
DOMAIN-SUFFIX,aistudio.google.com,PROXY
DOMAIN-SUFFIX,deepmind.google,PROXY

# --- 6.4 Microsoft Copilot ---
DOMAIN-SUFFIX,copilot.microsoft.com,PROXY
DOMAIN-SUFFIX,sydney.bing.com,PROXY
DOMAIN-SUFFIX,edgeservices.bing.com,PROXY

# --- 6.5 Other AI Services ---
DOMAIN-SUFFIX,midjourney.com,PROXY
DOMAIN-SUFFIX,stability.ai,PROXY
DOMAIN-SUFFIX,perplexity.ai,PROXY
DOMAIN-SUFFIX,huggingface.co,PROXY
DOMAIN-SUFFIX,poe.com,PROXY
DOMAIN-SUFFIX,character.ai,PROXY
DOMAIN-SUFFIX,replicate.com,PROXY
DOMAIN-SUFFIX,runway.com,PROXY
DOMAIN-SUFFIX,suno.ai,PROXY
DOMAIN-SUFFIX,udio.com,PROXY
DOMAIN-SUFFIX,cursor.sh,PROXY
DOMAIN-SUFFIX,v0.dev,PROXY

# --- 6.6 New AI Services (2025-2026) ---
DOMAIN-SUFFIX,x.ai,PROXY
DOMAIN-SUFFIX,deepseek.com,PROXY
DOMAIN-SUFFIX,mistral.ai,PROXY
DOMAIN-SUFFIX,cohere.com,PROXY
DOMAIN-SUFFIX,together.ai,PROXY
DOMAIN-SUFFIX,groq.com,PROXY
DOMAIN-SUFFIX,bolt.new,PROXY
DOMAIN-SUFFIX,replit.com,PROXY
DOMAIN-SUFFIX,windsurf.com,PROXY
DOMAIN-SUFFIX,codeium.com,PROXY
DOMAIN-SUFFIX,lovable.dev,PROXY
DOMAIN-SUFFIX,labs.google,PROXY
DOMAIN-SUFFIX,notebooklm.google,PROXY
DOMAIN-SUFFIX,notebooklm.google.com,PROXY

# ┌──────────────────────────────────────────────────────┐
# │  PHẦN 7: BỔ SUNG AD DOMAINS CÒN THIẾU              │
# └──────────────────────────────────────────────────────┘
# --- 7.1 Bổ sung Ad Networks ---
DOMAIN-SUFFIX,ads-twitter.com,REJECT
DOMAIN-SUFFIX,advertising.com,REJECT
DOMAIN-SUFFIX,liadm.com,REJECT
DOMAIN-SUFFIX,go.link,REJECT
DOMAIN-SUFFIX,onelink.me,REJECT
DOMAIN-SUFFIX,impression.link,REJECT
DOMAIN-SUFFIX,metric.gstatic.com,REJECT

# --- 7.2 Quảng cáo ứng dụng Trung Quốc ---
DOMAIN-SUFFIX,cm.bilibili.com,REJECT
DOMAIN-SUFFIX,data.bilibili.com,REJECT
DOMAIN-SUFFIX,zhihu-web-analytics.zhihu.com,REJECT
DOMAIN-SUFFIX,sugar.zhihu.com,REJECT
DOMAIN-SUFFIX,118.etao.com,REJECT
DOMAIN-SUFFIX,adash.m.taobao.com,REJECT
DOMAIN-SUFFIX,sclick.net,REJECT
DOMAIN-SUFFIX,re.taobao.com,REJECT
DOMAIN-SUFFIX,sdk.m.amap.com,REJECT
DOMAIN-SUFFIX,acs.m.taobao.com,REJECT

# --- 7.3 Phishing / Malware / Crypto Scam ---
DOMAIN-SUFFIX,coinhive.com,REJECT
DOMAIN-SUFFIX,coin-hive.com,REJECT
DOMAIN-SUFFIX,authedmine.com,REJECT
DOMAIN-SUFFIX,cryptoloot.pro,REJECT
DOMAIN-SUFFIX,crypto-loot.com,REJECT

# ┌──────────────────────────────────────────────────────┐
# │  PHẦN 8: CHẶN TELEMETRY & TRACKING HỆ THỐNG         │
# └──────────────────────────────────────────────────────┘
# --- 8.1 Microsoft Telemetry ---
DOMAIN-SUFFIX,data.microsoft.com,REJECT-DROP
DOMAIN-SUFFIX,telemetry.microsoft.com,REJECT-DROP

# --- 8.2 Apple Analytics ---
DOMAIN-SUFFIX,metrics.icloud.com,REJECT-DROP
DOMAIN-SUFFIX,metrics.mzstatic.com,REJECT-DROP
DOMAIN-SUFFIX,supportmetrics.apple.com,REJECT-DROP
DOMAIN-SUFFIX,books-analytics-events.apple.com,REJECT-DROP
DOMAIN-SUFFIX,xp.apple.com,REJECT-DROP
DOMAIN-SUFFIX,idiag.apple.com,REJECT-DROP
DOMAIN-SUFFIX,iphonesubmissions.apple.com,REJECT-DROP
DOMAIN-SUFFIX,radarsubmissions.apple.com,REJECT-DROP

# --- 8.3 Xiaomi / Huawei / Samsung Tracking ---
DOMAIN-SUFFIX,tracking.miui.com,REJECT-DROP
DOMAIN-SUFFIX,data.mistat.xiaomi.com,REJECT-DROP
DOMAIN-SUFFIX,tracking.rus.miui.com,REJECT-DROP
DOMAIN-SUFFIX,logservice.hicloud.com,REJECT-DROP
DOMAIN-SUFFIX,metrics.data.hicloud.com,REJECT-DROP
DOMAIN-SUFFIX,samsungads.com,REJECT-DROP

# ┌──────────────────────────────────────────────────────┐
# │  PHẦN 9: GAMING SERVICES ROUTING (PROXY)             │
# └──────────────────────────────────────────────────────┘
# --- 9.1 PlayStation Network ---
DOMAIN-SUFFIX,playstation.com,PROXY
DOMAIN-SUFFIX,playstation.net,PROXY
DOMAIN-SUFFIX,sonyentertainmentnetwork.com,PROXY

# --- 9.2 Xbox / Microsoft Gaming ---
DOMAIN-SUFFIX,xbox.com,PROXY
DOMAIN-SUFFIX,xboxlive.com,PROXY

# --- 9.3 Steam ---
DOMAIN-SUFFIX,steampowered.com,PROXY
DOMAIN-SUFFIX,steamcommunity.com,PROXY
DOMAIN-SUFFIX,steamstatic.com,PROXY

# --- 9.4 Nintendo ---
DOMAIN-SUFFIX,nintendo.com,PROXY
DOMAIN-SUFFIX,nintendo.net,PROXY

# --- 9.5 Epic Games ---
DOMAIN-SUFFIX,epicgames.com,PROXY
DOMAIN-SUFFIX,unrealengine.com,PROXY

# --- 9.6 Riot Games (LOL, Valorant, TFT) ---
DOMAIN-SUFFIX,riotgames.com,PROXY
DOMAIN-SUFFIX,leagueoflegends.com,PROXY
DOMAIN-SUFFIX,riotcdn.net,PROXY

# --- 9.7 EA / Blizzard / Ubisoft ---
DOMAIN-SUFFIX,ea.com,PROXY
DOMAIN-SUFFIX,origin.com,PROXY
DOMAIN-SUFFIX,blizzard.com,PROXY
DOMAIN-SUFFIX,battle.net,PROXY
DOMAIN-SUFFIX,ubisoft.com,PROXY
DOMAIN-SUFFIX,ubi.com,PROXY

# ┌──────────────────────────────────────────────────────┐
# │  PHẦN 10: STREAMING SERVICES (PROXY - Geo-unlock)    │
# └──────────────────────────────────────────────────────┘
# --- 10.1 Netflix ---
DOMAIN-SUFFIX,netflix.com,PROXY
DOMAIN-SUFFIX,netflix.net,PROXY
DOMAIN-SUFFIX,nflximg.net,PROXY
DOMAIN-SUFFIX,nflximg.com,PROXY
DOMAIN-SUFFIX,nflxvideo.net,PROXY
DOMAIN-SUFFIX,nflxso.net,PROXY
DOMAIN-SUFFIX,nflxext.com,PROXY

# --- 10.2 Disney+ ---
DOMAIN-SUFFIX,disneyplus.com,PROXY
DOMAIN-SUFFIX,disney-plus.net,PROXY
DOMAIN-SUFFIX,dssott.com,PROXY
DOMAIN-SUFFIX,bamgrid.com,PROXY
DOMAIN-SUFFIX,disney-portal.my.onetrust.com,PROXY

# --- 10.3 Amazon Prime Video ---
DOMAIN-SUFFIX,primevideo.com,PROXY
DOMAIN-SUFFIX,amazonvideo.com,PROXY
DOMAIN-SUFFIX,aiv-cdn.net,PROXY

# --- 10.4 HBO / Max ---
DOMAIN-SUFFIX,hbomax.com,PROXY
DOMAIN-SUFFIX,max.com,PROXY
DOMAIN-SUFFIX,hbo.com,PROXY

# --- 10.5 Other Streaming ---
DOMAIN-SUFFIX,hulu.com,PROXY
DOMAIN-SUFFIX,hulustream.com,PROXY
DOMAIN-SUFFIX,tv.apple.com,PROXY
DOMAIN-SUFFIX,crunchyroll.com,PROXY
DOMAIN-SUFFIX,vrv.co,PROXY
DOMAIN-SUFFIX,dazn.com,PROXY
DOMAIN-SUFFIX,bilibili.tv,PROXY

# ┌──────────────────────────────────────────────────────┐
# │  PHẦN 11: SOCIAL MEDIA ROUTING (PROXY)               │
# └──────────────────────────────────────────────────────┘
# --- 11.1 Telegram ---
DOMAIN-SUFFIX,telegram.org,PROXY
DOMAIN-SUFFIX,t.me,PROXY
DOMAIN-SUFFIX,telegra.ph,PROXY
DOMAIN-SUFFIX,telegram.me,PROXY
IP-CIDR,91.108.0.0/16,PROXY,no-resolve
IP-CIDR,149.154.160.0/20,PROXY,no-resolve

# --- 11.2 Discord ---
DOMAIN-SUFFIX,discord.com,PROXY
DOMAIN-SUFFIX,discord.gg,PROXY
DOMAIN-SUFFIX,discordapp.com,PROXY
DOMAIN-SUFFIX,discordapp.net,PROXY
DOMAIN-SUFFIX,discord.media,PROXY

# --- 11.3 Reddit ---
DOMAIN-SUFFIX,reddit.com,PROXY
DOMAIN-SUFFIX,redd.it,PROXY
DOMAIN-SUFFIX,redditmedia.com,PROXY
DOMAIN-SUFFIX,redditstatic.com,PROXY

# --- 11.4 Threads / WhatsApp Web ---
DOMAIN-SUFFIX,threads.net,PROXY
DOMAIN-SUFFIX,web.whatsapp.com,PROXY

# ┌──────────────────────────────────────────────────────┐
# │  PHẦN 12: DEVELOPER TOOLS (PROXY)                    │
# └──────────────────────────────────────────────────────┘
# --- 12.1 GitHub / GitLab ---
DOMAIN-SUFFIX,github.com,PROXY
DOMAIN-SUFFIX,github.io,PROXY
DOMAIN-SUFFIX,githubusercontent.com,PROXY
DOMAIN-SUFFIX,githubassets.com,PROXY
DOMAIN-SUFFIX,gitlab.com,PROXY
DOMAIN-SUFFIX,gitlab.io,PROXY

# --- 12.2 Package Registries ---
DOMAIN-SUFFIX,docker.io,PROXY
DOMAIN-SUFFIX,docker.com,PROXY
DOMAIN-SUFFIX,npmjs.org,PROXY
DOMAIN-SUFFIX,npmjs.com,PROXY
DOMAIN-SUFFIX,yarnpkg.com,PROXY
DOMAIN-SUFFIX,pypi.org,PROXY
DOMAIN-SUFFIX,registry.npmmirror.com,PROXY

# --- 12.3 Developer Communities ---
DOMAIN-SUFFIX,stackoverflow.com,PROXY
DOMAIN-SUFFIX,stackexchange.com,PROXY
DOMAIN-SUFFIX,medium.com,PROXY
DOMAIN-SUFFIX,dev.to,PROXY

# ┌──────────────────────────────────────────────────────┐
# │  PHẦN 13: TỐI ƯU KẾT NỐI (DIRECT - BỎ QUA VPN)       │
# └──────────────────────────────────────────────────────┘
# --- 13.1 Apple Services (Bypass for max speed & stability) ---
DOMAIN-SUFFIX,mzstatic.com,DIRECT
DOMAIN-SUFFIX,icloud.com,DIRECT
DOMAIN-SUFFIX,me.com,DIRECT
DOMAIN-SUFFIX,apple.com,DIRECT

# --- 13.2 Vietnamese Banking & E-Wallets (Anti-block & Bypass) ---
DOMAIN-SUFFIX,momo.vn,DIRECT
DOMAIN-SUFFIX,mservice.com.vn,DIRECT
DOMAIN-SUFFIX,zalopay.vn,DIRECT
DOMAIN-SUFFIX,vnpay.vn,DIRECT
DOMAIN-SUFFIX,vietcombank.com.vn,DIRECT
DOMAIN-SUFFIX,techcombank.com.vn,DIRECT
DOMAIN-SUFFIX,mbbank.com.vn,DIRECT
DOMAIN-SUFFIX,tpb.vn,DIRECT
DOMAIN-SUFFIX,vpbank.com.vn,DIRECT
DOMAIN-SUFFIX,bidv.com.vn,DIRECT
DOMAIN-SUFFIX,vtb.vn,DIRECT
DOMAIN-SUFFIX,vietinbank.vn,DIRECT
DOMAIN-SUFFIX,agribank.com.vn,DIRECT
DOMAIN-SUFFIX,acb.com.vn,DIRECT
DOMAIN-SUFFIX,vib.com.vn,DIRECT
DOMAIN-SUFFIX,sacombank.com.vn,DIRECT
DOMAIN-SUFFIX,hdbank.com.vn,DIRECT
DOMAIN-SUFFIX,ocb.com.vn,DIRECT
DOMAIN-SUFFIX,shb.com.vn,DIRECT
DOMAIN-SUFFIX,msb.com.vn,DIRECT
DOMAIN-SUFFIX,lpbank.com.vn,DIRECT
DOMAIN-SUFFIX,eximbank.com.vn,DIRECT
DOMAIN-SUFFIX,namabank.com.vn,DIRECT
DOMAIN-SUFFIX,seabank.com.vn,DIRECT
DOMAIN-SUFFIX,cake.vn,DIRECT
DOMAIN-SUFFIX,vietqr.io,DIRECT
DOMAIN-SUFFIX,napas.com.vn,DIRECT

# --- 13.3 Popular Vietnamese Apps (Lightning fast local access) ---
DOMAIN-SUFFIX,zalo.me,DIRECT
DOMAIN-SUFFIX,zaloapp.com,DIRECT
DOMAIN-SUFFIX,shopee.vn,DIRECT
DOMAIN-SUFFIX,shopeemobile.com,DIRECT
DOMAIN-SUFFIX,tiki.vn,DIRECT
DOMAIN-SUFFIX,lazada.vn,DIRECT
DOMAIN-SUFFIX,grab.com,DIRECT
DOMAIN-SUFFIX,be.com.vn,DIRECT
DOMAIN-SUFFIX,fpt.vn,DIRECT
DOMAIN-SUFFIX,vnexpress.net,DIRECT

# --- 13.4 Vietnam Local Network & GeoIP (Lightning fast local traffic) ---
DOMAIN-SUFFIX,vn,DIRECT
GEOIP,VN,DIRECT

# === DÒNG CHỐT QUY TẮC (FINAL FALLBACK) ===
# Tránh bỏ sót các kết nối không nằm trong danh sách quy tắc
FINAL,DIRECT

[Header Rewrite]
# === YOUTUBE NONCE ===
^https?://www\.youtube\.com/youtubei/v1/player header-replace x-youtube-client-version 2.20240101.00.00
# === REVENUECAT REMOVE ETAG (Locket Gold + all RC apps) ===
^https?:\/\/api\.revenuecat\.com\/.+\/(receipts$|subscribers\/?(.*?)*$) header-del x-revenuecat-etag
^https?:\/\/api\.revenuecat\.com\/.+\/(receipts$|subscribers\/?(.*?)*$) header-del X-RevenueCat-ETag
^https?:\/\/api\.rc-backup\.com\/.+\/(receipts$|subscribers\/?(.*?)*$) header-del x-revenuecat-etag
^https?:\/\/api\.rc-backup\.com\/.+\/(receipts$|subscribers\/?(.*?)*$) header-del X-RevenueCat-ETag

# === SPOTIFY REMOVE CACHE HEADERS ===
^https:\/\/(spclient\.wg\.spotify\.com|.*-spclient\.spotify\.com(:443)?)\/user-customization-service\/v1\/customize$ header-del if-none-match

[URL Rewrite]
# === YOUTUBE - Block ads and tracking ===
^https?:\/\/[\w-]+\.googlevideo\.com\/(?!(dclk_video_ads|videoplayback\?)).+&oad _ reject-200
^https?:\/\/(www|s)\.youtube\.com\/api\/stats\/ads _ reject-200
^https?:\/\/(www|s)\.youtube\.com\/(pagead|ptracking) _ reject-200
^https?:\/\/s\.youtube\.com\/api\/stats\/qoe\?adcontext _ reject-200
(^https?:\/\/[\w-]+\.googlevideo\.com\/(?!dclk_video_ads).+?)&ctier=L(&.+?),ctier,(.+) $1$2$3 302

[Map Local]
# === YOUTUBE - Block initplayback preroll ads ===
^https?:\/\/[\w-]+\.googlevideo\.com\/initplayback.+&oad data-type=text data="" status-code=200

[Script]
# === X (TWITTER) PRO (No Ads, Unlock Features) - chxm1023 ===
twitter-response = type=http-response, pattern=^https?:\/\/(api\.(twitter|x)\.com)\/graphql, script-path=https://raw.githubusercontent.com/chxm1023/Rewrite/main/Twitter.js, requires-body=1, max-size=0, timeout=10

# === INSTAGRAM NO ADS - app2smile ===
instagram-response = type=http-response, pattern=^https?:\/\/i\.instagram\.com\/api\/v1\/(feed\/timeline|clips\/discover|feed\/reels_tray), script-path=https://raw.githubusercontent.com/app2smile/rules/master/js/instagram.js, requires-body=1, max-size=0, timeout=10

# === YOUTUBE PREMIUM - ekaznyra Version (2026-05-09) ===
# Blocks all ads + enables background playback + PiP
youtube.request = type=http-request, pattern=^https:\/\/youtubei\.googleapis\.com\/youtubei\/v1\/(browse|next|player|reel\/reel_watch_sequence|get_watch), requires-body=1, max-size=0, binary-body-mode=1, script-path=https://raw.githubusercontent.com/wududegw/ytpre/main/Module/js/youtube.response.js
youtube.response = type=http-response, pattern=^https:\/\/youtubei\.googleapis\.com\/youtubei\/v1\/(browse|next|player|search|reel\/reel_watch_sequence|guide|account\/get_setting|get_watch), requires-body=1, max-size=0, binary-body-mode=1, script-path=https://raw.githubusercontent.com/wududegw/ytpre/main/Module/js/youtube.response.js, argument={"lyricLang":"vi","captionLang":"vi","blockUpload":false,"blockImmersive":false,"debug":false}

# ===== Spotify iOS15 (app2smile) =====
spotify-json = type=http-request, pattern=^https:\/\/(spclient\.wg\.spotify\.com|.*-spclient\.spotify\.com(:443)?)\/(artistview\/v1\/artist|album-entity-view\/v2\/album)\/, requires-body=0, script-path=https://raw.githubusercontent.com/app2smile/rules/master/js/spotify-json.js
spotify-proto = type=http-response, pattern=^https:\/\/(spclient\.wg\.spotify\.com|.*-spclient\.spotify\.com(:443)?)\/(bootstrap\/v1\/bootstrap|user-customization-service\/v1\/customize)$, requires-body=1, binary-body-mode=1, max-size=0, script-path=https://raw.githubusercontent.com/app2smile/rules/master/js/spotify-proto.js, script-update-interval=0

# === SOUNDCLOUD GO+ - Marol62926/MarScrpt (yfamilys, 2026-05-19) ===
soundcloud-response = type=http-response, pattern=^https?:\/\/api-mobile\.soundcloud\.com\/configuration\/ios, script-path=https://raw.githubusercontent.com/Marol62926/MarScrpt/main/soundcloud.js, requires-body=1, max-size=0, timeout=15

# === PICSART GOLD - ekaznyra (2026-04-21) ===
picsart-response = type=http-response, pattern=^https:\/\/api\.picsart\.com\/gw-v2\/shop\/subscription\/apple\/purchases, script-path=https://raw.githubusercontent.com/wududegw/ytpre/main/Module/js/PicsArt.js, requires-body=1, max-size=0, timeout=60
picsart-storages = type=http-response, pattern=^https:\/\/api\.picsart\.com\/gw-v2\/cloud-storage\/v1\/me\/storages, script-path=https://raw.githubusercontent.com/wududegw/ytpre/main/Module/js/PicsArt.js, requires-body=1, max-size=0, timeout=60

# === PICSART (NobyDa show/me endpoint) - yfamilys (2026-05-19) ===
picsart-nobyda = type=http-response, pattern=^https?:\/\/api\.(picsart|meiease)\.c(n|om)\/users\/show\/me\.json, script-path=https://raw.githubusercontent.com/NobyDa/Script/master/Surge/JS/PicsArt.js, requires-body=1, max-size=0, timeout=60

# === LIGHTROOM PREMIUM - litieyin/AD_VIP (yfamilys, 2026-05-19) ===
lightroom-response = type=http-response, pattern=^https:\/\/photos\.adobe\.io\/v2\/accounts, script-path=https://raw.githubusercontent.com/litieyin/AD_VIP/main/Script/lightroom.js, requires-body=1, timeout=10, max-size=131072

# === PHOTOSHOP EXPRESS PREMIUM - ekaznyra (2026-05-09) ===
photoshop-response = type=http-response, pattern=^https:\/\/lcs-mobile-cops\.adobe\.io\/mobile_profile, script-path=https://raw.githubusercontent.com/wududegw/ytpre/main/Module/js/photoshop.js, requires-body=1, timeout=10, max-size=131072

# === EMBY PREMIERE - ekaznyra (2026-05-09) ===
emby-response = type=http-response, pattern=^https?:\/\/mb3admin\.com\/admin\/service\/registration\/validateDevice, script-path=https://raw.githubusercontent.com/wududegw/ytpre/main/Module/js/emby.js, requires-body=1, max-size=0, timeout=10

# === KINEMASTER PRO - ekaznyra (2026-04-21) ===
kinemaster-response = type=http-response, pattern=^https:\/\/api-account\.kinemasters\.com\/v\d\/user\/subscribe$, script-path=https://raw.githubusercontent.com/wududegw/ytpre/main/Module/js/Kinemaster.js, requires-body=1, max-size=0, timeout=10

# === DJAY PRO - ekaznyra (2026-05-09) ===
djay-response = type=http-response, pattern=^https:\/\/app\.algoriddim\.com\/api\/v1\/validate-receipt, script-path=https://raw.githubusercontent.com/wududegw/ytpre/main/Module/js/djay.js, requires-body=1, timeout=10, max-size=131072

# === CALM PREMIUM - Alex0510/Eric (yfamilys, 2026-05-19) ===
calm-response = type=http-response, pattern=^https?:\/\/api\.calm\.com\/(me|device|ios\/receipt), script-path=https://raw.githubusercontent.com/Alex0510/Eric/Alex0510/surge/surge/Script/caml.js, requires-body=1, max-size=0, timeout=10

# === BUSUU PREMIUM - ekaznyra (2026-05-09) ===
busuu-response = type=http-response, pattern=^https:\/\/api\.busuu\.com\/users\/me, script-path=https://raw.githubusercontent.com/wududegw/ytpre/main/Module/js/bussu.js, requires-body=1, timeout=10, max-size=131072

# === HEADSPACE PREMIUM - ekaznyra (2026-05-09) ===
headspace-response = type=http-response, pattern=^https:\/\/api\.prod\.headspace\.com\/.*\/user-subscriptions, script-path=https://raw.githubusercontent.com/wududegw/ytpre/main/Module/js/headspace.js, requires-body=1, timeout=10, max-size=131072

# === ALIGHT MOTION PRO - ekaznyra (2026-04-21) ===
alightmotion-response = type=http-response, pattern=^https:\/\/us-central1-alight-creative\.cloudfunctions\.net\/getAccountStatusAndLicenses, script-path=https://raw.githubusercontent.com/wududegw/ytpre/main/Module/js/AlightMotion.js, requires-body=1, max-size=0, timeout=10

# === WINK FOREVER VIP - yqc007 / yfamilys (2026-05-19) ===
wink-response = type=http-response, pattern=^https?:\/\/api-sub\.meitu\.com\/v2\/user\/vip_info_by_group\.json, requires-body=1, max-size=0, timeout=10, script-path=https://raw.githubusercontent.com/yqc007/QuantumultX/master/WinkForeverVipCrack.js

# === TRUECALLER PREMIUM - ekaznyra (2026-04-21) ===
truecaller-response = type=http-response, pattern=^https:\/\/premium-(.+)\.truecaller\.com\/v\d\/(subscriptions|products\/apple), script-path=https://raw.githubusercontent.com/wududegw/ytpre/main/Module/js/TrueCaller.js, requires-body=1, max-size=0, timeout=10

# === CAMSCANNER PREMIUM - ekaznyra (2026-04-21) ===
camscanner-response = type=http-response, pattern=^https:\/\/(api|api-cs.*)\.intsig\.net\/(purchase\/cs\/query_prop|queryProperty|getPrivilegeItem), script-path=https://raw.githubusercontent.com/wududegw/ytpre/main/Module/js/camScanner.js, requires-body=1, max-size=0, timeout=15

# === BEAUTYPLUS PREMIUM - ekaznyra (2026-04-21) ===
beautyplus-response = type=http-response, pattern=^https:\/\/(api\.mr\.pixocial\.com\/v1\/manual_unlock|newbeee-api\.beautyplus\.com\/api\/v1\/asset\/balance), script-path=https://raw.githubusercontent.com/wududegw/ytpre/main/Module/js/BeautyPlus.js, requires-body=1, timeout=60, max-size=0

# === REVENUECAT MULTI-APP (Locket Gold) - ekaznyra (2026-04-21) ===
revenuecat-response = type=http-response, pattern=^https:\/\/api\.revenuecat\.com\/.+\/(receipts$|subscribers\/[^\/]+$), script-path=https://raw.githubusercontent.com/wududegw/ytpre/main/Module/js/revenuecat_multi.js, requires-body=1, timeout=60, max-size=0

# === REVENUECAT BACKUP DOMAIN (rc-backup fallback) - ekaznyra (2026-05-09) ===
revenuecat-backup = type=http-response, pattern=^https:\/\/api\.rc-backup\.com\/.+\/(receipts$|subscribers\/[^\/]+$), script-path=https://raw.githubusercontent.com/wududegw/ytpre/main/Module/js/revenuecat_multi.js, requires-body=1, max-size=0, timeout=60

# === VSCO PREMIUM - ekaznyra (2026-05-09) ===
vsco-response = type=http-response, pattern=^https:\/\/vsco\.co\/api\/subscriptions\/2\.1\/user-subscriptions, script-path=https://raw.githubusercontent.com/wududegw/ytpre/main/Module/js/VSCO.js, requires-body=1, timeout=10, max-size=131072

# === FUNIMATE PRO - ekaznyra (2026-05-09) ===
funimate-response = type=http-response, pattern=^https:\/\/api\.funimate\.com\/users\/me, script-path=https://raw.githubusercontent.com/wududegw/ytpre/main/Module/js/funimate.js, requires-body=1, timeout=10, max-size=131072

# === ITUNES PREMIUM (250+ Apps) - ekaznyra (2026-05-09) ===
itunes-response = type=http-response, pattern=^https?:\/\/buy\.itunes\.apple\.com\/verifyReceipt$, script-path=https://raw.githubusercontent.com/wududegw/ytpre/main/Module/js/iTunes.js, requires-body=1, max-size=0, timeout=60

# === SNOW PREMIUM - ekaznyra (2026-05-09) ===
snow-response = type=http-response, pattern=^https?:\/\/user-snow-api\.snow\.me\/v\d\/purchase\/subscription\/subscriber\/status, script-path=https://raw.githubusercontent.com/wududegw/ytpre/main/Module/js/Snow.js, requires-body=1, max-size=0, timeout=60

# === B612 KAJI VIP - ddgksf2013 (yfamilys, 2026-05-19) ===
b612-response = type=http-response, pattern=^https?:\/\/user-kaji-api\.b612kaji\.com\/v\d\/purchase\/subscription\/subscriber\/status, script-path=https://github.com/deezertidal/private/raw/master/js-backup/Crack/612.js, requires-body=1, max-size=0, timeout=60

# === MEITU XIUXIU PREMIUM - ekaznyra (2026-05-09) ===
meitu-response = type=http-response, pattern=^https?:\/\/(h5|api)\.xiuxiu\.meitu\.com\/v\d\/(h\d\/vip|vip|user)\/, script-path=https://raw.githubusercontent.com/wududegw/ytpre/main/Module/js/MeiTuXiuXiu.js, requires-body=1, max-size=0, timeout=60

# === WPS OFFICE PREMIUM - I-am-R-E (yfamilys, 2026-05-19) ===
wps-response = type=http-response, pattern=^https?:\/\/.*?account\.wps\.(com|cn)(:\d+)?\/api\/users\/\w+\/overview$, script-path=https://raw.githubusercontent.com/I-am-R-E/Functional-Store-Hub/Master/WPSOffice/Script/WPS.js, requires-body=1, max-size=0, timeout=10

# === XMIND PREMIUM - ekaznyra (2026-05-09) ===
xmind-response = type=http-response, pattern=^https?:\/\/www\.xmind\.(cn|net|app)\/_res\/devices, script-path=https://raw.githubusercontent.com/wududegw/ytpre/main/Module/js/xmind.js, requires-body=1, max-size=0, timeout=10

# === ALARMY PREMIUM ===
alarmy-response = type=http-response, pattern=^https:\/\/ars\.alar\.my\/api\/v2\/user\/sync, script-path=https://raw.githubusercontent.com/Marol62926/MarScrpt/main/alarmy.js, requires-body=1, max-size=0, timeout=10

# === GRAMMARLY PREMIUM - yqc007 (yfamilys, 2026-05-19) ===
grammarly-response = type=http-response, pattern=^https?:\/\/subscription\.grammarly\.com\/api\/v1\/subscription$, script-path=https://raw.githubusercontent.com/yqc007/QuantumultX/master/GrammarlyPremiumCrack.js, requires-body=1, max-size=0, timeout=10

# === NOTABILITY PLUS - litieyin (yfamilys, 2026-05-19) ===
notability-response = type=http-response, pattern=^https:\/\/notability\.com\/subscriptions, script-path=https://raw.githubusercontent.com/litieyin/AD_VIP/main/Script/notability.js, requires-body=1, max-size=0, timeout=10

# === PHOTOMATH PLUS - ddgksf2013 (yfamilys, 2026-05-19) ===
photomath-response = type=http-response, pattern=^https?:\/\/lapi\.photomath\.net\/v4\/me, script-path=https://raw.githubusercontent.com/deezertidal/private/master/js-backup/Crack/poh.js, requires-body=1, max-size=0, timeout=10

# === SMALLPDF PRO - Marol62926 (yfamilys, 2026-05-19) ===
smallpdf-response = type=http-response, pattern=^https?:\/\/pro\.smallpdf\.com\/pro\/account, script-path=https://raw.githubusercontent.com/Marol62926/MarScrpt/main/smallpdf.js, requires-body=1, max-size=0, timeout=10

# === PEAK PRO - chamberlen (yfamilys, 2026-05-19) ===
peak-response = type=http-response, pattern=^https:\/\/billing\.peakcloud\.org\/billing\/2\/user\/me, script-path=https://raw.githubusercontent.com/deezertidal/shadowrocket-rules/main/js/peak.js, requires-body=1, max-size=0, timeout=10

# === POLARR PRO - NobyDa (yfamilys, 2026-05-19) ===
polarr-response = type=http-response, pattern=^https:\/\/api\.polaxiong\.com\/v1\/payments\/appleiap\/receipts\/confirmation, script-path=https://raw.githubusercontent.com/NobyDa/Script/master/Surge/JS/Polarr.js, requires-body=1, max-size=0, timeout=10

# === MYFITNESSPAL PREMIUM - Marol62926 (yfamilys, 2026-05-19) ===
myfitnesspal-response = type=http-response, pattern=^https?:\/\/premium-api\.myfitnesspal\.com\/v3\/subscriptions\/MFP\/, script-path=https://raw.githubusercontent.com/Marol62926/MarScrpt/main/myFitnessPal.js, requires-body=1, max-size=0, timeout=10

# === MUSIXMATCH PREMIUM - Marol62926 (yfamilys, 2026-05-19) ===
musixmatch-response = type=http-response, pattern=^https?:\/\/apic\.musixmatch\.com\/ws\/1\.1\/config\.get, script-path=https://raw.githubusercontent.com/Marol62926/MarScrpt/main/musixmatch.js, requires-body=1, max-size=0, timeout=10

# === FIMO CAMERA - ddgksf2013 (yfamilys, 2026-05-19) ===
fimo-response = type=http-response, pattern=^https:\/\/server\.yoyiapp\.com\/fimo-user\/user$, script-path=https://github.com/deezertidal/private/raw/master/js-backup/Crack/fimo.js, requires-body=1, max-size=0, timeout=10

# === VARLENS PREMIUM - I-am-R-E (yfamilys, 2026-05-19) ===
varlens-response = type=http-response, pattern=^https:\/\/mid\.zineapi\.com\/@varlens\/api\/user\/info\/, script-path=https://raw.githubusercontent.com/89996462/Quantumult-X/main/ycdz/Varlens.js, requires-body=1, max-size=0, timeout=10

# === SUB-STORE (Node Management) ===
sub-store-core = type=http-request, pattern=^https?:\/\/sub\.store\/((download)|api\/(preview|sync|(utils\/node-info))), script-path=https://github.com/sub-store-org/Sub-Store/releases/latest/download/sub-store-1.min.js, requires-body=1, timeout=120
sub-store-simple = type=http-request, pattern=^https?:\/\/sub\.store, script-path=https://github.com/sub-store-org/Sub-Store/releases/latest/download/sub-store-0.min.js, requires-body=1, timeout=10
sub-store-sync = type=cron, cronexp=0 0 * * *, wake-system=1, timeout=120, script-path=https://github.com/sub-store-org/Sub-Store/releases/latest/download/cron-sync-artifacts.min.js

# === BOOM EQUALIZER - ddgksf2013 (yfamilys, 2026-05-24) ===
boom-response = type=http-response, pattern=^https:\/\/apimboom2\.globaldelight\.net\/itunesreceipt_v2\.php$, script-path=https://github.com/deezertidal/private/raw/master/js-backup/Crack/boom.js, requires-body=1, max-size=0, timeout=10

# === FANTASTICAL PREMIUM - ddgksf2013 (yfamilys, 2026-05-24) ===
fantastical-response = type=http-response, pattern=^https:\/\/api\.flexibits\.com\/(v1\/auth\/device|v1\/account\/details), script-path=https://raw.githubusercontent.com/deezertidal/private/master/js-backup/Crack/fantastical.js, requires-body=1, max-size=0, timeout=10

# === CRAFT PREMIUM - 89996462 (yfamilys, 2026-05-24) ===
craft-response = type=http-response, pattern=^https:\/\/api\.craft\.do\/auth\/v2\/profile, script-path=https://raw.githubusercontent.com/89996462/Quantumult-X/main/ycdz/Craft.js, requires-body=1, max-size=0, timeout=10

# === DAY ONE PREMIUM - 89996462 (yfamilys, 2026-05-24) ===
dayone-response = type=http-response, pattern=^https?:\/\/dayone\.app\/api\/v2\/users\/(receipt|account-status), script-path=https://raw.githubusercontent.com/89996462/Quantumult-X/main/ycdz/dayone.js, requires-body=1, max-size=0, timeout=10

# === NICEGRAM PREMIUM - I-am-R-E (yfamilys, 2026-05-24) ===
nicegram-request = type=http-request, pattern=^https?:\/\/api\.nicegram\.app\/api\/v\d\/user\/info, script-path=https://raw.githubusercontent.com/I-am-R-E/Functional-Store-Hub/Master/Nicegram/Script/Nicegram.js, requires-body=1, max-size=0, timeout=10

[MITM]
enable = true
hostname = *youtube.com, *googlevideo.com, youtubei.googleapis.com, api.revenuecat.com, api.rc-backup.com, spclient.wg.spotify.com, i.instagram.com, api.twitter.com, api.x.com, api.picsart.com, photos.adobe.io, lcs-mobile-cops.adobe.io, mb3admin.com, api-account.kinemasters.com, app.algoriddim.com, api.calm.com, api.busuu.com, api.prod.headspace.com, us-central1-alight-creative.cloudfunctions.net, api-sub.meitu.com, premium-*.truecaller.com, api*.intsig.net, api.mr.pixocial.com, newbeee-api.beautyplus.com, vsco.co, api.funimate.com, buy.itunes.apple.com, user-snow-api.snow.me, user-kaji-api.b612kaji.com, *.xiuxiu.meitu.com, *account.wps.com, *account.wps.cn, www.xmind.cn, www.xmind.net, www.xmind.app, ars.alar.my, subscription.grammarly.com, notability.com, lapi.photomath.net, pro.smallpdf.com, billing.peakcloud.org, api.polaxiong.com, premium-api.myfitnesspal.com, apic.musixmatch.com, server.yoyiapp.com, mid.zineapi.com, apimboom2.globaldelight.net, api.flexibits.com, api.craft.do, dayone.app
`;

// App State Management
const State = {
  rawConfig: DEFAULT_CONFIG,
  parsed: null,
  activeTab: 'overview',
  
  // Rule Table Pagination & Search
  ruleQuery: '',
  ruleFilterAction: '',
  rulePage: 1,
  rulePageSize: 10,
  
  // Simulator State
  simulatorLogs: [],
  
  // Notification timer
  toastTimer: null
};

// ==========================================
// 1. Parser Engine
// ==========================================
function parseConfig(text) {
  const result = {
    metadata: {
      name: 'Untitled Ruleset',
      desc: 'No description provided.',
      version: '1.0.0',
      date: 'N/A',
      author: 'Unknown',
      homepage: '',
      icon: '',
      system: 'all'
    },
    general: {},
    rules: [],
    rewrites: [],
    mapLocals: [],
    scripts: [],
    unknownSections: {}
  };

  const lines = text.split(/\r?\n/);
  let currentSection = null;

  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i];
    const line = rawLine.trim();

    // 1. Parse Metadata Headers (e.g. #!name=...)
    if (line.startsWith('#!')) {
      const match = line.match(/^#\!([a-zA-Z0-9]+)\s*=\s*(.+)$/);
      if (match) {
        const key = match[1].toLowerCase();
        const value = match[2].trim();
        result.metadata[key] = value;
      }
      continue;
    }

    // 2. Identify Section Headers
    if (line.startsWith('[') && line.endsWith(']')) {
      currentSection = line.slice(1, -1).trim();
      continue;
    }

    // Skip empty lines
    if (!line) continue;

    // Save index reference for toggle enables
    const lineIndex = i;

    // 3. Process Section Contents
    if (currentSection === 'General') {
      // General is key = value
      const commentIdx = line.indexOf('#');
      const cleanLine = commentIdx >= 0 ? line.substring(0, commentIdx).trim() : line;
      if (cleanLine.includes('=')) {
        const parts = cleanLine.split('=');
        const key = parts[0].trim();
        const val = parts.slice(1).join('=').trim();
        result.general[key] = val;
      }
    } else if (currentSection === 'Rule') {
      // Rule is TYPE,VALUE,ACTION[,OPTIONS] or AND block
      const isComment = line.startsWith('#') || line.startsWith(';');
      const activeContent = isComment ? line.replace(/^[\#\;]\s*/, '') : line;
      
      const parts = splitCommaSafely(activeContent);
      if (parts.length >= 3) {
        result.rules.push({
          type: parts[0].toUpperCase(),
          value: parts[1],
          action: parts[2].toUpperCase(),
          options: parts.slice(3).join(','),
          enabled: !isComment,
          rawLineIndex: lineIndex
        });
      } else if (parts[0] && parts[0].toUpperCase() === 'AND') {
        // AND rules logic, parse match criteria
        result.rules.push({
          type: 'AND',
          value: parts.slice(1, -1).join(','),
          action: parts[parts.length - 1].toUpperCase(),
          options: '',
          enabled: !isComment,
          rawLineIndex: lineIndex
        });
      }
    } else if (currentSection === 'Header Rewrite' || currentSection === 'URL Rewrite') {
      const isComment = line.startsWith('#') || line.startsWith(';');
      const activeContent = isComment ? line.replace(/^[\#\;]\s*/, '') : line;
      result.rewrites.push({
        section: currentSection,
        content: activeContent,
        enabled: !isComment,
        rawLineIndex: lineIndex
      });
    } else if (currentSection === 'Map Local') {
      const isComment = line.startsWith('#') || line.startsWith(';');
      const activeContent = isComment ? line.replace(/^[\#\;]\s*/, '') : line;
      result.mapLocals.push({
        content: activeContent,
        enabled: !isComment,
        rawLineIndex: lineIndex
      });
    } else if (currentSection === 'Script') {
      const isComment = line.startsWith('#') || line.startsWith(';');
      const activeContent = isComment ? line.replace(/^[\#\;]\s*/, '') : line;
      if (activeContent.includes('=')) {
        const parts = activeContent.split('=');
        const name = parts[0].trim();
        const configStr = parts.slice(1).join('=').trim();
        
        result.scripts.push({
          name: name,
          config: configStr,
          enabled: !isComment,
          rawLineIndex: lineIndex
        });
      }
    }
  }

  return result;
}

// Splits line by comma, respecting parentheses (e.g. inside AND blocks)
function splitCommaSafely(str) {
  const result = [];
  let current = '';
  let depth = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str[i];
    if (char === '(') depth++;
    else if (char === ')') depth--;
    
    if (char === ',' && depth === 0) {
      result.push(current.trim());
      current = '';
    } else {
      current += char;
    }
  }
  if (current) result.push(current.trim());
  return result;
}

// ==========================================
// 2. Matching Engine (Simulation)
// ==========================================
function evaluateMatch(domain, parsedConfig) {
  const domainLower = domain.toLowerCase().trim();
  const trace = [];
  
  trace.push({
    title: `Starting Evaluation for Domain: "${domainLower}"`,
    type: 'info',
    desc: 'Checking configuration rules sequentially...'
  });

  // Check rules in order
  for (const rule of parsedConfig.rules) {
    if (!rule.enabled) continue;

    const ruleValLower = rule.value.toLowerCase().trim();

    if (rule.type === 'DOMAIN') {
      if (domainLower === ruleValLower) {
        return handleHit(rule, `Exact match of DOMAIN rule: "${rule.value}"`, trace);
      }
    } else if (rule.type === 'DOMAIN-SUFFIX') {
      // E.g. match spclient.wg.spotify.com with spotify.com or spclient.wg.spotify.com
      if (domainLower === ruleValLower || domainLower.endsWith('.' + ruleValLower)) {
        return handleHit(rule, `Suffix matched rule: "${rule.value}"`, trace);
      }
    } else if (rule.type === 'DOMAIN-KEYWORD') {
      if (domainLower.includes(ruleValLower)) {
        return handleHit(rule, `Keyword matched rule: "${rule.value}"`, trace);
      }
    } else if (rule.type === 'AND') {
      // AND blocks logic. E.g. AND,((DOMAIN-SUFFIX,googlevideo.com), (PROTOCOL,UDP)),REJECT
      // If domain matches googlevideo.com, it is potentially a hit (mocking protocol check)
      if (rule.value.includes('googlevideo.com') && domainLower.endsWith('googlevideo.com')) {
        return handleHit(rule, `AND block condition matched (Suffix: googlevideo.com, Protocol: UDP)`, trace);
      }
    } else if (rule.type === 'GEOIP') {
      // Vietnam GeoIP bypass
      if (ruleValLower === 'vn' && (domainLower.endsWith('.vn') || domainLower.endsWith('.vn.com'))) {
        return handleHit(rule, `GeoIP Vietnam matched (.vn extension)`, trace);
      }
    }
  }

  // Fallback to default
  const defaultAction = 'DIRECT';
  trace.push({
    title: `Default Fallback Applied`,
    type: 'fallback',
    desc: `No active rules explicitly matched this domain. Traffic routed to Default connection: ${defaultAction}`
  });

  return {
    action: defaultAction,
    rule: null,
    trace: trace
  };
}

function handleHit(rule, matchMsg, trace) {
  trace.push({
    title: `Rule Match Hit: [${rule.type}]`,
    type: 'hit',
    desc: `${matchMsg} -> Action routed: ${rule.action} ${rule.options ? '(' + rule.options + ')' : ''}`
  });
  return {
    action: rule.action,
    rule: rule,
    trace: trace
  };
}

// ==========================================
// 3. Optimizer & Beautifier
// ==========================================
function runOptimization(parsed, rawText) {
  const issues = [];
  let duplicatesCleaned = 0;
  let redundanciesCleaned = 0;
  const uniqueRules = new Set();
  const suffixRules = []; // tracking suffix rules to check for subdomain redundancies
  
  // First pass: identify all suffixes
  parsed.rules.forEach(r => {
    if (r.enabled && r.type === 'DOMAIN-SUFFIX') {
      suffixRules.push(r.value.toLowerCase().trim());
    }
  });

  const lines = rawText.split(/\r?\n/);
  const cleanedLines = [...lines];
  const linesToRemoved = new Set();

  for (let i = 0; i < parsed.rules.length; i++) {
    const rule = parsed.rules[i];
    if (!rule.enabled) continue;

    const ruleKey = `${rule.type}:${rule.value.toLowerCase().trim()}:${rule.action.toUpperCase()}`;

    // 1. Check exact duplicates
    if (uniqueRules.has(ruleKey)) {
      duplicatesCleaned++;
      linesToRemoved.add(rule.rawLineIndex);
      issues.push({
        type: 'warning',
        title: 'Duplicate Rule Detected',
        desc: `Rule \`${rule.type}, ${rule.value}, ${rule.action}\` is repeated and will be cleaned.`
      });
      continue;
    }
    uniqueRules.add(ruleKey);

    // 2. Check redundant subdomain matches
    // If we have a rule DOMAIN-SUFFIX,adjust.com,REJECT, then DOMAIN,app.adjust.com,REJECT is completely redundant.
    if (rule.type === 'DOMAIN') {
      const valLower = rule.value.toLowerCase().trim();
      const parentSuffix = suffixRules.find(suffix => valLower.endsWith('.' + suffix));
      if (parentSuffix) {
        redundanciesCleaned++;
        linesToRemoved.add(rule.rawLineIndex);
        issues.push({
          type: 'info',
          title: 'Redundant Subdomain Rule',
          desc: `\`DOMAIN, ${rule.value}\` is redundant since \`DOMAIN-SUFFIX, ${parentSuffix}\` is already blocked.`
        });
      }
    }
  }

  // Construct clean text
  const optimizedLines = [];
  for (let i = 0; i < lines.length; i++) {
    if (!linesToRemoved.has(i)) {
      optimizedLines.push(lines[i]);
    }
  }

  return {
    issues: issues,
    duplicatesCleaned: duplicatesCleaned,
    redundanciesCleaned: redundanciesCleaned,
    optimizedText: optimizedLines.join('\n')
  };
}

// ==========================================
// 4. Reactive UI Rendering
// ==========================================
function initApp() {
  State.parsed = parseConfig(State.rawConfig);
  
  // Set initial text in editor
  const textarea = document.getElementById('configEditor');
  textarea.value = State.rawConfig;
  updateLineNumbers();

  // Tab navigation bindings
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const tabName = btn.dataset.tab;
      switchTab(tabName);
    });
  });

  // Editor Key Listener to parse in real-time
  textarea.addEventListener('input', (e) => {
    State.rawConfig = e.target.value;
    State.parsed = parseConfig(State.rawConfig);
    updateLineNumbers();
    renderOverview();
    renderRulesTable();
    renderScriptsTab();
    renderOptimizer();
  });

  // Hook Scroll of textarea and line numbers
  textarea.addEventListener('scroll', () => {
    const lineNumbers = document.getElementById('lineNumbers');
    lineNumbers.scrollTop = textarea.scrollTop;
  });

  // Action Buttons
  document.getElementById('saveBtn').addEventListener('click', saveConfig);
  document.getElementById('beautifyBtn').addEventListener('click', optimizeAndBeautify);

  // Search input binding
  document.getElementById('ruleSearch').addEventListener('input', (e) => {
    State.ruleQuery = e.target.value;
    State.rulePage = 1;
    renderRulesTable();
  });

  document.getElementById('ruleFilter').addEventListener('change', (e) => {
    State.ruleFilterAction = e.target.value;
    State.rulePage = 1;
    renderRulesTable();
  });

  // Match simulator console input binding
  const simInput = document.getElementById('simConsoleInput');
  simInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      const val = simInput.value.trim();
      if (val) {
        executeSimulation(val);
        simInput.value = '';
      }
    }
  });

  // Trigger initial renders
  renderOverview();
  renderRulesTable();
  renderScriptsTab();
  renderOptimizer();
  initSimulatorWelcome();
  if (window.lucide) {
    window.lucide.createIcons();
  }
}

function updateLineNumbers() {
  const lineNumbers = document.getElementById('lineNumbers');
  const text = State.rawConfig;
  const linesCount = text.split(/\r?\n/).length;
  
  let numStr = '';
  for (let i = 1; i <= linesCount; i++) {
    numStr += i + '\n';
  }
  lineNumbers.textContent = numStr;
}

function switchTab(tabName) {
  State.activeTab = tabName;
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.tab === tabName);
  });
  document.querySelectorAll('.tab-content').forEach(content => {
    content.classList.toggle('active', content.id === `${tabName}Tab`);
  });

  // If entering Optimizer, refresh calculations
  if (tabName === 'optimizer') {
    renderOptimizer();
  }
}

// ------------------------------------------
// Overview Tab
// ------------------------------------------
function renderOverview() {
  const meta = State.parsed.metadata;
  
  // Metadata fields
  document.getElementById('metaName').textContent = meta.name;
  document.getElementById('metaDesc').textContent = meta.desc;
  document.getElementById('metaVersion').textContent = meta.version;
  document.getElementById('metaDate').textContent = meta.date;
  document.getElementById('metaAuthor').textContent = meta.author;
  
  const homepageLink = document.getElementById('metaHomepage');
  homepageLink.textContent = meta.homepage || 'None';
  homepageLink.href = meta.homepage || '#';
  
  // Metrics count
  const rules = State.parsed.rules;
  const totalCount = rules.length;
  const rejectCount = rules.filter(r => r.enabled && r.action === 'REJECT').length;
  const proxyCount = rules.filter(r => r.enabled && r.action === 'PROXY').length;
  const directCount = rules.filter(r => r.enabled && r.action === 'DIRECT').length;
  const scriptCount = State.parsed.scripts.length;

  document.getElementById('metricTotalRules').textContent = totalCount;
  document.getElementById('metricRejects').textContent = rejectCount;
  document.getElementById('metricProxies').textContent = proxyCount;
  document.getElementById('metricDirect').textContent = directCount;

  // Render list of rules grouped by category (Ad networks, AI, Gaming, Banking etc)
  const listContainer = document.getElementById('categoryCountList');
  listContainer.innerHTML = '';

  const groups = [
    { name: 'Ads & Anti-Tracking', icon: 'shield-alert', count: rejectCount },
    { name: 'AI Services Routing', icon: 'brain', count: rules.filter(r => r.enabled && r.value.includes('openai') || r.value.includes('chatgpt') || r.value.includes('deepseek') || r.value.includes('gemini')).length },
    { name: 'VIP App Scripts', icon: 'sparkles', count: scriptCount },
    { name: 'Vietnamese Banking DIRECT', icon: 'wallet', count: rules.filter(r => r.enabled && r.action === 'DIRECT' && (r.value.includes('.vn') || r.value.includes('momo') || r.value.includes('bank'))).length },
    { name: 'Social Media & Chats', icon: 'message-square', count: rules.filter(r => r.enabled && r.value.includes('telegram') || r.value.includes('reddit') || r.value.includes('discord')).length },
    { name: 'Media Streaming VIP', icon: 'video', count: rules.filter(r => r.enabled && r.value.includes('netflix') || r.value.includes('youtube')).length }
  ];

  groups.forEach(g => {
    const row = document.createElement('div');
    row.className = 'category-row';
    row.innerHTML = `
      <div class="category-name">
        <i data-lucide="${g.icon}" style="width: 14px; height: 14px; vertical-align: middle;"></i>
        <span>${g.name}</span>
      </div>
      <div class="category-count">${g.count}</div>
    `;
    listContainer.appendChild(row);
  });
  if (window.lucide) {
    window.lucide.createIcons();
  }
}

// ------------------------------------------
// Rules Tab Paginated Table
// ------------------------------------------
function renderRulesTable() {
  const rules = State.parsed.rules;
  
  // Filter rules
  let filtered = rules.filter(r => {
    const matchQuery = !State.ruleQuery || 
      r.value.toLowerCase().includes(State.ruleQuery.toLowerCase()) || 
      r.type.toLowerCase().includes(State.ruleQuery.toLowerCase());
    const matchAction = !State.ruleFilterAction || r.action === State.ruleFilterAction;
    return matchQuery && matchAction;
  });

  // Pagination bounds
  const total = filtered.length;
  const pagesCount = Math.ceil(total / State.rulePageSize) || 1;
  if (State.rulePage > pagesCount) State.rulePage = pagesCount;

  const startIdx = (State.rulePage - 1) * State.rulePageSize;
  const endIdx = Math.min(startIdx + State.rulePageSize, total);
  const pageRules = filtered.slice(startIdx, endIdx);

  // Stats Text
  document.getElementById('ruleTableStatsText').textContent = `Showing ${total > 0 ? startIdx + 1 : 0} to ${endIdx} of ${total} entries`;

  // Render Table Rows
  const tbody = document.getElementById('rulesTableBody');
  tbody.innerHTML = '';

  if (pageRules.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 2rem;">No rules matching search criteria found.</td></tr>`;
  } else {
    pageRules.forEach(rule => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><span class="rule-type-badge">${rule.type}</span></td>
        <td style="font-family: 'Fira Code', monospace; word-break: break-all;">${rule.value}</td>
        <td><span class="action-badge ${rule.action.toLowerCase()}">${rule.action}</span></td>
        <td><span style="font-size: 0.75rem; color: var(--text-muted);">${rule.options || '-'}</span></td>
        <td>
          <label class="toggle-switch">
            <input type="checkbox" ${rule.enabled ? 'checked' : ''} data-line="${rule.rawLineIndex}">
            <span class="slider"></span>
          </label>
        </td>
      `;
      
      // Toggle change event binding
      tr.querySelector('input').addEventListener('change', (e) => {
        toggleRuleLine(rule.rawLineIndex, e.target.checked);
      });

      tbody.appendChild(tr);
    });
  }

  // Paging controls
  const paginationControls = document.getElementById('rulePaginationControls');
  paginationControls.innerHTML = '';

  // Prev Button
  const prevBtn = document.createElement('button');
  prevBtn.className = `page-btn ${State.rulePage === 1 ? 'disabled' : ''}`;
  prevBtn.innerHTML = '←';
  if (State.rulePage > 1) {
    prevBtn.addEventListener('click', () => { State.rulePage--; renderRulesTable(); });
  }
  paginationControls.appendChild(prevBtn);

  // Page Numbers
  const maxPageVisible = 3;
  let startPage = Math.max(1, State.rulePage - 1);
  let endPage = Math.min(pagesCount, startPage + maxPageVisible - 1);
  if (endPage - startPage < maxPageVisible - 1) {
    startPage = Math.max(1, endPage - maxPageVisible + 1);
  }

  for (let p = startPage; p <= endPage; p++) {
    const pBtn = document.createElement('button');
    pBtn.className = `page-btn ${State.rulePage === p ? 'active' : ''}`;
    pBtn.textContent = p;
    pBtn.addEventListener('click', () => { State.rulePage = p; renderRulesTable(); });
    paginationControls.appendChild(pBtn);
  }

  // Next Button
  const nextBtn = document.createElement('button');
  nextBtn.className = `page-btn ${State.rulePage === pagesCount ? 'disabled' : ''}`;
  nextBtn.innerHTML = '→';
  if (State.rulePage < pagesCount) {
    nextBtn.addEventListener('click', () => { State.rulePage++; renderRulesTable(); });
  }
  paginationControls.appendChild(nextBtn);
  if (window.lucide) {
    window.lucide.createIcons();
  }
}

function toggleRuleLine(lineIndex, enabled) {
  const lines = State.rawConfig.split(/\r?\n/);
  const line = lines[lineIndex];

  if (enabled) {
    // enable: remove starting # or ;
    lines[lineIndex] = line.replace(/^[\#\;]\s*/, '');
  } else {
    // disable: prepend #
    lines[lineIndex] = '# ' + line;
  }

  State.rawConfig = lines.join('\n');
  const textarea = document.getElementById('configEditor');
  textarea.value = State.rawConfig;
  
  State.parsed = parseConfig(State.rawConfig);
  renderOverview();
  renderRulesTable();
  renderScriptsTab();
  renderOptimizer();
}

// ------------------------------------------
// Scripts Tab
// ------------------------------------------
function renderScriptsTab() {
  const scripts = State.parsed.scripts;
  const rewrites = State.parsed.rewrites;

  const rewritesContainer = document.getElementById('rewritesContainer');
  rewritesContainer.innerHTML = '';

  if (rewrites.length === 0) {
    rewritesContainer.innerHTML = `<div style="color: var(--text-muted); font-size: 0.8rem;">No URL / Header Rewrites configured.</div>`;
  } else {
    rewrites.forEach(r => {
      const item = document.createElement('div');
      item.className = 'category-row';
      item.style.marginBottom = '0.5rem';
      item.style.flexDirection = 'column';
      item.style.alignItems = 'flex-start';
      item.style.gap = '0.35rem';
      item.innerHTML = `
        <div style="display:flex; justify-content:space-between; width:100%;">
          <span class="rule-type-badge">${r.section}</span>
          <label class="toggle-switch">
            <input type="checkbox" ${r.enabled ? 'checked' : ''} data-line="${r.rawLineIndex}">
            <span class="slider"></span>
          </label>
        </div>
        <div style="font-family: 'Fira Code', monospace; font-size: 0.75rem; color: var(--text-secondary); word-break: break-all; margin-top: 0.25rem;">
          ${r.content}
        </div>
      `;
      item.querySelector('input').addEventListener('change', (e) => {
        toggleRuleLine(r.rawLineIndex, e.target.checked);
      });
      rewritesContainer.appendChild(item);
    });
  }

  const scriptsContainer = document.getElementById('scriptsContainer');
  scriptsContainer.innerHTML = '';

  if (scripts.length === 0) {
    scriptsContainer.innerHTML = `<div style="color: var(--text-muted); font-size: 0.8rem;">No active VIP App scripts configured.</div>`;
  } else {
    scripts.forEach(s => {
      const item = document.createElement('div');
      item.className = 'category-row';
      item.style.marginBottom = '0.5rem';
      item.style.flexDirection = 'column';
      item.style.alignItems = 'flex-start';
      item.style.gap = '0.35rem';
      item.innerHTML = `
        <div style="display:flex; justify-content:space-between; width:100%;">
          <span style="font-weight: 600; color: #a855f7;"><i data-lucide="sparkles" style="width:14px; height:14px; vertical-align:middle; margin-right:4px;"></i>${s.name}</span>
          <label class="toggle-switch">
            <input type="checkbox" ${s.enabled ? 'checked' : ''} data-line="${s.rawLineIndex}">
            <span class="slider"></span>
          </label>
        </div>
        <div style="font-family: 'Fira Code', monospace; font-size: 0.7rem; color: var(--text-secondary); word-break: break-all; margin-top: 0.25rem;">
          ${s.config}
        </div>
      `;
      item.querySelector('input').addEventListener('change', (e) => {
        toggleRuleLine(s.rawLineIndex, e.target.checked);
      });
      scriptsContainer.appendChild(item);
    });
  }
  if (window.lucide) {
    window.lucide.createIcons();
  }
}

// ------------------------------------------
// Live Match Simulator
// ------------------------------------------
function initSimulatorWelcome() {
  const body = document.getElementById('simConsoleBody');
  body.innerHTML = `
    <div class="console-welcome">
      <p style="color:#a855f7; font-weight:600; font-size:0.9rem; margin-bottom: 0.5rem;">👑 Phan Doãn Hoàng - PREMIUM MATCH TESTBENCH 👑</p>
      <p>Enter a domain URL below to trace Surge routing decisions dynamically.</p>
      <p style="color:var(--text-muted); margin-top: 0.25rem;">Examples: spclient.wg.spotify.com, gemini.google.com, doubleclick.net, momo.vn</p>
    </div>
    <div id="simConsoleResults"></div>
  `;
}

function executeSimulation(domain) {
  const resultsContainer = document.getElementById('simConsoleResults');
  resultsContainer.innerHTML = ''; // clear previous simulation trace
  
  const traceOutput = evaluateMatch(domain, State.parsed);
  
  let delay = 0;
  
  // Print each trace step with typing simulator delay
  traceOutput.trace.forEach((step, idx) => {
    setTimeout(() => {
      const stepDiv = document.createElement('div');
      stepDiv.className = `trace-step ${step.type === 'hit' ? 'hit' : ''}`;
      
      let badgeStyle = 'color: #38bdf8;';
      if (step.type === 'hit') badgeStyle = 'color: #f43f5e; font-weight:600;';
      if (step.type === 'fallback') badgeStyle = 'color: #10b981; font-weight:600;';
      
      stepDiv.innerHTML = `
        <span style="${badgeStyle}">[${step.title}]</span><br>
        <span style="color: var(--text-muted); font-size:0.75rem;">└ ${step.desc}</span>
      `;
      resultsContainer.appendChild(stepDiv);
      
      // Auto-scroll console
      const consoleBody = document.getElementById('simConsoleBody');
      consoleBody.scrollTop = consoleBody.scrollHeight;
    }, delay);
    
    delay += 250; // 250ms spacing per step
  } );

  // Final summary block
  setTimeout(() => {
    const summaryDiv = document.createElement('div');
    summaryDiv.className = 'trace-match-details';
    
    let borderClr = 'rgba(16, 185, 129, 0.3)';
    let valClr = 'color: var(--accent-direct);';
    if (traceOutput.action === 'REJECT' || traceOutput.action === 'REJECT-DROP') {
      borderClr = 'rgba(244, 63, 94, 0.3)';
      valClr = 'color: var(--accent-reject);';
    } else if (traceOutput.action === 'PROXY') {
      borderClr = 'rgba(6, 182, 212, 0.3)';
      valClr = 'color: var(--accent-proxy);';
    }

    summaryDiv.style.borderLeft = `4px solid ${borderClr}`;
    summaryDiv.innerHTML = `
      <div style="font-weight:600; font-size:0.85rem; margin-bottom:0.25rem;">Simulation Result:</div>
      <div style="display:flex; justify-content:space-between; font-size:0.8rem;">
        <span>Final Decision: <strong style="${valClr}">${traceOutput.action}</strong></span>
        <span style="color:var(--text-muted);">Matches: ${traceOutput.rule ? traceOutput.rule.type + ' (' + traceOutput.rule.value + ')' : 'Default Fallback'}</span>
      </div>
    `;
    resultsContainer.appendChild(summaryDiv);
    
    const consoleBody = document.getElementById('simConsoleBody');
    consoleBody.scrollTop = consoleBody.scrollHeight;
  }, delay + 300);
}

// ------------------------------------------
// Optimizer Tab
// ------------------------------------------
function renderOptimizer() {
  const optResult = runOptimization(State.parsed, State.rawConfig);
  
  // Totals
  document.getElementById('optDuplicateCount').textContent = optResult.duplicatesCleaned;
  document.getElementById('optRedundancyCount').textContent = optResult.redundanciesCleaned;
  
  const statusEl = document.getElementById('optHealthStatus');
  if (optResult.issues.length === 0) {
    statusEl.textContent = 'OPTIMIZED';
    statusEl.className = 'opt-stat-value healthy';
  } else {
    statusEl.textContent = `${optResult.issues.length} ISSUES`;
    statusEl.className = 'opt-stat-value warning';
  }

  // Issue Lists
  const listContainer = document.getElementById('optimizationIssuesList');
  listContainer.innerHTML = '';

  if (optResult.issues.length === 0) {
    listContainer.innerHTML = `
      <div style="display:flex; flex-direction:column; align-items:center; justify-content:center; color: var(--text-muted); text-align:center; padding: 2rem;">
        <i data-lucide="sparkles" style="width:28px; height:28px; color: #10b981; margin-bottom: 0.5rem;"></i>
        <div style="font-weight: 600; color: var(--text-primary);">Config looks perfectly optimized!</div>
        <div style="font-size:0.75rem; margin-top:0.25rem;">No duplicate or redundant subdomains detected.</div>
      </div>
    `;
  } else {
    optResult.issues.forEach(issue => {
      const item = document.createElement('div');
      item.className = 'issue-item';
      
      const icon = issue.type === 'warning' ? 'alert-triangle' : 'info';
      
      item.innerHTML = `
        <div class="issue-icon ${issue.type}">
          <i data-lucide="${icon}"></i>
        </div>
        <div class="issue-details">
          <div class="issue-title">${issue.title}</div>
          <div class="issue-desc">${issue.desc}</div>
        </div>
      `;
      listContainer.appendChild(item);
    });
  }
  if (window.lucide) {
    window.lucide.createIcons();
  }
}

function optimizeAndBeautify() {
  const optResult = runOptimization(State.parsed, State.rawConfig);
  
  if (optResult.issues.length === 0) {
    showToast('🚀 Configuration is already optimized!');
    return;
  }

  State.rawConfig = optResult.optimizedText;
  
  // Sync raw text editor
  const textarea = document.getElementById('configEditor');
  textarea.value = State.rawConfig;
  
  // Re-parse
  State.parsed = parseConfig(State.rawConfig);
  updateLineNumbers();
  renderOverview();
  renderRulesTable();
  renderScriptsTab();
  renderOptimizer();

  showToast(`⚡ Cleaned ${optResult.duplicatesCleaned} duplicates & ${optResult.redundanciesCleaned} redundant rules!`);
}

// ------------------------------------------
// Utility Actions
// ------------------------------------------
function saveConfig() {
  // Save/Download file trigger
  const blob = new Blob([State.rawConfig], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  
  const a = document.createElement('a');
  a.href = url;
  
  // Extract custom file name from metadata
  const rulesetName = State.parsed.metadata.name.replace(/[^\w\s\-\_]/g, '').trim().replace(/\s+/g, '_');
  a.download = `${rulesetName || 'surge_rules'}.conf`;
  
  document.body.appendChild(a);
  a.click();
  
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  
  showToast('💾 Ruleset configuration saved successfully!');
}

function showToast(message) {
  let toast = document.getElementById('toastNotification');
  if (!toast) {
    toast = document.createElement('div');
    toast.id = 'toastNotification';
    toast.className = 'toast';
    document.body.appendChild(toast);
  }

  toast.innerHTML = `<i data-lucide="check-circle" style="color:#10b981; width:16px; height:16px;"></i> <span>${message}</span>`;
  toast.style.display = 'flex';

  if (window.lucide) {
    window.lucide.createIcons();
  }

  if (State.toastTimer) {
    clearTimeout(State.toastTimer);
  }

  State.toastTimer = setTimeout(() => {
    toast.style.display = 'none';
  }, 3500);
}

// Initialize on window load
window.addEventListener('DOMContentLoaded', initApp);
