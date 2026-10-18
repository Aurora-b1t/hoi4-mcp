# AGENTS.md — 驾驶 HOI4 MCP 的游玩规范

给驱动本 MCP Server 的 Agent(agent)看的行为手册。
你不是玩家本人,你通过工具对游戏窗口做「玩家等价」操作。

## 基本循环

1. **观察**:`hoi4_state()` 拿运行/暂停态与日期面板;`hoi4_hud('all')` 拿全窗+顶栏+日期。
   读数请把游戏暂停住(事件弹窗造成的自动暂停就顺势 利用)。
2. **决策**:依据截图读出的数字(顶栏从左到右:PP / 稳定度% / 战争支持度% / 人力 /
   军用工厂 / 资源 / 燃油% / 海军参数/外交信号计数)。
3. **操作**:`hoi4_click` + 截图反馈逐面板导航(菜单位置见 README 坐标表)。
   tooltip 拆解用 `hoi4_hover(x, y)`(移动不点击,回执截图读数)。
4. **复核**:每次写操作后必须再截图观察结果;把「点击→截图」当两个原语。

## 数据驱动的决策(离线优先,存档即真值)

- 排科研前:`hoi4_country_detail('latest', sections='research')` 的 `avail[]`
  就是按前置图推导的"现在能排的科技"(SP 门槛/隐藏/国别已滤)。
- 排国策前:`hoi4_country_detail('latest', sections='focus')` 的 `available[]`
  = 前置满足∩互斥未锁∩树归属 的"现在能选的国策"清单(带 cost/est_days/
  前置/GATED 标记);GATED 行带不可离线求值的触发器——选前在国策树 UI
  复核一眼再点。口径:国策时长 = cost×7 天(defines FOCUS_POINT_DAYS);
  无选中时进度字段 = 银行日(≤10,MAX_SAVED_FOCUS_PROGRESS),选中瞬间
  带入 → est_days 已扣银行(例:cost5=35 天存 10 天银行 → 25 天)。

## 纪律

- **暂停中再动手**:任何多步 UI 导航先确认暂停,防止画面在操作间隙变化。
- **暂停切换后立即复核**:每次 `hoi4_pause_toggle`/调速后马上 `hoi4_state()`/
  截图确认 icon 已翻面;未确认状态前不要离开会话(19 日事故:toggle 后离开,
  游戏在后头跑了 5 个游戏月,PP 289→835)。
- **不要连发点击**:单次 `hoi4_click` 后等截图稳定(~1s),再判定下一目标。
- **写后读**:存档/暂停/调速后总是回来 `hoi4_state()` 或截图复核;把「点击→截图」当两个原语。
- **事件弹窗是排队的**:自动暂停 → `hoi4_popup()` 拿证据 → 读文字 → 自己
  `hoi4_click` 点选项(读哪个点哪个) → 再查一轮;处理完一枚还会浮下一枚,
  直到 `hoi4_popup()` 显示干净地图为止。不要盲点几何,弹窗无通用关闭坐标。
- **写通道 v3 定位(参考 Clausewitz-MCP, 见 README 路线图 v2)**:主写路径 =
  命令注入(CSession::Post,玩家点击同一队列,CanExecute 照常生效);
  **UI 点击降为测试期用具**(联调/回退/frontend 动作:启动、装载存档)。
  inject 工具 = `hoi4_inject_status`(只读)+ `hoi4_inject_speed`(±1/±2)+
  `hoi4_inject_post`(单条:速度/暂停/SetNationalFocus)+ `hoi4_focus_ids`
  (只读, id↔名),写工具都过 _write_refusal 护栏;三条铁律:只调反汇编确认过
  签名的地址 / post 前查句柄类型(类型混淆=崩溃)/ 循环内不注入。
  - **22 日「平台级阻断」已作废(23 日定案)**:`GetProcessMitigationPolicy(
    UserShadowStack)` 返回的是 **4 字节** DWORD;当年按 8 字节读出的 0x100 被当成
    `SetContextIpValidation`,实际 **0x100 = bit 8 = CetDynamicApisOutOfProcOnly**,
    `SetContextIpValidation` 是 bit 2 且为 0(本机 SDK 10.0.22000 winnt.h + phnt
    bindings 一致)。victim 五原语矩阵 23 日重测**全绿**:graft
    (SetThreadContext)、CreateRemoteThread→私有 RWX、CRT→LoadLibraryW、
    QueueUserAPC、QueueUserAPC2 全部可用;公开资料亦无对应报告。
    **不要再引用"跨进程执行被内核封锁"这一说法**。
  - **主路径 = APC 写通道(write v3, 23 日真机闭环 ✓)**:`QueueUserAPC2` +
    `QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC` 把 139B 载荷投到**游戏自己的线程**;
    不挂起任何线程、不新建线程(新线程没有游戏的线程局部状态,这正是旧协议 B
    被 TLS 打死的原因)、载荷在该线程自己的 TLS 语境里跑,APC 返回后 ntdll 用
    NtContinue 恢复被打断的上下文原样续跑。载荷 = 原子 claim(单发单用,多余
    投递是空操作)→ 预取 post/queue/blob/count 进 callee-saved 寄存器(**首次
    调用后绝不重读 job**)→ 换槽位私有栈(~15.6KB)→ operator new + 拷 blob +
    Post(force=0)。实现 `hoi4_mcp/inject/apc.py` / `CommandLayer.send_apc()`;
    新工具 `hoi4_inject_post`(速度/暂停/SetNationalFocus)。
  - **23 日血案(必读)**:通道 v1 私有栈只有 3.8KB 且紧贴 job,真实 operator new
    的栈帧把 job 踩掉 → 载荷重读垃圾 → `call 0` → 游戏 BEX64 死亡。修法 = 槽位
    0x4000(栈顶 +0x3FF0)+ 寄存器预取 + `job_intact` 输入字段回读(为 False 时
    必须把该发当不可信)。**规矩:任何新载荷先在替身跑道
    (`research/apc_probe/apc_channel_dryrun.py`:假 new/post 记录全部参数、
    `--deep-stack` 模拟深栈调用链)全绿再上真机** —— 23 日跳过这一步的代价是一个
    游戏进程,而同一条替身跑道随后又抓到一个编码 bug(`mov rcx,r14` 编错)。
  - **focus id 映射(22 日交付,注入的前置)**:`hoi4_focus_ids()` 一次只读
    ~20s 重建 {数字id: 名字}(全库 10,668;GER 前缀 438);与
    `hoi4_country_detail(...,'focus')` 的 available[] 名字 join 得到
    SetNationalFocusCommand 的 focus_id 字段值(锚点:
    GER_the_four_year_plan=58138;german_focus 本局线 id 段 58116-58xxx)。
    `hoi4_inject_post(command='SetNationalFocus', focus='GER_...')` 可直接用名字;
    `DropCurrentNationalFocus` 只收 tag(内部用 `&tag`;25 日真机闭环 ✓)。
  - **VM 载荷三条定案(25 日;排"参数错位"类故障前必读)**:①**op 记录布局** =
    `[code, a0, a1, a2, a3, a4, RESULT, a5]` —— **a4 与 a5 之间夹着 RESULT**;
    `CALL` 读 `a2..a5 = rcx/rdx/r8/r9`,`ALLOC_CTOR` 读 `a2..a4 = rdx/r8/r9`
    且 `a5 = size<<40`;②**一次投递 = 一次 `_resolve_refs`**(`Script._resolved`
    会拒第二次):解析原地改操作数,跑两遍 page 加两遍、参数整体错位 —— 24 日
    "载荷读错操作数"的真因就是测试脚本手工解析一次、`run()` 又解析一次;
    ③**栈参数(5+ 参)不支持**:`Script.call` 直接拒绝第 5 个参数(载荷在私有栈上
    写 callee home space 在 VM 里必炸,而同一段独立 shellcode 全绿 —— NOTES 25 日
    "血案 4")。引用(Ref)的存储 = 生产者的 RESULT 字段;`read_ptr` 给的是局部
    缓冲区**绝对地址**(`ctor(..., rdx=&tag, ...)` 的 `&value` 形状)。
  - 执行验证口径:posted=True 只代表命令进了队列并被 take;`job_intact=True`
    才有资格谈"发得干净";**HUD 速度 pips 变化 = 执行证据**(23 日实测 4→5,
    shots/day23_speed_compare.png)。游戏自己拒绝时 Post 返回 0(实测:速度已在
    下限时 Decrease 被拒)——那是 CanExecute 活着的正面证据,不是失败。
    **存档 diff 是最强证据**(25 日:`focus.current` → null、`banked_days` 10 天回归、
    `n_completed` 不变,全程零 UI 点击)。
  - 暂停位免 UI 读法已上:`hoi4_inject_status` 的 paused 行 = idler+0x6C1,
    与 ‖/▶ 字形互为双证。
  读层同步换轨:live 内存读(毫秒级/不暂停)为时效关键路径(暂停态/日期/
  战斗 org/移动/弹窗)的目标读法;存档分析(~15-40s 且强制暂停)退居
  开发语料/偏移字典/对表真值/慢变量兜底。
- **回放前置校验**: `hoi4_replay` 会先拿录制起点帧和当前帧打分,diff>8 直接拒
  (面板布局变了)。看到 refused 不要 force——先把画面摆回录制时的状态;
  只有确认差异只是装饰性(横幅/天气)才 force=true。
- **调速**(`hoi4_set_speed`)是尽力而为:1 档走时约 1 小时/秒量级左右,用
  两次日期读数校准;低档下小时跳变稀疏,像素投票捕不齐,以 icon 分类为准。

## 状态语义

- `state=running` / `paused`:**状态字形分类(‖/▶ 列轮廓)的结论**;像素投票只作
  参考证据(横幅动画会让暂停面也在"动",窗口缩放也会让旧数字带失效)。
  结论相左时以你看到的回执截图里的 ‖/▶ 图标为准。
- `hoi4_save()` 预填文件名 `GER_<游戏日期>`;返回新建 `.hoi4` 文件即成功证据。
  注意:**运行中游戏每月 1 日自动落 autosave.hoi4**(19 日实证),'latest'
  不一定是你刚才存的那份——装载前先 `hoi4_saves()` 对日子。
- **存档即快照**:`hoi4_saves()` / `hoi4-selftest save-info` 可离线读出任何一个
  `.hoi4` 的玩家国/意识形态/难度/**精确日期**(译码见 saveparse.saveinfo)。
  需要“当前局面”的可靠读数时:暂停 → `hoi4_save()` → 读新存档——零内存风险。
- `hoi4_date()`(内存 CGameDate 簇)是**候选证据**,不是单值真值:暂停时活钟家族
  同值,但静态默认/计划日期会把簇挤乱;最终裁决用日期面板截图。
- **人力/兵役口径(17-19 日定案)**:悬停顶栏人力图标 (0.300, 0.024) 读
  「可用核心人口(X M)中的 N%」——它就等于 save `manpower.ratio`/1e5;
  兵役法名义值同框显示(如「有限征兵 2.50%」),修正国两者会出现差异。

## 安全层(19 日上线)

- **写层护栏**:8 个写工具(暂停/调速/点击/存/装/关/录制/回放)全部经过
  `_write_refusal()`:①`HOI4_READ_ONLY=1` 一律拒;②三源守卫判 detects 多人
  (game.log `[[ Launching MULTIPLAYER-game ]]`、hoi4.exe 活跃 TCP、存档
  `multiplayer` token) → 拒;`HOI4_ALLOW_MP=1` 是开发者显式豁免。
- 遇到 `refused: ...` 返回时:看理由,不要重试写工具;读工具不受影响。
- 随时可用 `hoi4-selftest guard` 离线+live 复查守卫结论。

## 已知操作故障模式(别慌)

- 空 absSend(键盘)会被游戏吞掉 → 永远用 `hoi4_click`,不要指望打字。
- **横幅动画乱真**:通知 toast 会滑进日期面板后方持续播放(暂停时也动)——
  这就是旧像素投票误报的根源;状态判定看 ‖/▶ 字形和回执截图,别看"面板动没动"。
- **截图右侧黑带 = 游戏客户端越出屏幕**:此时像素投票恒报 paused、死区点击
  全部无效。SessionDriver 初始化会自动 `ensure_onscreen` 把窗口移回屏内
  (OS 级拖窗,不碰游戏);若仍见黑带,先解决窗口位置再操作。
- **窗口尺寸变了坐标表就可能漂**(19 日:1295x837 小窗→1920x1200 无边框,
  日期数字带失效一次):开工先抓一张 full 截图核对再引用坐标。
- `hoi4_state` 结果为 unknown 时不是坏了:字形模糊(被遮挡/布局变化)就这样回,
  按 AGENTS 纪律以截图人工裁决。
- 游戏重启后 MCP 工具自动重连;若报 `expected exactly one hoi4.exe`,看是不是
  你手动开了两个实例。
- **主菜单既不吃外点也不吃 ESC**:只能点它自带的『关闭』
  (`hoi4_dismiss('menu')`;坐标 0.502, 0.660)。紧张度/情报类面板才吃
  `hoi4_dismiss('outside')`(点大西洋空海,不选师)。
- **地区/省面板**(点地图省名弹出)在自己的标题栏右上角有 X
  (`0.335, 0.205`),不阻塞主地图、一般无需关;同一面板换省 = 再点地图省份。

## 存档驱动的读层(推荐主路径)

`hoi4_country_detail(save_name='latest', tag, sections)` 一键离线读出:
pol(PP/稳定度/战争支持度/政党支持率/国策 idea 清单) / research(已完成科技
level+完成日、在研科技及 points、**avail=可研清单**) / prod(军民生产线: 装备名/工厂/数量) /
res(oil/alu/tungsten/steel/chromium/coal) / units(师 id/模板名/位置/org/强度/
经验/人力) / diplo(态度+好感) / decisions(生效中的决议!) / focus(当前国策
+进度) / fuel(燃油/最大/增益) / mp(兵源) /
**construction(建造队列: 建筑/州/进度/工厂数; 空队列=无此区块)** /
**chars(现任领袖/顾问/将领/科学家点名)** /
**theatres(战区→师 id 句柄 + 前线; 师详情用 units 区块按 id join)**。
数字与游戏 UI 直接对表:PP=289.16↔UI 289、政党支持率和恒为 100、MeFo 决议
恰好是开局自带的那条。**存档即真值,零内存风险**。

读数口径须知(17-18 日定案):
- 稳定度/战争支持度是**基础值**;UI 顶栏 = 基础 + 修正合成
  (GER 70% 基础 → UI 81% = 70+执政党支持率6%+帝国议会5%)。对表时别慌。
- 在研科技: invested_days = points/points_factor;剩余天数粗估
  (cost×110 − points)/points_factor(超前惩罚科技 factor 会 <1)。
- **research.avail** = 按存档日期+前置图推导的"现在就能排"的科技(已滤掉
  特殊项目门槛/隐藏/他国专属);排序 = 无超前惩罚优先→新年份→低耗时;
  est_days = cost×110/空槽位 factor(纯国家加成)。排科研从这里挑,
  剩余天数以 UI 面板为准。
- **theatres.units 的 id 就是 units.divisions 的师 id**(双档实证全重叠);
  军显示名("1. Armee")不序列化,别去找。**军队编组整个都不在存档里**
  (20 日定案,全档无 army 级序列化体);师个体名 = 模板名+序号,
  units 区块已重建(如 "1. Panzer-Division"),师→战区归属看 theatres。
- manpower.ratio/1e5 = 实际可征召人口%(含国家修正,非兵役法名义值);
  兵役法名义看 pol.ideas 里的 *_conscription。
- prod 的装备名(archetype)、units 的师模板名、chars 的角色名都是
  存档内 join 出的真名,可直接对 UI;chars 首次构建约 1 分钟。
- focus.available[] 见「数据驱动的决策」;GATED 行的含义见该节。

## 装载存档(hoi4_load)

- `hoi4_load('latest')` 一步到位:☰→载入→选行(mtime 倒序=hoi4_saves 同序)→
  『载入游戏』;**装载会丢弃当前会话进度**,未存档先 `hoi4_save()`。
- 保险流程:先 `confirm=false`(选行即停)看『selected』截图——高亮行+悬停
  详情框直接给出**文件名/日期/多人游戏=否**,核对后再 `confirm=true` 全程。
- 载入完成后核对 after_load 截图的日期面板 = 存档头日期(工具会一并返回
  expected)。选错行时『返回』在 (0.449, 0.810)。

## 演示目标(验收剧本, 供参考)

新开德国 1936 档:暂停读数 → 选一个国策(点国策树图标 → 点击目标节点)→
排一个科研 → 存档。这一套通了,v1 的「agent 全闭环」验收就成立。
已达成(15-16 日):`hoi4_world_state`/`hoi4_country_detail` = 存档闭环读层;
全链路(live 暂停→菜单→存档→离线解析)反复实测 ✓。
17 日追加:建造面板(0.331)选军用工厂→点地图州排队→存档→离线读回
`construction: queue[1]: arms_factory@s68 fac=15` ✓;
科研面板(0.19-0.227)直接读剩余天数(113日)与 +16% 速度 ✓;
政治面板从**顶栏稳定度图标 (0.155,0.024)** 进(第二排没有政治!)。
18 日追加:`hoi4_load('latest')` 全链路 ×2 ✓;research.avail 可研清单 +
theatres 战区指挥链上线(离线双档回归);窗口出屏自动归位(ensure_onscreen)。
19 日追加:安全层(守卫+只读屏障)上线 ✓;icon_state 字形检测器取代像素投票 ✓;
录制回放 hoi4_record/hoi4_replay E2E ✓;manpower.ratio UI 对表 ✓;
事件弹窗两类实弹标定(条约类/通知类几何,见 README 坐标表)+ 命令队列
日志(posted/sent/received/executed_commands.log)发现,反汇编从日志文本入手。
20 日追加:**focus.available[] 可用国策清单**上线(前置图+互斥+树归属过滤,
GER/SOV 双档回归 ✓);**hoi4_hover** tooltip 悬停原语(live:人力 tooltip
66.25M 中的 2.50% ↔ ratio ✓);hoi4_replay **起点帧校验**(拒绝/放行/force
三路径 live ✓);hoi4_popup(recall=N) 复读旧证据 ✓;tools 面板 17→**18**;
pytest 回归套件 24 用例全绿(存档层第一次有自动化回归网);
军队编组定案「不在存档」;修 bin5._value 窗口末溢出 bug。
21 日追加:**inject 写层首战闭环**——CSession::Post 玩家同通道真机打穿(速度
命令 CIncreaseGameSpeedCommand posted→执行→HUD pips 1→2 可视化验证 ✓);
静态表落盘 inject/tables.py(Post=0x2250B00/new=0x21C9AF0/队列=[CGameApp+0x380]/
全局槽位 G_GAMESTATE=0x332F260/玩家 tag=gamestate+0x520;类名实为
CCurrentGameState);调用原语 inject/call.py(主线程劫持协议=RIP∈镜像白名单+
rearm,新线程协议被游戏私 TLS 封死);同会话第 2+ 注入概率性崩游戏为首要
未决项(一令一会话纪律先行);tools 18→**20**(+inject_status/inject_speed,
都过 _write_refusal);pytest 24→**30**(inject tables 静态验证 6 用例)。
游戏进程死过 3 次(字节级案例全记录 NOTES.md 21 日),GER 主档完好零损失。
22 日追加:平台级阻断定案(10-14 KB → SetContextIpValidation 系统级启用,
victim 全矩阵实锤,写层转入自启动豁免路线)+ **focus id↔名映射闭环**
(live 10,668/10,668,GER 438,存档 join ✓;+`hoi4_focus_ids`,tools 20→
**21**);racy 扫描器(GetThreadTimes 增量+双 RIP 采样)落层备用;
pytest 30→**36** 全绿。游戏进程今天零死亡(全程只读或替身实验)。
23 日追加:**22 日「平台级阻断」作废**(0x100 是 bit 8 = CetDynamicApisOutOfProcOnly,
SetContextIpValidation 是 bit 2 且为 0;victim 五原语矩阵 graft/CRT/LoadLibrary/
APC/APC2 **全绿**)+ **APC 写通道真机闭环**:QueueUserAPC2 special APC → 游戏自己
的线程里跑 operator new + 拷 blob + Post,**HUD 速度 pips 4→5 视觉复核 ✓**
(latency 14-190ms, 连发 6 次全绿, job_intact 三振出局)。首战因通道 v1 私有栈
只有 3.8KB 且紧贴 job,被真实 operator new 的栈帧踩坏 → 载荷重读垃圾 → `call 0`
→ 游戏 BEX64 死亡(替身 `--deep-stack` 原样复现;修复=槽位 0x4000 布局 + 首次
调用前把参数预取进 callee-saved 寄存器 + job 输入字段回读)。tools 21→**22**
(+`hoi4_inject_post`, 支持 SetNationalFocus 名字解析);pytest 36→**54** 全绿。
**新纪律:任何新载荷必须先在替身跑道全绿再上真机**(23 日跳过这步的代价是一个
游戏进程,同一条跑道随后又抓到一个编码 bug)。
