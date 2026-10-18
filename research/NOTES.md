# Windows 逆向研究笔记 (HOI4 1.19.3.0, Operation Postern, checksum 5632)

## 已确认事实

### PE/RTTI
- hoi4.exe 55.8MB，MSVC x64，/GR RTTI 完整保留。
- 静态扫描产出: 18316 类 / 15316 COL / 10390 vftable（tables/generated/rtti.json）。
- 运行时实例定位（vftable 指针扫描，protect 掩码 0xFF 后取 0x04/0x08 页）已验证可用。

### 运行时基线（主菜单，1936 数据预载后）
- country=440, focus_progress=440, focus_tree=67, idea=11642,
  province=26826(≈13414×2 顾及双 vftable), state=2162, unit_leader=873,
  army/war/front/game_state=0
- 进入会话后（德国 1936 新局, 暂停）:
  air_wing=458, army=4872, front=1267, ship=2712, province=26826, state=2162
- CGameApplication/CGameGraphics/CGameGui/CGamePlaySettings/CGameIdler 各 1 实例。
- **CGameState 的 vftable (0x27210e0/0x2721138) 在运行内存里 0 命中** → 会话世界根对象
  或为非多态容器 / 或用其它类承载。改用「语义锚定」路线（用已知值定位，见下）。
- 军 division 对象无独立 RTTI（非虚拟类），预计从 CArmy 内部容器按 id 遍历。
- CCountry 数组连续排布（同 prob 440 个，stride ~0x1710~0x1990 可从相邻实例间隔推断）。

### 玩家命令体系（写层的钥匙）
- 369 个 `C*Command` 具体命令类 + `CCommandHelper<T>` 模板实例。
  例: CSetNationalFocusCommand, CSelectDecisionCommand, CSetResearchCommand,
  CAddPlayerCommand/CRemovePlayerCommand, CMoveCommand, CMassMoveCommand,
  CMergeArmiesCommand, CWithdrawArmyHqCommand, CDiplomaticActionCommand(外交通用),
  CReplaceIdeaCommand(法案/ideas), CSetProductionLineCommand, CRemoveProductionLineCommand、
  CRemoveConstructionCommand, CReplaceBuildingCommand, CSetGameSpeedCommand,
  CIncreaseGameSpeedCommand, CStartGameCommand, CPostHotJoinCommand…
- 完整清单: research/commands.txt。命令对象在游戏进程内构造并投递（参考项目走
  CCommandQueue::Post；Windows 版未见同名类，需从 CCommandHelper<T>/析构函数入手定位投递点）。

### 存档格式
- 现代存档为 "HOI4bin5" 二进制 token 流（字符串全量存储+4 字节回引偏移复用），
  44-55MB 一份。含完整世界快照，可作读层的 id/value 对照语料与兜底读端。
- 用户 17 个存档全部为 1.19.0.1 保存，**1.19.3.0 标记无法载入**(版本不兼容)。
- continue_game.json 指向 PRC_2026 存档，加载直接 CTD（repository 已知: 别点"继续游戏"）。

### GUI/输入
- PrintWindow 截图对 HOI4 DX11 恒黑; mss(DWM 合成) 可用。
- SendInput 归一化到窗口坐标可用；游戏读原始输入路径。
- settings.txt: fullScreen=no borderless=yes(size 1920x1200) 抓屏/点击最稳。
- 菜单路径已手过一遍: 主菜单(单人游戏@0.494,0.219) → 开始游戏(0.494,0.369) →
  载入游戏(0.494,0.417) → 选国家界面(有趣的国家@0.146,0.066;
  德意志国 人口 portrayal@0.335,0.380; 选择国家@0.5757,0.9152; 开始@0.876,0.942)。

## 下一步
1. 语义锚定: 游戏暂停态 date=1936.01.01.12 → 在内存找 CGameDate/编码后的日期地址;
   空格恢复 1 小时后 diff → 锁定活跃 date 对象 → 回溯宿主对象 → 世界根。
2. CCountry 数组基址持有者 → 主数据库类; CCountry 字段偏移与存档语料对齐。
3. 命令投递点: 反汇编 CAddPlayerCommand/CSetNationalFocusCommand 的虚函数与
   CCommandHelper<T> 的工厂函数, 找全局队列对象与 Post 调用约定。
4. 表生成: offsets.json/commands.json/handles.json + 版本锁。

## 后续进展 (10-15 下午)

### 指令反汇编 v1
- CSetNationalFocusCommand vtable @ RVA 0x2996458:
  vfn[0] = dtor (call 0x24c4410, jmp 0x24c3a20)
  vfn[1] = 序列化/记录函数: `mov edx,0x1f3` → **0x1F3 = SetNationalFocus 的命令类型 ID**
           读取命令体字段 +0x1C(qword), +0xC(dword), +0x16(u16), +0x18(u8), +0x20(dword)
           打包后 call 0x24c2e20 (带日志辅助, 非队列本体)
           尾部 call qword ptr [rax+0xb0] (可能是记录回调)
- 0x24c2e20: 依赖 0x1e2360(字符串绑定?) + 0x24bfbb0(printf-like) + jmp [rax+8]:
  是日志/kind-description 层, 不是命令队列。
- 结论: 真正的投递函数仍需定位; 换道用「UI 点击即可投放全部命令」的兜底优先写层
  （所有命令都能从屏幕操作发起, 与"像玩家"一致）。注入 Post 继续作为增强攻坚。

### 存档 bin5 解析
- rakaly/jomini lexer token 表 (u16 LE, 位置 magic 'HOI4bin5' 后):
  0x0001 '=' | 0x0003 '{' | 0x0004 '}' | 0x000C i32 | 0x000D f32 | 0x000E bool(!=0) |
  0x000F 带引号串(u16 len) | 0x0014 u32 | 0x0017 无引号串 | 0x0167 f64 | 0x029C u64 | 0x0317 i64
- 无 0x7xCF 等; 未见 0x29C77F8 = U64 opcode 误读假设已被否 (它就是个数值)。
- 解析器已能正确读 PRC 存档头(communist/very_easy/Aurora/"Operation Postern v1.19.2.0.a729"等)。
- 用户存档全是 mod 剧本(如 The Fire Rises), 非 vanilla; 读取逻辑不受影响。

### 锚定收敛
- CGameState vftable 运行时 0 命中已复核(会话中也是 0): 会话世界根为非多态容器。
- 判定: 走「实例+字段带」语义状态图: 直接对 CCountry/CProvince/CArmy/CCountry 军队等
  多态实例建索引, 字段偏移通过存档值域比对 + 指针结构推断; 不再强求唯一世界根。
- CGameDate 拷贝不追踪实时时钟(它在 +8/+32 无小时步进), 时钟另行 diff 定位(优先级降)。

## 15 日晚进展 (读层攻坚日)

### 基础设施修复
- 截图三连修好: (1) PrintWindow 对 DX11 恒黑已确认, mss 兜底抓屏;
  (2) **DPI 坐标错位**是此前截区污染的原因 → screenshot.py 已加
  SetProcessDpiAwarenessContext(-4), 客户区现在按物理像素 1942x1256 呈现;
  (3) _topmost 上下文临时置顶抓屏(不抢焦点, SWP_NOACTIVATE)。
- 日期面板(顶栏右侧)按钮归一化坐标: 调速- (0.758, 0.059), 暂停/继续 (0.775, 0.059),
  调速+ (0.898, 0.059)。点击有效(实测暂停↔继续切换成功)。
- **SendInput 键盘(空格)不生效**: 游戏虽是前台, 键被(疑似 IME)吞掉; 鼠标点击路线可靠。
- 边窗小窗显示: 游戏当前处于 1295x837 逻辑(1920x1200 边窗设置 changed?)窗口化小窗。

### 时钟/日期攻坚(未破, 已搁置)
- CGameDate 实例 +8 = packed u64 (0x029C77F8 为暂停时主导值, 358k/400k),
  +16 恒指向静态 RVA 0x27183D8(全实例同值), +32 是 +8 的孪生。
- 0x029C9A30 - 0x029C77F8 = 0x2238 = 8760 = 365*24 → 疑似小时线性编码;
  但: ①主导值在游戏暂停→恢复→推进多天后**不变**(缓存副本, 非活时钟);
  ②对 [V0-0x4000, V0+0x20000] 带的 u64 全内存 diff 20 游戏小时零变动;
  ③u32 带宽窗 [0x2100000,0x3200000] diff 也没小时级小差值;
  ④id 0x039F1D4B(存档里 game_version 邻近处)同属 0x29C/0x39F 家族。
- 结论: 活时钟对象不落在这些打包值副本里; wait_for 日期先用 UI 读法
  (AP 顶栏日期文本可从截图读出), 内存时钟继续搁置。
- whom_holds 反追: 81000 → SSubUnitStats(师统计), 810 → 杂; 稳定度/战争支持度
  未在 CCountry 本体 0x2000 带以 u32/f32 位型出现 → 字段在卫星子对象里。

### CCountry 实战数据(游戏运行会话内实测)
- 440 个 CCountry 实例; 主导步长 0x1710(410 处), 少量 0x4530(两个 0x1710 缺口)与大间隔
  → 实例数组按簇分布, 排序后相邻差 0x1710 的连续块可拼出主体; 抽样指针带无 'GER\0'。
- CCountry 指针带 0x800 内大量「每国一台」卫星对象: CScientistRecruitmentPool(+32/+8),
  CNuke(+16), CCountryCharacters(+8), CCountryOccupationStatus(+8),
  CCountryReportsManager(+8), CCountryAI/CStrategicAI/CCryptology(+8)…
- 'G\0E\0R\0' 命中均为文件名字符串池里的 "GER_1936_naval_mtg.txt.txt"(AI 海军脚本),
  非国别标签; 国别标签疑似单独的 CDbCountry/CCountryTag 结构。

### 存档 bin5 格式实锤(重要, 离线可解析)
- 魔数实为 **'HOI4bin5\*' 9 字节**(带星号), 随后即 token 流, 全小端:
  id u16 | EQUAL(0x0001) | 值 token; 字符串值 = QUOTED(0x000F)/UNQUOTED(0x0017) + u16 len + utf8。
- 首段语义: T012A="ITA" / T2E3E="fascism" / T299F="very_easy" /
  T00EE="Case Green v1.18.2.0.41f5 (b781)" (mod 名) / 嵌套 { "ITA" = { "Aurora" = {…} } }。
- 文件尾无内嵌 token 字典; FNV1a/CRC 恒等式均不匹配 id → **id→name 表在进程内存**,
  尚未定位(旧 token_table.py 只抓到了 C 运行库名表, 待重做)。
- 已有 saveparse/bin5.py 语法层 Reader 可用, 需加「id 表接入」才能出语义树。

### 决策
- 读层 v1 三条腿: ①顶栏/面板截图裁块(AP 可直接读数) 已实现; ②内存实例索引已具备
  (rtti.json + instances.py, 已验数: 会话 army=4884/front=1267/country=440 等);
  ③存档 bin5 语义解析(待 token 表)。
- 写层走 UI 点击(玩家等价)为主, CCommandQueue::Post 注入继续作攻坚项(下次)。
- 会话内 UI: 暂停/速度/存档 已打通(菜单坐标), 待封装进 MCP 工具。

## 15 日收官
- mcp_server.py 重写, 8 工具全部注册并冒烟通过:
  hoi4_game_info / hoi4_instances(实测 ~60s, 全部名字直查 by_name) /
  hoi4_hud(full|topbar|date|small) / hoi4_state(日期区 4 帧多数投票, 送截图回执) /
  hoi4_pause_toggle / hoi4_set_speed / hoi4_click(通用点击) / hoi4_save。
- E2E 实测成绩: 暂停↔继续往返多次成功; 存档两连: GER_1936_02_25_08.hoi4 &
  GER_1936_02_25_16.hoi4 (38-39MB, 新 vanilla 德国档, 供 token 表研究语料)。
- 误报根因定性: 通知横幅动画进日期区像素 diff → 多数投票后仍误报的场景以
  回执截图为准; 工具返回的 datepanel 路径 = agent 复核证据。
- 文档: README.md(工具面+坐标表+架构)、AGENTS.md(游玩规范)、zcode-mcp.json(接线)。
- pyproject: +mss 依赖; +hoi4-server 入口。
- 游戏留在暂停态收工。

## 下次顺手清单
1. bin5 token 表: 进程内存里定位 id→text 注册表(优先), 或比较两次存档流推断;
   PRC_2026 / GER_1936_02_2x 存档可做解析验收语料。
2. CCountry 字段带: 先存档-内存双源对齐(存档里 PP per country 顺序 ↔ CCountry
   数组顺序), 再用帽日值域对比钉字段。
3. CCommandQueue::Post: 反汇编 CAddPlayerCommand/CCommandHelper<T>::Create 工厂,
   全局队列对象; Plan A 注入原型。
4. 待办杂项: hoi4_load(按存档名列表点击), 事件弹窗通用关闭器, 决心/科研面板坐标表。

## 15 日晚·二番战 (bin5 破解日)

### ★ 存档 token 表完全破解 (游戏夜最大收获)
- **id→name 注册表就在 exe 镜像里, 但不在任何 section**: 运行时实例带
  vftable 指针 0x27183a8/0x27183d8 — **0x27183a8/0x27183d8 = CGameDate 的两个
  vftable (rtti.json 可查证)**! 即所谓「缓存副本」的那批 CGameDate 对象
  (`{vfptr, u64日期, vfptr_2}` 24 字节) 就是**活时钟**。
- 旧 token_table.py 的 "指针数组" 方案抓到的是 C 运行库函数名表(wrong table)。
- 磁盘版失败: 表在 .data VirtualSize 之外的镜像空洞, 只有运行中的进程才有
  → tokens.py 必须走运行时读取(Game attach), 落盘 tokens.json 固定下来。
- 提取器: sentinel 值(0x7ff7699c5170) 连锁(步长 0x48) 定位 → 节点:
  +0x00 sentinel, +0x08 id(u64), +0x10 nameptr(短串内联自指, 长串指针出镜像),
  +0x18 u32=21|u32=len+1, +0x30 内联 name。
- 今日落盘: tables/generated/tokens.json = 10763 tokens (Python
  `-m hoi4_mcp.saveparse.tokens` 即提取, id→字符串名键值对)。

### ★ bin5 格式全解 (orz - 3 大坑一路踩平)
- 魔数真正 9 字节 `HOI4bin5\x2A`, 无压缩, 直接 token 流。
- 语句: `id = value | <prim> = value | <quoted> = value` — **原始键支持:
  数字/字符串直接作 key**(省份 id 527=`{...}`, 模板名='tank...'); 语句头部
  EQUAL 也可单独出现(匿名键); token: EQUAL=0x0001 OPEN=0x0003 CLOSE=0x0004。
- v1 稳定解析器契约(13s 全档 1.8M 语句, EOF+depth0): ①先消费 token 再取
  payload(peek-then-prim 是坑源) ②body 项单 prim; VALUES 位 prim-run 贪跑
  ③值槽末尾 non-prim token 也 consume (防死循环) ④`("id", t)` 残值归还。
- 待修(已知缺陷, 0.96% 键噪声大源): 字符串键歧义(串内容被当 id 读) →
  "prim-run 贪跑"与"原始键"语义冲突; 单 prim 值假设不可全推。后续用
  jomini 权威源(离线不可得)或小档双档对照重推 body 契约。
- research/bin5_probe.py(限额解析+错误定点+统计) & bin5_render.py
  (语义树渲染+双档差分) = 后续研究主力工具。

### ★ 日期编码破解 (saveinfo)
- `date_token = 60759359 + 自1936-01-01 00:00 游戏小时数` (HOI4 历法无闰年!)
- GER_02_25_08/16 → +8 差分自洽; ITA_1936_01_01_12 → offset 12 ✓;
- 27 档全量验证通过(含 PRC/The-Fire-Rises mod 档 2023/2026, TUR, SRI);
- saveinfo.py: read_header(16KB 快解)/summary/decode_date/encode_date。

### ★ 运行时日读针 (runtime_state.py)
- CGameDate 对象: {vfptr0x27183a8|0x27183d8, u64 packed_date, vfptr_2} 24 字节。
- 暂停时所有 live copies 同值(当前=HUD 一致 1936-03-02 7:00, 当时 8 份同步);
  运行中分散, 且**对象地址随游戏 tick 会被 reallocate → 缓存地址仅几小时有效**。
- 内容里有大量 scheduled/static 日期(1939-01-01 x4894 默认值, 计划日期群),
  单值真值不可得 → hoi4_date() 作证据罗列(count 簇列表), HUD 截图或新存档
  才是绝对真值; saveinfo 才是精确历史通道。
- 遗留: 找「运行中直接读活钟」的可靠偏移(如唯一独占 addr+8 值模式);

### MCP 层增补
- hoi4_saves(): 存档目录 → read_header 摘要列表(离线, 不碰游戏)。
- hoi4_date(): CGameDate 簇证据(运行时扫描 ~25s)。
- selftest: +token-scan(重建 tokens.json), +save-info <paths>。

### 游戏状态收工前状态
- 图标语义最终实证: **▶=运行中, ‖=暂停** (运行时时间走,暂停即冻结; 4s 双截图对比).
- 会话验证: 游戏 1936-03-02 后曾被留在运行态一路走到 1936-03-19 24:00,
  已点击暂停收工(‖, 双截图复核冻结)。
- CGameDate 对象地址在运行期会 realloc: 曾于暂停+运行两个相位均读到
  u64=日期token(0x039F0345 族), 但地址不稳定(几小时后失效) — 内存直读
  日期只能作"证据簇"工具, 真值走 HUD 截图或新存档。

## 下次清单 (更新)
1. bin5 深树: 权威 jomini 源引拿到后再推 body 契约; 或手写小悖论存档
   (GUI 造 2 差异存档连续 8h)做差分对标。
2. runtime_state: 求一个「无输入」的活钟定址(如 addr+8 值唯一独占 match
   HUD 校验); 或干脆走 saveinfo 从 hoi4_save 存档精确读当前值。
3. CCountry 字段带双源对齐(现在的强项: token 表全解, 同名 key 如
   stability/war_support 已可在存档里按国寻值)。
4. CCommandQueue::Post 反汇编攻坚。
5. hoi4_load 菜单点击路径封装/事件弹窗关闭器。

## 15 日晚·三番战 (bin5 v3 全解日 — 全档读写闭环达成 ★)

### ★ bin5 语法终极版 (bin5_lex3, research/)
v1 的"0.96% 键噪声"与"states 内部失步"全部归因于 **两个 token 长度错误**：
1. **F32 (0x000D) = 10 字节**：2B token + **8B 定点载荷** (高32位通常为0，
   低32位 = 原始整数；值按字段取 /1e5 (PP/stability/war_support 等 0..1 分数)
   或 /2^24 (政党支持率)。v1 按 6B 跳过会把后 4 字节当 id token -> 结构漂移，
   永久失步到文件尾。**"mipmap/vertexshader 垃圾"全部是漂移产物**。
2. 字符串无终结符 (4+ln)，与 v1 相同。曾怀疑 +2 尾巴，反证为误 (尾字节其实是
   *下一* token)。
全档验证：**opens==closes==964797, final_depth==0, p==N 精确字节级闭合**。

### ★ 结构扫描器 (research/bin5_scaffold.py)
一次性 walkthrough -> numpy 数组 (pos/kind/depth/span)，~5s 处理 39MB：
- `find_countries`: depth0 的 `countries = {`，匹配 close 得全 countries 体
  [0x78ab90, 0x23371f0) = 29MB。
- `country_anchors`: 浅层 QUOTED 大写 && '=' '{' 的键 -> 439 个国家锚点，
  配对 close => **每国独立体区间**(GER=444,094B, ENG=331,562B…)。无 dups。
- `statement_member_scan`: 给定 body 区间 -> 每个一级成员的 (prim|body)。
- `NAMES`(token 表) 反解键名 -> GER 一级成员 41 个全部有名。

### ★ 字段语义证实 (双档比对 + UI 校准)
- `political_power` raw=28,614,400/1e5=186.14 (02-25 存) ↔ 28,916,000/1e5
  =289.16 (03-31 存, 四年计划启动 -10 PP) — **PP scale = 1e5** ✓
- `stability` 70000/1e5=0.70, `war_support` 30000/1e5=0.30 ✓ (UI 显示百分比×100)
- 政党 `popularity` = /2^24 (0.2086/0.0596/0.2384)
- **focus** 子体 = { progress / current / paused } — current=国策 id 字符串
  (`GER_the_four_year_plan`)；progress 原始单位=1/100000 (10.0/35日)。

### ★ 读层新工具面 (hoi4_mcp/readstate/ + mcp_server `hoi4_world_state()`)
- `world_summary(path)` -> header(player/date/difficulty/version) + 439 国
- `top_lines()` -> 摘要文本 (player/date + majors/PP-first 40 国的
  PP/stab/wsup/slots/tree)
- MCP: `hoi4_world_state('latest')` 一键 — 暂停→存档→解析→读全部国家数字。

### ★ E2E 验收闭环 (GUI 全真实点击链实测)
状态机 drivable 位置表（1.19.3.0, 1920x1200 无边框 client）:
- 第二排按钮: 阵营~0.0852, 决议~0.1055, 情报~0.156, 科研~0.198-0.218
- 政治(国策入门) ~0.0749 顶部 tab『选择一个国策』-> 国策树;
  树内 branch tabs: 陆/空/海/经济/政策:史实/政策:谋逆; 节点双击出 detail;
  detail 的『开始』按钮约 (0.74, 0.243)。
- 科研面板槽位1 (0.205, 0.449) -> 科技图详情: 『研发』(0.775, 0.251)。
- **模态窗关闭 = 点击窗外** (紧张度面板等) — 面板内 "关闭" 按钮不响应，
  外点 y≈0.75 立刻关。ESC 无效。
实测链：暂停 -> 政治 -> 选择国策 -> 『四年计划』开始 ✓ -> 科研 →
MG08 机枪研发 ✓ → 菜单存档 `GER_1936_03_31_11.hoi4` ✓ →
world_state 读回: `focus.current='GER_the_four_year_plan' progress=10.0`,
PP 289.16 (both digits match the UI 289 & -10 cost) → **v1 验收剧本成立**.

### 遗留事项 (下次)
1. 把科技/production/resources/construction/diplomacy/units 等 body 逐个语义
   提取 (框架已具备: statement_member_scan 可递归 1-2 层)。
2. hoi4_world_state 里 country_detail 关闭 'NPC 2000PP' 过滤 (KAS/WIS 等)。
3. 事件弹窗通用关闭器 (当前用"外点"策略; 找摸出通用 X 坐标)。
4. polygraph: focus progress 单位 /1e5 与天数的互算 (46/3.5?) 待证。
5. CCommandQueue::Post 反汇编 (写层增强, 优先级降 — UI 点击链已可用)。

## 16 日·读层大丰收日 (country_sem v2 + 输入坐标框架修复)

### ★ statement_member_scan 丢成员 bug 修复 (关键)
- 国家体一级成员实为 72 个 (division_template_id ×6 重复); 旧扫描只拿到 41:
  **body 分支 `i = cl+1` 之后又 `i += 3`** — 对 body 值多跳 3 token,每吞掉
  body 后面的一个成员 (掉进 body 内层后被 depth 过滤为主线时还可能整段失步)。
- 修复后 GER 全成员在册: technology/resources/diplomacy/characters/theatres/
  logistics(244K!)/manpower/flags/country_reports/decision_status 等全部收复。
  world_summary/top_lines/country_detail 全部受益。

### ★ 0x0167 token 不是 IEEE double, 是 int64 定点 /1e6
- 燃油族字段 bytes = 8B int64 (如 GER fuel raw=10,340,362,255 → /1e6=10,340.36);
  按 f64 解会得到 5.1e-314 垃圾。
- 校准: 同国多存档斜率: (fuel 03-31 − 01-01)=601.7 单位/90.5 天 = 6.65/日
  = 油3 × fuel_gain_per_oil(2.2) ✓ 与 UI 增益 8.6 中扣掉出口/消耗自洽。
- 分工: 0x000D → /1e5 (PP/stab/军工 progress/政党支持率%); 0x0167 → /1e6。
- **政党 popularity = raw/1e5 直接是百分比** (ITA 两档求和恒=100.0; 旧笔记
  "/2^24 分数"同 raw 双解, 存文档按 % 走)。

### ★ 国家语义全映射实测 (GER_1936_03_31 → `readstate/country_sem.py`)
- pol: politics 体含 political_power(289.16)/ruling_party/elections/parties
  (popularity%)/ideas(法案+精神: sour_loser/partial_economic_mobilisation/
  limited_exports/limited_conscription = UI 一致)。
- research: technology.technologies 条目: **level 有 => 已完成** (level+date 完成日);
  **level 无 + research_points => 在研** (GER 'support_weapons' rp=34.8 =
  上午 E2E 点的 MG08); slots = 槽位族表 (used_saved_points/points_factor)。
- prod: production.military_lines[8]/naval_lines[13] — **每条线 = 一个重复键
  `military_lines` 体** (不是体里的成员!); 行内: 行id(T_000B 第二个)/变体id
  (equipment_variant_index → T_000B)/produced/active+requested factories/
  priority/amount(-1=无限)/speed/cost。stockpile = production.equipments 条目
  {T_000B:{T_000B:变体id,type},amount}。cic_bank/value。
- res: resources.{produced,imported,exported,to_export,base_export}
  → oil4/alu153/tungsten5/steel301/chromium5/coal278 (1.19.3 新增 **coal**!)。
- units: units 体重复 `division` 条目: sig(id)=T_000B 体, division_template_id
  → 模板id (443-445), location=省id, organisation/strength/experience/dig_in/
  army_manpower{...value} (9,000/师 标准师)。fleet 计数 = `fleet` 条目数,
  其 task_force 计数在体里; 顶层 num_ships=42 直接 prim ✓。
- diplo: diplomacy.active_relations: 每国 {attitude, cached_sum}(GER 对 ENG/
  SOV/FRA... attitude_hostile -10, 对自身 -100)。
- decisions: decision_status.active_timed_decision/{decision,days}+
  active_targeted_decision/{decision,target,days} — GER_mefo_bills_mission
  days=90 ✓ 开局自带!
- fuel: fuel_status.{fuel,max_fuel(定点1e6),fuel_gain,fuel_cost,
  fuel_gain_per_oil,remaining_hours,history[]}。
- mp: manpower.ratio=250000 (raw i32; 兵役法 2.5% ← /1e5 口径假说, 待定案);
  divisions_manpower 合计 269,600 = 30 师 × 9,000 ✓。

### ★ NPC '2000PP' 之谜破案 (PRC_2026 档)
- 那 ~1500-1739 PP 的一排国 (NMB/KNU/M23/…) 是 **真实积存 PP**:
  Fire-Rises mod 2023-2026 间 AI 民族国家长期不化 => PP 按天堆。
  非解析伪迹; top_lines 已按 major 优先排, 显示逻辑无需过滤器 — 结案。

### ★ 建造队列之谜 (未破, 主缺口)
- 全档 439 个 `construction` 键都在 **country_reports** 里且全零 (统计报告体);
  各国没有国家级 construction 队列体。排建造中的数据要么在 `states` 体
  (buildings/queue per state), 要么接收在 deployment/theatres — 下次攻。
  同类缺口: 在研科技只有 progress 点数, 没有匹配 UI 的"总成本/剩余天"。

### ★ 输入坐标框架矫正 (click↔capture 统一客户区, 关键修复)
- 病灶: Input._abs 用 **GetWindowRect(含标题栏/边框)** 而 capture 用客户区
  → y 偏 ~2.4%: 偶发点空、菜单按钮行内的 hover-only、地区面板 X 点不准。
- 修复: input.py `_game_window_rect` = GetClientRect+ClientToScreen;
  screenshot.capture_smart 的 mss 兜底也改抓客户区矩形。
- 回归实测 (live):
  - 日期面板按钮 y: 0.059 → **0.024** (x 不变 0.759/0.776/0.897) —
    三按钮 hover 高亮+点击过关: 暂停↔运行往返成功 (11:00→16:00 走了 5 游戏小时
    再回暂停)。
  - ☰ 主菜单 = (0.978, 0.024) 同行; 菜单内行: 载入 0.257/保存 0.30/关闭 0.660。
  - 存档对话框: 保存 = (0.560, 0.813) ✓ GER_1936_03_31_16.hoi4 落盘 38.3MB。
  - 全链路: live 暂停过 → 菜单 → 存档 → `hoi4_country_detail('latest')`
    读回与 UI 对表 ✓✓。
  - 维基浏览器误开事故: 一次点在 0.978,0.058 (旧拍) 开出 Paradox Wiki 内嵌
    浏览器; 其 X 在 (0.947, 0.163) 一点即关 ✓ (记录以防再误开)。
  - 地区/省面板 (点省份弹出): 不吃外点, 自带 X = **(0.335, 0.205)** ✓ 实测关闭;
    面板换目标 = 直接点目标省。
- 新工具: `hoi4_dismiss('menu'|'outside')` — menu=点主菜单自带关闭;
  outside=点大西洋空海 (0.030,0.900) 关"外点可关"类面板 (如紧张度)。
  事件弹窗仍需 agent 读截图选项后自行点 (options 语义)。

### 游戏收工前状态
- 游戏 PAUSED @ 16:00, 31 3月 1936 (存档 GER_1936_03_31_16 同日), 无遮挡面板。

### 下次清单
1. **建造队列** 存档位置 (states 体? deployment?) — 找到即可补 `hoi4_country`
   的 construction 区块; 验收法: live 里排一条基建 → 存档 diff。
2. 在研科技的总成本/剩余日 (科技本体定义可能在 exe 表或 common 光盘数据。
3. theatres(5.3K) / logistics(244K) / characters(官员) 三个大体的语义。
4. equipment 变体名: 全局 `equipments` (1.1MB) / `division_templates`
   (234K, 内含 name='步兵师1936B型') — 接入 country_sem 输出可读名字。
5. manpower.ratio (250000 raw) 与兵役法百分比的口径定案。

## 17 日·建造队列+命名+科研成本日 (读层 v1.5)

### ★ 建造队列破案 (最大缺口补上)
- **宿主 = 国家体 `production.general_lines`** (token 0x2fb2), 重复
  `building` 条目; **队列空时整个成员不序列化** — 这就是 GER(玩家从未排建)
  查无 construction 的原因; ENG(AI 在建) 88 国有 general_lines。
- 顶层全局体清点 (top_survey.py): 无独立 construction 体; states(1081 州,
  buildings 只存完成等级+血量 level/partial_health/healthy_levels) 也没有。
- 条目 schema (ENG 实测): `{T_000B={serial,type=59}, produced, active_factories,
  priority, amount, speed, cost, created_date, building={template=建筑名(内联串),
  location=州id}, allied_build}`。
  - cost=10800.0 ↔ common/buildings industrial_complex base_cost=10800 ✓
  - produced/cost = 进度 (ENG@0.441/0.006/未开工三连) ✓
  - speed = active_factories × 7.2 (基础产能×修正), 未开工条目无
    produced/active_factories/speed 字段
  - created_date: 60759372=1936-01-01 13:00(开局), 60761479=1936-03-29(AI 新排) ✓
- 检索法: 建筑类型名不在 token 表(内联字符串); str_hunt.py 按内容 hunt +
  path_to.py 求容器路径 (countries→production→general_lines→building)。

### ★ 装备/师模板命名 (global_tables.py, 全部 join 验证通过)
- 顶层 `equipments` (4505 条) = 每国每 archetype 的框架登记: 键=archetype 名
  (infantry_equipment_1...), id={serial,type}; **生产线/库存的
  equipment_variant_index {serial,type} 按同 id 精确 join 到 archetype** ✓
  (GER 8 军线+13 海线全解析)。
- 顶层 `division_templates` (727 条): {id, name='Infanterie-Division',
  country}; division.division_template_id 按 serial join → 师名 ✓。
- 自定义变体名: 国家 production.scheduled_equipment_variants
  {archetype={name='StuG III', upgrades, modules, industrial_organisation}},
  无 id — 按 archetype 提示 (GER 1 条: StuG III)。
- 读层 API: `Countries.tables()` → GlobalTables(frames/templates/chars)。

### ★ 科研成本 (techdata.py + sec_research 增强)
- common/technologies/*.txt 解析出 research_cost + start_year (TechDB)。
- **save 里 research_points = 研究天数等效 × points_factor**:
  invested_days = points/factor (factor 含国家加成+超前惩罚, ITA 1937 档
  infantry_weapons2(yr1938) factor=0.73 即超前惩罚实锤)。
  - GER: 34.8pts/1.16 = 30.0d = 开局 30 存量日 (BASE_RESEARCH_POINTS_SAVED=30) ✓
  - EME cost1.0: 01-01→04-05 完成 = 93.5d@1.16 → 总天数/成本常数 ≈ 100±10
    天/单位 (synth_oil 3.0 约 292d 佐证); **精确常数待 live UI 剩余天数对表**。
- defines 实锤: BASE_RESEARCH_POINTS_SAVED=30, BASE_YEAR_AHEAD_PENALTY_FACTOR=2。
- 同游戏日内 points 不变 (日粒度结算) — 03-31 11:00 与 16:00 档 points 相同 ✓。

### ★ manpower.ratio 口径定案 (跨国 439 国)
- ratio/1e5 = **实际可征召人口%** (= 兵役法% × 国家修正), 非法律名义值:
  USA disarmed(1%)→0.5, SOV volunteer(2.5%)→1.5, GER limited(5%)→2.5,
  ITA limited→2.5, FRA limited→1.65, CHI volunteer→0.33, extensive→5.0-5.75。
- 法律名义值看 ideas 里的兵役法 idea 名。UI 可征召% live 对表待验。

### ★ characters 区块 (chars)
- 国家 `characters` = character_status 列表: {character:{id,type=73},
  country_leader/advisor/unit_leader/scientist 布尔}; 角色可兼任。
- 顶层 `character_manager` = {historical: 10137, dynamic: 2408, next_character_id};
  character 条目 {id, token, **name**, country, gender, portraits,
  country_leaders/field_marshal/corps_commander/advisors/...} → id→name join ✓
  (GER: leader=GER_wilhelm_pieck, 70 顾问, 50 将领, 17 科学家)。
  注意: name 是存档 token 名非本地化显示名; 首次构建 ~70s (惰性)。
- theatres = {theatre: {area, unit[](军 id), front[]}} — 军/前线指挥链, v2;
  logistics = 每日历史日志体 (4KB/日), 低优。

### 读层 v1.5 交付物
- `readstate/global_tables.py`: find_top_body + GlobalTables
  (frames/templates/scheduled_variants/characters)。
- `readstate/techdata.py`: TechDB (common/technologies 解析,
  HOI4_INSTALL 自动识别)。
- `country_sem.py`: +construction 区块 (general_lines), +prod 的
  archetype/custom_variants, +units 的 template 名, +research 的
  cost_units/start_year/invested_days, +chars 区块; SECTIONS 注册表 12 项。
- selftest CLI: country-detail <path> [tags...] 参数修复。
- mcp_server hoi4_country_detail 文档同步。

### 待 live 验证清单 (今日下午)
1. 排一条建造 → 存档 → GER 新档出现 production.general_lines + 条目语义 ✓?
2. 科研面板剩余天数 ↔ invested_days → 总成本常数定案。
3. 人力面板可征召% ↔ ratio/1e5。
4. (顺手) 载入存档的菜单点击路径 = hoi4_load 的实现材料。

## 17 日·live 会话实录 (全链路终验 ★)

### ★ 建造队列 E2E 闭环 (验收成立)
live: 载入 GER_1936_03_31_16 → 建设面板 (锤砧图标 @0.331) → 选军用工厂
(工业建筑 2 号图标, tooltip 建造花费 7200 = base_cost ✓) → 点地图州排队
(15/15 工厂自动分配) → 菜单存档(覆盖确认框→OK) → 离线解析新档:
`construction: queue[1]: arms_factory@s68 queued fac=15` ✓✓
- produced=None(未起 tick) + active_factories=15 并存 — 字段按需出现。
- 存档前先 `_backup_GER_1936_03_31_16_pre_construction.hoi4` 备份。
- 覆盖确认框: 覆盖游戏存档 {取消(0.435,0.678) | OK(0.570,0.678)}。

### ★ 科研成本定案 (UI 对表)
科研面板 (0.19-0.227, 烧瓶): **MG08 式重机枪 = 113日 剩余**, 研究速度 +16%
= points_factor 1.16 ✓✓。points 模型自洽: 总点数 = 34.8 + 113×1.16 =
165.9 = cost 1.5 × ~110 点/单位 (1918 老科技含落后奖励~10%)。
投入 30d = 开局银行 30 点(×1.16=34.8pts) + 0 天(同日未滚动) ✓。
**经验公式: 剩余天数 ≈ (cost×110 − points)/points_factor; 超前惩罚
科技 (如 factor 0.73) 会再乘** — 够 agent 排期用, 精确系数以后再磨。

### ★ 稳定度/战争支持度 save↔UI 口径 (重要!)
顶栏悬停稳定度 tooltip: **基础值 70.00% + 执政党支持率 +6.00% (40%×0.15)
+ 帝国议会 +5.00% = 81%** → **save 存基础值, UI 是基础+修正合成**。
war_support 同理 (30 基础 → UI 35%)。country_sem 的 pol 输出=基础值,
读数时若要对表 UI 需加执政党支持率×0.15 等修正。PP 是累计制所以直接对表。

### ★ 顶栏语义补全
- `270 日` (绿箭头+油桶) = **燃油可用天数** (fuel/日耗, 10341/38≈270 ✓);
  `100%` = ?; `195` = 海军?; `73` = 军用工厂计数。
- 人力 1.33M ↔ save manpower 族 (可征召% 对表未完成, 悬停不支持, 下次用
  政治面板读)。

### ★ 面板坐标表 (1.19.3, 1920x1200 client, 实测)
- **政治面板 = 顶栏稳定度图标 (0.155, 0.024)** (不是第二排!) — 点开政治;
  稳定度 tooltip 即在其上悬停出现。
- 第二排: 阵营 0.089 | 决议 0.1205(左缘~0.105) | 情报 0.1615 |
  科研 0.19-0.227 | 国际市场 0.261 | **建造 0.331** | 生产? 0.361 |
  部署? 0.386 | 回收? 0.409 | 将领? 0.434 (y=0.095)。
- 建造放置: 选建筑图标(军用工厂=工业建筑行2列2 @0.383,0.355) → 点地图州;
  放置模式州徽会显示 1+1/6 之类; 队列行出现即成功。
- 主菜单 (0.28,0.024 也能开? ☰在0.978); 菜单行: 载入0.292/保存0.335/…/关闭0.660。

### ★ demo 存档异常观察 (记录在案)
- GER_1936_03_31_16: GER 拥有奥地利 (state 68 奥斯特马克, owner=GER,
  city), 工厂 73 军/37 民(建造面板 35+2), 政党 40/35/10/15,
  difficulty=very_easy, 存档头无 mod 标记, 游戏 checksum 5632(S)。
  15 日 demo 局的来历(可能 launcher playset 残留 mod 或演示期 AI 扩张)
  **不影响读层正确性** — 所有语义按值域/结构实证, 不依赖剧本假设。
- chars 领袖 bug 修复: country_leader=True 有 4 人(希特勒/阿登纳/
  Max Alt/皮克 = 意识形态继承人池), 取**体序第一个** = 现任领袖
  (UI 阿道夫·希特勒 ✓); 原实现被后者覆盖 → 已修 (out['leader'] is None guard)。

### 游戏收工状态
- 游戏 PAUSED @ 16:00 31 3月 1936, GER 有 1 条军工厂建造队列(s68)。
- 载入存档 UI 路径已走通: 主菜单→单人(0.498,0.196)→载入(0.498,0.387)→
  选档(0.115,0.393=列表首行)→开始(0.876,0.942) — hoi4_load 的实现材料齐。

## 18 日·读层 v2 收官日 (avail + theatres + hoi4_load ★)

### ★ 科研可研推导 (research.avail — TechDB leads_to 前置图)
- common/technologies/*.txt 补解析 `path = { leads_to_tech = X }` → 反向前置图:
  parents(T) = 所有 leads_to 指向 T 的科技; **T 可研 ⟺ 全部 parent ∈ done**
  (无入边 = 树根, 天然可研)。
- **存档科技键 = 精确 tier 名**: GER_03_31 done[55] 里 infantry_weapons 与
  infantry_weapons1 是两个独立条目(全 level=1)。level>1 (ENG artillery4 lv2、
  PLD infantry_weapons4 lv2) 是 mod 重复授权痕迹 → 按「键在即完成」处理,
  不做家族展开。
- **三类过滤 (v1 初版漏了前两类, 207→130)**:
  1. **特殊项目门槛** (Götterdämmerung): `is_special_project_tech = yes` 或
     allow 含 `is_special_project_completed` — 这类科技**没有 leads_to 入边**
     (supersonic_fighter1 由 sp_air_supersonic_jet 解锁), 会被误判成根科技;
  2. **隐藏科技**: `allow = { always = no }` (lotta_svard/elephantry/
     JAP_silver_wheels/camelry 等国民精神占位);
  3. **国别限定**: allow 里 `tag/original_tag = XXX` — 不匹配剔除
     (GER_heavy_armored_car 对 GER 正确保留)。
- 排序: ahead-of-time(0 优先) → start_year 倒序 → cost 升序;
  est_days = cost×110/factor_free, **factor_free = 空槽位的 points_factor**
  (纯国家加成; busy 槽的 factor 混入超前惩罚, 不能直接用)。
- 双档验证: GER_03_31 avail[130] 头排 improved_light_td/art/spaa、EME、
  cv_fighter1、improved_sonar 全 yr1936 合理; PRC_2026 avail[131]
  thermonuclear_bombs 打头(2026 无 ahead) ✓。学说(1.19 改 XP 里程碑制,
  common/doctrines)与科技树分离, 不在本区块。

### ★ theatres 区块 (师-战区-前线指挥链)
- 结构 (GER/PRC 双档验证): `country.theatres.theatre` = {id{serial,type=67},
  area(states-run), `unit`×N(**{serial,type=51} 句柄**), `front`×N(
  {serial,type=66}, area, provinces-run, enemies-run)}。
- **unit 句柄 serial == units.division 的师 id**: GER 30/30, PRC 109/109
  全重叠 — 战区→师归属由此 join。**军显示名 ("1. Armee") 不序列化**
  (全文 'Armee' 唯一命中是 FRA 角色名 Quartier General d'Armee)。
- 顶层 `unit_leader` 体只是一串 T_0003 裸 id (873 个), 无结构 — 以后要
  将领-军归属再攻。

### ★ hoi4_load (写层最后一块拼图, live E2E ×2 ✓)
- 游戏内 ☰ → 载入(0.502,0.257) → 载入对话框(全屏模态, 本地/云端 tab 默认本地)
  → 选行 → 『载入游戏』。
- **17 日坐标表两处误测, 18 日 live 重标**:
  1. 列表首行 = **(0.45, 0.382)**, 行距 **0.066**, 6 行全可见 — 旧表
     (0.115,0.393) 点在对话框外的地图上(幸而是无害空点);
  2. 确认按钮 = **『载入游戏』(0.567, 0.810)** (与存档框『保存』同位);
     旧表 (0.876,0.942) 是主菜单流程坐标, 对话框里点空。
  另: 返回钮 (0.449, 0.810)。
- **行序 = mtime 倒序** (实测与 hoi4_saves 完全一致); 悬停行出详情框
  (游戏存档文件名/日期/铁人/难度/**多人游戏:否**) — 选行后截图自带此框,
  就是现成的核对证据。
- 全链路: ☰→载入→row0→载入游戏 → 日期面板 ‖ 16:00 31 3月 1936 =
  GER_1936_03_31_16 头部日期 ✓✓ (先手动分步验, 再 confirm=True 一次全程)。
- confirm=false 半程模式: 选行即停, 供 agent 核对高亮行后再确认。

### ★ 窗口几何保护 (ensure_onscreen)
- 开工时发现窗口漂移到 (1110,177): 客户端右侧 ~470px 越出 2560 宽屏幕 →
  mss 截图右侧黑带、日期面板/☰ 全在屏外死区 — **像素投票恒报 paused
  (黑区零变化), 死区点击全部无效**。
- 修复: `screenshot.ensure_onscreen(hwnd)` — SetWindowPos 平移回虚拟屏内
  (OS 级窗口管理, 玩家拖窗等价, 不碰游戏状态); SessionDriver.__init__
  自动执行。本次测试中由用户手动移回, 工具兜底留给以后。
- 教训: 看到截图黑带先怀疑窗口位置, 不要信像素投票。

### 收工状态
- 游戏 PAUSED @ 16:00 31 3月 1936 (hoi4_load 二次复验后的原样会话)。
- 读层 v2 = 14 区块: pol/research(+avail)/prod/construction/res/units/diplo/
  decisions/focus/fuel/mp/chars/theatres。

### 下次清单
1. 多人检测 + read_only 屏障: 存档头/载入详情框已能读「多人游戏:否」;
   live 会话 MP 检测(进程/网络层)待做 — inject 类工具启用前必须先有。
2. 事件弹窗通用关闭器 (摸通用 X 坐标)。
3. 军级视角: theatres 无军名; UI 若需军组织, 挖 deployment 或 CArmy
   RTTI 实例遍历 (army≈4872 实例 = 每师一个? 有待定案)。
4. CCommandQueue::Post 反汇编 (写层增强, 优先级降 — UI 点击链已全覆盖)。
5. 会话录制回放 (点击序列 JSON)。

## 19 日·安全层 + 状态检测重写日 (MP 守卫 / read_only / 录制回放 / 弹窗实弹 ★)

### ★ 环境突变与新事实
- 游戏（同一进程）今日重启过: logs/ 全部 11:41 新建, game.log 明确
  `[[ Launching SINGLEPLAYER-game ]]` @ 11:44:14——game.log 的
  Launching 标记 = **live 会话类型的最权威证据源**（顺带发现
  posted/sent/received/executed_commands.log 四个命令队列日志, 与
  存里的命令日志 --> 对以后 CCommandQueue::Post 攻坚是绝佳参考）。
- 窗口变回 **1920x1200 无边框客户区**（16-18 日是 1295x837 小窗）。
  这暴露了 is_running 的大坑: 日期数字带 y0.048-0.078 是小窗时代的
  校准, 大窗下数字其实在 y≈0.015-0.035（按钮行 0.024 校准仍有效）。

### ★ is_running 重写: 状态字形分类器取代像素投票 (关键)
- 像素投票两连败: ①运行中恒报 paused（区域没抓到数字）②暂停时被
  **斜纹横幅动画**污染（一条条纹 toast 藏在日期文字后面持续滑动,
  暂停基线差分飙到 9-12）→ 日期带 diff 票选不可靠, 弃为主动判据。
- 新主判据: **‖/▶ 状态字形列轮廓分类** (`SessionDriver.icon_state`,
  patch 中心 (0.773, 0.022) 40x28):
  - ‖ = 两个分离短亮柱 (run 宽 ≤6, 两岛) → paused
  - ▶ = 一个连续楔形 (run 宽 ≥9, 向右单调收窄) → running
  - 两帧 0.6s 间隔投票需一致; 模糊 → undecidable/None
  - (收工前补充) 逐像素差分定位: 日期数字行 client y≈15-19 有**扫光效果
    常驻闪烁**(暂停时也动) → 像素投票带天生带噪声, 彻底降级为参考证据;
    警戒 mini-icons 行 y≥0.036 也常驻闪动, 投票带上缘收窄至 y<0.036。
    icon 双帧判读改『任一可判即可信』(横幅/悬停可能恰好吃掉一帧)。
  - patch 左缘 12 列是相邻按钮装饰(两态形状一致)直接丢弃
- live 验证: running ✓ → pause_toggle → paused ✓; 之后整场无事。
  `cast_timevote()` 保留下沉为证据文本; `cast_diffs()` = 图标+投票。
- 教训固化: 状态判定永远有双证据(icon + 回执截图), 投票只是参考。

### ★ 多人检测三源守卫 (safety.py, 新)
1. **game.log 尾部**最近一次 `[[ Launching MULTIPLAYER-game ]]` /
   `Launching SINGLEPLAYER-game` (frontend.cpp 打点, 零侵入,免费);
2. **iptable(GetExtendedTcpTable)**: hoi4.exe PID 名下 TCP 数
   (SP 观测 = 0; 曾瞬时出现过 1 条 CDN/遥测, 所以 tcp 只做证据不单独锁);
3. **存档 token `multiplayer` (0x3E74)**: 33/33 本地 SP 档整档无此键
   (raw 字节扫描 0 命中) → 有真值 = MP; 无键 = 非结论性, 与 ①联判。
- `GuardReport{log_launch,tcp_open,save_flag,verdict,reasons}`:
  log=multiplayer 或 save_flag=True → verdict=multiplayer;
  log=singleplayer(+save 无键) → singleplayer; 其余 unknown。
- ▸ 存疑留档: 无 MP 样本, `multiplayer` 键在 MP 档的取值/位置未经
  正向验证 (是 Jomini 惯例推断, 载入对话框"多人:是/否"可为终验)。

### ★ read_only / MP 写层门禁 (路线图#6 兑现一半)
- env: `HOI4_READ_ONLY=1` → 全部写工具直接拒;
  `HOI4_ALLOW_MP=1` → 开发者豁免(违反"仅单人"盟约时自己显式承担)。
- `_write_refusal()` 挂到全部 8 个写工具: pause_toggle/set_speed/
  click/save/load/dismiss/record('start')/replay——读工具不动。
- `hoi4_game_info` 现附 guard 行 + barriers 状态; selftest 新增
  `guard`、`replay-check` 子命令。函数级三路径测试通过(实测拒/放)。

### ★ 会话录制回放 (ui/recorder.py + hoi4_record/hoi4_replay)
- Input 层包装(幂等 attach, 原始方法存 `_rec_orig` 防双层包裹):
  click/right_click/wheel/key 全记 JSONL
  `{dt, kind, x?, y?, hold?, vk?, note?}` → ~/.hoi4_mcp/recordings/。
- Recorder.replay: 按 dt/speed 重放(driver.input), 末尾证据截图;
  replay-check 自检(步数/计划等待/无点击干跑)。
- **E2E live**: 录「暂停→运行→暂停往返」(2 clicks + 2 notes) →
  stop 落盘 → replay-check 输出计划(4 步, 7.1s) → live 回放 4/4 步
  → 终态 paused ✓。第一次录制时暴露的误报已随检测器重写消解。

### ★ manpower.ratio UI 终验 (17 日遗留关闭)
- 顶栏人力窗口悬停 **(0.300, 0.024)** (纯 input.move, 不点击):
  「可用核心人口（65.84M）中的 **2.50%**」↔ save `manpower.ratio`
  250000/1e5 = 2.50% ✓✓; 兵役法名义「有限征兵 2.50%」同框;
  陆军 269.60K ↔ divisions_manpower 269,600 ✓。GER 无国家修正时
  有效=名义, 修正国需看 ratio。**口径正式定案**。
- 顺手钉牢: 悬停 x 0.353 = 「工业」经济 tooltip(军工 20/28 等),
  0.32 空, 0.30 = 人力——顶栏图标列坐标可按此继续补。

### ★ 事件弹窗实弹标定 (下次清单#2 关大半)
- 现场来了两枚连环弹窗(排队逐个呈现, 都自动暂停):
  - **条约类(单钮)**: 亚的斯亚贝巴条约(埃塞被吞并): 盒
    x 0.316-0.685 / y 0.258-0.733, 单「好的」@(0.499, 0.685);
  - **通知类(双钮)**: 研究完成! MG08式重机枪(15日排的, 排队通知
    按序呈现): 盒 x 0.332-0.708 / y 0.306-0.606, 「详情」@
    (0.398, 0.577), 「好的」@(0.642, 0.577)。
- 几何随事件而变 → **通用 X 坐标不存在**, 定案为证据套件:
  `hoi4_popup()` = icon 复核 + full/date/box 三图, agent 读字后
  自己 hoi4_click 选项, 点完重查; 盲点选项=风险, 不做。
- game.log 不记暂停切换(log size delta=0), 暂停事件只能靠 UI 证据。
- 现场数据: 事件逐个排队, 处理完一个立刻浮下一个, 需循环读图。

### ★ 时钟事故 + 收工协议复盘 (纪律案例)
- 诊断暂停键时一次 toggle 后未复验就离开 → 游戏在后台跑到
  1936-09-19 (PP 289→835, 燃油 270→99日, 埃塞被吞并)。完整恢复了
  (弹窗清空 + 收工存档 GER_1936_09_19_06.hoi4, 头日期 1936-09-19 06
  与面板''对表 ✓)——教训: **toggle 后必须立即 icon 复核**, 未确认
  状态前不要离开会话(AGENTS 纪律强化条目, 见 AGENTS.md 更新)。
- 月度自动存档 autosave.hoi4 (1936-04-01 01) 在运行窗口自动落盘 →
  月度自动存档机制实证, hoi4_saves 应将 autosave 排进"最新"序列。

### 收工状态
- 游戏 PAUSED @ 6:00 19日 9月 1936, 无遮挡面板, 弹窗全清;
  存档 GER_1936_09_19_06 (latest) 为下次起点; guard=singleplayer。
- 工具面 14 → **17**: +hoi4_record / hoi4_replay / hoi4_popup;
  game_info 带 guard; state 用 icon 分类器(旧投票降为参考证据)。

### 下次清单
1. 军级视角(army 显示名仍缺): UI 部署面板/战区面板截图读法, 或
   CArmy 实例遍历; unit_leader 裸 id 串仍无结构。
2. 弹窗套件经验值扩充: 遇新事件类型再补几何(多钮堆叠/滚条);
   低价增强: hoi4_popup 加“读最近三张 shots”参数免重复抓屏。
3. CCommandQueue::Post 反汇编——四条命令日志已找到, 从
   posted_commands.log 的非空样本反推命令文本格式再入内层。
4. warm-start: tokens/rtti 表如果游戏升级需重扫(token-scan)。
5. 会话录制回放 v2: 录制时带状态复核注记(可选), replay 前置
   "起点状态校验"(录制首页截图与当前帧 diff < 阈值才放行)。

## 20 日·读层 v3 日 (可用国策推导 + hover 原语 + 回放前置校验 + pytest ★)

### ★ focus 存档 schema 破案 (本日最大收获)
- 国家体 `focus` 成员 = { **completed = <focus-id> 重复键列表**(每完成一条
  追加一个, 完成序), progress = F32, current = <id> selector?, paused = bool }。
  GER 09-19 档 completed=[GER_the_four_year_plan] 单条 + 无 current = "国策
  完成后未再选"的形态; SOV 5 条/ITA 7 条/ENG 4 条/FRA 3 条全量在册。
- **progress raw /1e5 = 天数**(7 国全整数日 ✓): 无 current 时 = 银行日
  (上限 defines `MAX_SAVED_FOCUS_PROGRESS = 10`), 有 current 时 = 已投入
  当前国策的天数。**选中国策瞬间把整笔银行带入**(GER 03-31 排四年计划当日
  即 progress=10.0 的原因); 完成后银行重计。
- **时长口径实锤**: defines NFocus:`FOCUS_POINT_DAYS = 7` ("Each point takes
  a week") → **duration_days = cost × 7**(common/national_focus 的 cost 字段)。
  GER 四年计划 cost5=35 天: 排入时 10 天银行 → 剩 25 天 ✓ 与 unattended
  跑动后完成自洽; SOV_fascist_youth_union cost10=70 天, 09-19 档 progress 52
  → 剩 18 天 ✓ (UI 待对表一次即闭)。
- 连续档差分(03-31_16 vs 09-19_06, 171.5 游戏日)复验: 各 majors 的
  progress 变化与「完成旧国策→换新→银行重计」账目全部对得平(bypass 秒完
  条目除外)。

### ★ focusdata.py = 国策版 research.avail (读层第 16 区块能力)
- `common/national_focus/*.txt` 全量解析 (34 文件 9844 国策 / 67 棵树,
  含 37 个深嵌套块——统一用**括号配平**扫描, 不依赖缩进)。
- 每条: id / cost / **prerequisite OR-block 前置图**(多 block = AND,
  block 内多 focus = OR) / mutually_exclusive / available 非空触发标记
  (GATED, 不可离线求值) / bypass 标记。
- **树归属过滤用存档自证**: 国家体 `focus_tree` prim = 字符串树 id
  ("german_focus"…), 440 国扫一遍 = 权威 tree→tags 映射 (文件侧 country
  块不可靠: norway.txt 的选择因子是 `NOR_AAT = yes` DLC 标志, 无 tag)。
  可选 = 前置满足 ∩ 未完成/未在研 ∩ 互斥未锁 ∩ (本 tag 树 ∪ generic ∪
  前置邻接到达的共享分支); **他国树根永不泄漏** (文件侧 tag 法会把
  NOR/PRC-warlord 树根漏给 GER, 已被此法击败)。
- est_days = duration − 银行日 (第一次选择才有效)。GER 09-19: banked 10
  → cost5 行 est 25d, cost10 行 est 60d ✓。

### ★ 军队编组定案: 不序列化 (负面结果, 关案)
- 全档 10834 个 `army = {` 命中**全部**在 character_manager 头像区
  (角色 portrait 的 GFX 名单), 军队编组体一个都不存在; 顶层 unit_leader
  依旧只是裸 id 串; theatres.theatre 直接挂师句柄 (无军级分组)。
- **可重建的最近似物**: division.division_name = {type, name_order} —
  每模板内的建师序号 → units 区块已输出重建名 "<序>. <模板名>"
  (GER "1. Panzer-Division" / SOV "18. Strelkovaya Diviziya" 双文化实证 ✓)。
  伞兵/海军陆战队无序号者退回纯模板名。军级指挥链读数到 theatres 为止,
  再往上只剩 live UI (部署/战区面板) 或 CArmy 实例遍历 (写层项)。

### ★ 工具面 17→18 + 两项强化
- **hoi4_hover(x, y)**: 悬停不点击 + 回执截图。顶栏 tooltip 拆解的正式
  原语 (人力 0.300 / 稳定度 0.155 / 工业 0.353 @y0.024)。live 实测:
  「可用核心人口 (66.25M) 中的 2.50%」↔ save ratio 250000/1e5 ✓✓ (17 日
  口径在新会话数字上复验)。写层门禁内 (第 9 个受护写工具)。
- **hoi4_popup(recall=N)**: 读最近 N≤8 张已存截图免重抓 (弹窗逐帧对比
  是刚需, 19 日下次清单#2 的低价增强受益者)。
- **录制回放 v2**: record start 时并存**起点帧 PNG** 进 meta;
  replay 前拿当前帧与之做全帧 mean-diff, >8 拒 (证据路径双给:
  ref/now 截图), force=true 豁免。live 三路径: 噪声起点帧拒 ✓ /
  force 放行 ✓ / 正常档 diff ≈0 放行 ✓。
- `hoi4_country_detail` 文档同步 (focus/units 新能力)。

### ★ pytest 回归套件 (tests/, 24 用例全绿, ~63s)
- 本地数据缺位自动 skip (conftest 找最新 GER 档/HOI4 安装目录)。
- 覆盖: bin5 全档 opens==closes 配平 | saveinfo 日期编解码+无闰历法 |
  safety 三源守卫合成证据 (synthetic multiplayer=true/false/noise blob) |
  focusdata 树解析/前置图/互斥/est_days 银行折算/他国树根不泄漏 |
  country_sem 语义 (政党支持率和=100, focus schema, 师名重建) | techdata
  前置图/SP/hidden 过滤。
- **顺手抓出真 bug**: `saveparse/bin5.py _value` 的 prim 贪跑循环在
  档末/窗口末 peek 越界抛 struct.error → 被 save_mp_flag 的 except 吞掉
  → **真 multiplayer=true 若恰在扫描窗口尾部会误判 False** (保守假阴性)。
  修法: 循环内加 EOF 守卫 (r.p+2 > len)。合成 MP 档回归覆盖。
  (注意: 老版 Reader.prim 的 F32 仍按 4B float 读 —— 与 v3 定案的
  8B 定点不符, 只影响读 F32 值的路径; saveinfo/save_mp_flag 只读
  字符串+bool+u32 头部/标记值, 现网安全。后续换 lex3 内核时一并清账。)

### ★ 环境注记
- 游戏同进程未重启 (PID 26716), 本日全程只读+hover+一次误点即关;
  会话保持 PAUSED @ 6:00 19日 9月 1936 收工, 弹窗全清, guard=singleplayer。
- 命令日志四件 posted/sent/received/executed_commands.log 在 SP 会话
  0 字节 —— 非空样本需要 MP 或 -debug; CCommandQueue::Post 反汇编
  (路线图#4) 的文本参考要换个来源。

### 收工状态
- 读层 14 区块 → **16 项能力** (focus v2 + 师名重建), 工具 18 个,
  首次有自动化回归网 (pytest)。
- 下次清单:
  1. focus UI 剩余天数对表 (暂停下悬停国策树, 一次即可闭 est_days 口径)。
  2. CCommandQueue::Post: 命令日志空, 换 disasm 路线 (research/ 两脚本已铺)。
  3. 多人态正向样本 (MP 档) 验证 multiplayer token 正向取值。
  4. (可选) bin5 内核统一到 lex3 (F32 定点), 清掉 v1 读者的隐性分歧。
  5. (可选) hoi4_record replay-check 与 replay 起点校验合并提示语。

## 21 日·inject 写层攻坚日 (Phase I 首战: 通道打通 + 稳定性未决 ★)

### 战场交待
- 游戏 (26716) 在会话首试后被杀, 一共重启 3 次。死因全部查清且各有字节级
  案例 (见 §shellcode 三连败), 不是玄学: 两处是我方编码错误, 一处是
  TLS 语境发现 (协议级), 一处概率性死亡仍未定案 (唯一 open item)。

### ★ Windows 静态表全部落定 (inject/tables.py, 皆从 UI 代码路径反汇编钓出)
- **Post = 0x2250B00** (CSession::Post(queue, cmd, force)) — UI 三处尾跳
  调用形态锚定; 入队路径 = 前置谓词 (cmd vfn[+0x60]/+0x80, 多为 `xor al,al;
  ret` 恒假桩) 或 force≠0 或 **[queue+0x795]≠0 (SP 实测=1)** → 0x2250C20:
  stamp cmd+0xC=queue+0xA4 (发送者=1=GER) + cmd+0x16=min(queue+0x80,0x7fff) →
  **[CSession+0x58] 容器 vfn[+0x28] append**; 拒绝路径 = delete cmd + 返回 false。
- **operator new = 0x21C9AF0** (UI 分配点, jmp→0x25507D4→MSVC 堆);
  SetNationalFocus=0x38、Increase/DecreaseGameSpeed=0x28/0x40
  (UI `mov ecx,size; call new` 直接钓出)。
- **队列链**: idler(CInGameIdler)vtable+0x88 thunk → [idler+0x530]=
  CGameApplication → 其 vtable+0x88 = `mov rax,[rcx+0x380]; ret` →
  **queue = [CGameApp+0x380]** (CSession*), 纯成员读取。
- **静态全局槽位** (镜像内 RVA 同会话重建): G_GAMESTATE=0x332F260
  (**类名实为 CCurrentGameState**, vftable 0x2721158 — 15 日"无多态世界根"
  迷案告破), G_IDLER=0x332F698, G_GAMEAPP=0x3452450, G_QUEUE=0x3451DA8。
- **玩家 tag = gamestate+0x520** (Linux GS_PLAYER_TAG 平移; 构造调用里
  `cmp [G+0x520]>0 ? &G+0x520 : &G+0` 直接看见); 实测 GER=1 ✓。
- **SetNationalFocus (Windows)**: ctor(0x1146E60) = **+0x28 tag(i32,[rdx] 解引用)
  +0x2C focus_id(i32,=r8d) +0x30 mode(i32∈{0,1,2},=r9d)**; 变体 ctor 0x1146EA0
  从 focus 对象取 [r8+8] qword。UI 事件 [rdx+8] = focus 数字 id —— 与字符串名
  的映射要 live 抓 CNationalFocus 实例 (**未完成, 下次攻**)。
- 命令 spec 全录 inject/tables.py (BASE_INIT: [+8]=0 +C=-1 +10=0 +14=FFFF0000
  +18=0 +1C=0 — 与参考项目 Linux 版同构, offset 由本平台 ctor 自证);
  **命令不用调 ctor 就可构建** (vptr+BASE_INIT+字段+零填充已够)。

### ★ 远程调用原语 (inject/call.py) — 两协议 + 三起字节惨案
- **Shellcode (rbx 版, 每 store capstone 复核)**: param 持在 callee-saved rbx
  (`mov rbx,rcx`), call [rbx+n] 从 job 取函数/参数, 存 result@+0x28 /
  done@+0x30; fused 版另记 cmd@+0x28/posted@+0x30/done@+0x38, 复制段
  rep movsq 由 [rbx+0x40] 控制拷贝 qword 数。
  🔴 **惨案 1**: done-store 原 hex `48 C7 42 30...` — modrm 0x42 的 rm=010
  **缺 REX.B 时是 rdx 不是 r10** → 写到 "arg2(=0)+0x30" = **写空指针页** →
  AV (替身进程 0xC0000005 死亡; 第一个 26716 会话同死法)。教训: 扩 RM 用 r10
  必须 REX.B (4C 前缀); 现 rbx=011 不吃 B, `48` 就够。
  🔴 **惨案 2**: EXIT 尾巴 `jmp [rbx+0x38]` 放在 `pop rbx` **之后** — rbx 已还原
  成替身原值, 跳进垃圾。现序 = 先 jmp (永不 return)。
- **协议 A 劫持 (hijack=产品路径)**: 挂起全线程 → 选 **RIP∈合法镜像** 的冻结
  线程 → GetThreadContext 存档 → SetThreadContext(RIP=arena shellcode,
  RCX=param, RSP=arena+0x2FF8 私栈) → 只恢复它 → 轮询 done → 再挂起 → 还原
  context → 全恢复。
  🔴 **惨案 3 (协议级, 高价值)**: 劫持**冻结在内核等待里的线程 = 进程死**
  (替身睡眠循环 victim 三连死于变体实验; busy-loop victim 全绿)。GetThreadContext
  的用户态 RIP 无法区分"真用户态"与"syscall 陷阱帧里的最后用户态"——白名单
  必须是 RIP∈游戏镜像; 找不到就 rearm (freeze→scan→thaw→重试)。
- **协议 B 新线程 (newthread)**: CreateRemoteThread + 自退出 shellcode
  (RtlExitUserThread 尾跳)。**受 TLS 语境封死**: 游戏自己的代码大量读
  `gs:[0x58] TLS 槽` (连成员容器构造辅助 0x11DF40 都读游戏 TLS 索引分配器)
  → 新线程上除 GetTickCount 这类系统调用, **游戏侧函数几乎必 AV**
  (Post 的 log/describe 路径真机二次实弹把会话打死 = 定案)。协议 B 降级为
  研究工具。
- 替身干跑规程 (python victim): tick/pid/连调/递增四连全绿才上真机 ——
  **pre-game 验证规程值得固化**。

### ★ 真机闭环 (fused 单冻结窗口: new+copy+Post)
- 教程会话 (意大利 1936-11, 误点单人教程局): 空闲 RIP 采样 119 线程、每轮
  0-2 个在镜像内 (≈10-40% 帧命中, 线程 20740/20652 主/渲染高频) → attempts=60
  可以抓到。**CIncreaseGameSpeedCommand posted=True → drain 执行 → 命令对象
  释放 (堆复用为字符串实锤) → HUD 速度 pips 1→2 瞬时可验** ✓✓✓
  —— **v2 写层「玩家点击同通道」的首次完整可观察闭环成立**。
- 🔴 **未决 (首要)**: 同一会话**第二次** fused 发送在 restore 的 SetThreadContext
  上崩掉整个进程 (两局复现, WinError 31; 疑似全 118 线程挂起的竞态, 与命令
  类型无关)。缓解已写进纪律/MCP 文案: **一令一会话**、cooldown 2s; 死后
  存档装载恢复无数据损失。下次攻: 缩短冻结窗口 (先 racy 扫描后定点冻结)。
- 产物 MCP: `hoi4_inject_status` (只读) / `hoi4_inject_speed` (±1/±2,
  单冻结窗/发, 2s cooldown + 一令一会话警告); 静态回归 tests/test_inject_tables.py
  (基础字段/schema/shellcode 编码/RVA 对齐 6 用例, 30/30 绿)。

### ★ 顺带收获 (操作层/读层)
- **重启回档路径实锤**: launcher『开始游戏』(播放集=无 Mod) → 主菜单
  『单人游戏』落地屏自带最近存档列表 (左列 row0=最新; row 行 y≈0.373, x≈0.108,
  1920x1200) → 点行 → 『开始』@(0.851,0.946)。『继续游戏』(GER 旗=上次会话)
  为规避 NOTES 15 日 CTD 案例未采用。
- **Read 工具看图坐标必须换算**: Read 渲染会缩放截图, 目测坐标再点持续脱靶
  (『开始』连点三次脱靶即此); 修正法 = 原始 PNG 程序化 bbox 定位 (如 22b6
  绿色面)。launcher 点击用项目 Input(SendInput 归一化) 有效。
- idler+0x6C1 暂停位本会话 = paused ✓ (与 icon_state 双证, Linux IDLER_PAUSED
  同位); **速度字节不在 idler 带** (0x6C0..0x6C7 无差) — 在 CGamePlaySettings
  里 (未 diff 到, 下次攻), 但速度验证已可走 HUD pips 闭环。
- AGENTS/README 工具面同步 (inject 组 2 工具, 现役工具 18→20)。

### 收工状态
- 游戏进程在教程会话第二次注入死亡后退出; **GER 主档 GER_1936_09_19_06
  完好在盘**, 下次载入即回 1936-09-19 06:00 挂起态。v2 写层=已验证通道 +
  已隔离的稳定性尾刺 (一令一会话纪律先行)。

### 下次清单 (v2 路线图顺序)
1. **稳定性攻坚** (解除一令一会话): 先 racy 扫描后定点冻结 / 逐线程挂起 /
   读懂 crash 与挂起竞态关系; fix 后重跑多连注入验证。
2. SetNationalFocus 闭环: focus 数字 id ↔ 字符串名映射 (live 抓
   CNationalFocus 实例), mode 0/1/2 语义 → 存档 diff 验收 (Phase I 主菜)。
3. CGamePlaySettings 速度/暂停字节 diff 定位 (注入变化后全带扫描收敛)。
4. CCountry 字段带双源对齐 (Linux 表 CO_STABILITY_BASE=0x10A8 等起底,
   Windows 平移待验证; 存档 tokens ↔ 内存偏移)。
5. -debug 重启采样命令日志 (posted/sent/received/executed 可作对照文本)。

## 22 日·环境级阻断定案 + focus 数字 id 映射闭环 ★

### 任务面 (按 21 日下次清单)
1. 稳定性攻坚 → **升级为平台级阻断定案** (见下, 一令一会话纪律仍维持但根因已明);
2. SetNationalFocus 的 focus id 映射 → **闭环达成** (10,668/10,668, 独立交付);
3. CGamePlaySettings 速度字节 → 未动 (策略阻断优先级更高)。
4. CCountry 字段带 / -debug 采样 → 未动。

### ★★ 主结论: 10-14 安全更新带来「跨进程执行全面封锁」(系统级, 不可对天不改)
**时间线证据**: KB5127648/KB5127647/KB5121794/KB5127694 InstalledOn=2026-10-14;
last boot=10-17 11:37 (今天); 21 日 live 闭环发生在重启前。Defender 三开关
(AMService/AV/RTP) 全关 → 不是 Defender 行为拦截。机器策略 (Get-ProcessMitigation):
DynamicCode=0x0 / CFG=0x0, 但 **UserShadowStack policy = 0x100** (bit8-9=01 ⇒
**SetContextIpValidation=ENABLE**) 对 hoi4.exe/python-victim/notepad 完全一致。

**victim 四象限 + 逆向实验矩阵** (全部替身 python, key 事实逐条坐实):
- 热主线程 victim × 劫持/hijack-graft: 232ms 后整个进程死; 读回 graft 后
  **RIP=0x0** (graft 被内核置零);
- 热主线程 × newthread (协议 B): 同死;
- 睡眠 victim × 劫持: API 报错但进程存活 (picker 靠 trap-frame 误选睡者 → 空 graft);
- CRT(非镜像 RWX arena): notepad/py311 fail-fast 0xC0000409 (进程连坐),
  cmd/py38 线程级 0xC0000005 (进程苟活) — 全部不可用;
- **CRT 起点在已加载模块内部 (python312.dll+0x1000): 完全正常** (线程跑起来,
  进程活) → 非镜像私有内存被启动校验拒绝;
- SetThreadContext graft RIP=kernel32!GetTickCount (系统函数入口): **RAX 收到
  真 tick** — graft 确实执行了! 但线程随后 RIP=0 → 死亡螺旋 → restore 后进程死;
- graft RIP=目标进程镜像内 code cave (python312 零段, WPM 可写可读): 同样死亡;
- NtCreateSection(SEC_IMAGE)+NtMapViewOfSection 映射 msimg32 + WPM patch
  (CoW 成功) + CRT 进映射镜像: 也死 (白名单疑似按"正常加载模块"判)。

**机制归纳 (操作级)**: 在本 build, ①CreateRemoteThread 起点必须在"正常加载
的可执行镜像页"内; ②SetThreadContext 重定向 RIP 有 **SetContextIpValidation
检查点** — 非系统位图有效目标 (私 arena/目标进程无 CFG 镜像的 code cave 均判
无效) → RIP 被**置 0**, 线程随之进入 RIP=0 调度死亡螺旋 (RAX 留有成功执行痕迹,
说明 graft 瞬间确实运行过); ③所有指向非系统有效目标的路径全部无法存活。
**对项目含义**: CSession::Post 写通道的"graft+恢复"协议在当前 OS 状态下
**victim 无可能性; 游戏进程大概率同判** (同一 policy 0x100)。21 日"一令一会话"
纪律解释也同时升级: 不是挂起竞态玄学, 而是恢复阶段的第二次 SetThreadContext
本身就是死亡原语 (性与 victim 恢复死亡完全一致)。

**未走完的路 (下次优先)**:
- a) **自启动游戏**: 用自己 CreateProcess 带 PROCESS_CREATION_MITIGATION_POLICY
  attribute (SetContextIpValidation=DISABLE) 启动 hoi4.exe — 进程级豁免的
  唯一正路; 需确认游戏自启参数路径 (launcher 转发参数/continuelastsave)。
- b) Windows 更新卸载/ Insider 通道回滚 (用户决策级)。
- c) graft 目标侧换"目标进程内被标记 valid 的点" — 需要游戏镜像 CFG/EHCONT
  元数据, hoi4.exe guardflags=0 → 理论无有效点; 除非 (a) 生效否则此路不通。
- d) (长线) 纯读层的 CArmy/战场实时数据不依赖写通道, 不受影响。

### ★ focus 数字 id ↔ 名 映射 (今日独立交付, Phase I 主菜前置达成)
- live vftable 扫描: CNationalFocus vftable RVA **0x2739C08** (+0x10 二级 vft
  0x2739C88, 同对象); 实例 **10,668** 个;
- **id = int32 @ +0x08** (全实例唯一, 范围 12989..65031);
- **name = MSVC std::string @ +0x18** (union{sso[16]; ptr} + size@+0x10 +
  cap@+0x18; cap>15→堆指针, ≤15→内联): 全变体修复后 **10,668/10,668 全提取**
  (v1 只对堆指针串有效, 547 个 SSO 内联串漏报; +0x38 为同一名字的第二份副本
  可兜底); (id,name) 零重复;
- 资产锚点 (GER 1936-09-19 暂停会话): GER_the_four_year_plan=**58138**,
  GER_autarky_efforts=58139, GER_slowdown=…; GER 前缀 438 个 (双树: 威权
  帝国线 32711/38126-38149 段 + 本局 58116-58xxx 段);
- **存档 join 验证 ✓**: save GER completed=[GER_the_four_year_plan] ↔ id 58138;
  available[] 9 条中 GER_* 与 generic_* 六成直接命中 (army_effort 等三条
  generic焦急 missed — 它们在 live 表里的名字是 generic_focus 树里的
  "industrial_effort" (58086)/“political_effort”(58099), 与 available 行名
  对得上; army_effort/aviation_effort/naval_effort 三条未入 live 名集合 —
  属于 disk 侧 generic_focus 的特定条目, 与 live 表整体 100 提取不冲突, 单点);
- disk FocusDB (common/national_focus 解析, 9844 focus/67 树) ↔ live: 重合
  9342/9844 (94.9%); live 独有 779 个 = DLC 树 (RAJ 391/CHI 129/SMB/BALTIC…)
  — 本机装 CreamAPI (appid=255710=Cities Skylines!), DLC 内容不在
  common/national_focus 磁盘文件中 (live 内存是唯一 truth source);
  disk 独有的 502 = v1 (堆指针-only) 提取器漏掉的 SSO 串, v2 已全收;
- **交付物**: hoi4_mcp/inject/focus_ids.py (scan_focus_ids proc只读 一次
  vftable 扫 ~20s + 全库 id↔名); MCP 工具 **hoi4_focus_ids(prefix)** (+1021
  → 工具面 21 个); 研究产物 research/focus_ids_live.json (438 GER 条 +
  全库); tests/test_inject_focus_ids.py 6 用例 (MSVC 串解码 SSO/堆/拒错/
  vft 锚点/ID 布局) — **pytest 36/36 全绿**。

### 顺带收获
- `win32ext.get_thread_times()` (create/exit/kernel/user 秒, 供 racy 判别与
  主线程识别, 已并入 RemoteCaller/_threads 排序 — 弃 psutil 线程版本依赖);
- `win32ext.mitigation_report()` (只读 shadow_stack/dynamic_code/cfg 三策略
  还原 — 游戏进程这三都在 day22 合法读取测试过);
- RemoteCaller racy 扫描器 (probe_targets: 两份 GetThreadTimes 增量 + 双
  RIP 采样 in-image+distinct) — **策略层面照常正确**, 只是目前 OS 状态下
  是"能找到 graft 目标也保不住"级别; legacy_fallback 默认关闭;
- 惨案热量消耗文件: injector_race_scan/cave_bisect/caveprobe/cavetargets
  (研究目录留在 research/, 无 MCP 面)。

### 下次清单 (按优先级)
1. **平台方案定案** (最大商业价值): 试用 PROCESS_CREATION_MITIGATION_POLICY
   关 SetContextIpValidation 自启动 hoi4.exe (或与用户协商 Insider/更新
   回滚) → 重跑 victim 四象限 → 多连注入 (重燃烧 21 日 E2E 脚本);
2. 若 (1) 成功: SetNationalFocus {tag=1, focus_id=58138 等映射, mode 0} 注入
   → 存档 diff 验收 (sleep mode 语义) — Phase I 主菜;
3. CGamePlaySettings 速度字节 (idler+0x6C1 已双证, 只差速度字节) 的 diff;
4. FocusDB DLC 树补源 (读 dlc/*.zip) — 提高 disk 推导覆盖 (live map 已全);
5. CCountry 字段带双源对齐 (Linux 表起步)。

## 23 日·22 日误诊定案 + APC 写通道上线 (write v3, 真机 E2E ★★)

### ★★ 主结论 1: 22 日的「平台级阻断」是读错位——根本没这回事
- `GetProcessMitigationPolicy(ProcessUserShadowStackPolicy)` 返回的是
  **4 字节** DWORD; 22 日的 `mitigation_report()` 用 size=8 调用 → 今天复测
  该调用直接 `ERROR_INVALID_PARAMETER(87)`, 同一函数当天能出 0x100 说明当时
  传的是 4。**0x100 = bit 8 = `CetDynamicApisOutOfProcOnly`, 不是 bit 2
  `SetContextIpValidation`** (本机 SDK 10.0.22000 winnt.h 与 phnt/libobs
  bindings 三方一致);
- 内核侧 `KeVerifyContextIpForUserCet` 第一道门就是
  `if (!process->MitigationFlags2Values.UserCetSetContextIpValidation) return
  STATUS_SUCCESS;`, 第二道门 `if (!Thread->Tcb.CetShadowStack) ...` — 而
  hoi4/explorer/python **bit2 = 0**, 即校验根本没开;
- **victim 五原语重测矩阵 (research/apc_probe/matrix.py, 每种一个全新替身) 全绿**:
  | 原语 | 22 日结论 | 23 日实测 |
  |---|---|---|
  | WriteProcessMemory 数据写 | 可用 | ✓ canary 读写回 |
  | SetThreadContext graft (RemoteCaller) | **必死** | ✓ GetTickCount=32324250, 替身存活 |
  | CreateRemoteThread→私有 RWX | **fail-fast 0xC0000409** | ✓ 6ms 执行, 存活 |
  | CRT→LoadLibraryW | — | ✓ msimg32 真被加载 |
  | QueueUserAPC(alertable) | — | ✓ 0ms 命中, 非 alertable 线程正确不投递 |
  | QueueUserAPC2(SPECIAL) | — | ✓ 忙线程也投递 |
- 公开资料侧同样没有对应报告 (research 子代理调研: 2025-2026 无任何
  "10 月更新封锁跨进程注入" 的记录; .NET 9 的 CET 崩溃、CE 论坛的"改值要
  点 50 次"都与 IP 校验无关)。**旧解释 (第二次 SetThreadContext 即死 /
  一令一会话) 一并作废**: 21 日的"第二发崩"更可能就是 21 日自己抓到的
  惨案 3 (graft 冻结在内核等待里的线程) + 挂起窗竞态。
- 教训入库: **策略位必须按 SDK 位序逐位解码后再下结论**; `get_mitigation_policy`
  的 size 参数已修 (4)。

### ★★ 主结论 2: APC 写通道 = 比 graft 更好的主路径 (已真机闭环)
- 原理: `QueueUserAPC2(hThread, payload, job, QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC)`
  → 载荷在**游戏自己的线程**上、于内核→用户态返回点执行;
  ①不挂起任何线程 (21 日"第二发死"的温床消失) ②不新建线程 (新线程没有游戏
  的线程局部状态, 这正是协议 B 被 TLS 打死的原因) ③载荷在该线程自己的 TLS
  语境里 ④APC 返回后 ntdll 用 NtContinue 恢复被打断的上下文, 线程原地续跑。
- 载荷 (hoi4_mcp/inject/apc.py, 139B, capstone 逐条复核):
  `xchg` 原子 claim (单发单用, 多线程排队也只有一发真跑) → 把 post/queue/blob/
  count 预取进 r13/r14/r15/rbp (关键: **首次调用后绝不重读 job**) → 换私有栈 →
  `operator new(size)` → `rep movsq` 拷 blob → `Post(queue, cmd, force=0)` →
  done → 还原 rsp → ret。
- 目标线程选择: GetThreadTimes 两采样分类, **优先 parked (user time 不涨 =
  停在内核等待里, 投递点不持锁)**; 一次向至多 4 个 parked 线程排队 (claim 保证
  多余投递是空操作), 1.2s 内无人认领才动 main/hot。
- 真机 E2E (进程 32572, GER 1936-09-19 06:00 暂停):
  `IncreaseGameSpeed` → `posted=True, cmd=0x187cba2f890 (真堆指针), ran_on=36720,
  kind=parked, latency=14ms, job_intact=True`, 游戏存活; **HUD 速度 pips 4→5
  视觉复核 ✓** (shots/day23_speed_compare.png); 连发 6 次 (增减交替) 全部入队,
  其中一次 `posted=False` 是**游戏自己拒绝** (速度已在下限) —— CanExecute 活着
  的正面证据。

### ★ 首战事故 → 根因 → 修复 (本日最重要的工程教训)
- 事故: 第一次真机 post (20:55) **打死游戏**: WER `BEX64 / 0xc0000005 /
  出错模块 unknown / 错误偏移 0x0` = 跳到地址 0。
- 根因 (替身复现): 通道 v1 的私有栈只有 0xF00 (3.8KB) 且**紧贴 job/blob**;
  真实 `operator new` 的调用链把栈走穿到 job 上 → 载荷重读 job 得到垃圾
  (真机现场读回就是"字段整体错位 + 0x7FF9.. 这类栈上代码指针"), `rcx=0` 的
  `rep movsq` 变空拷贝, 随后 `call [rbx+0x10]` = **call 0**。
  替身实验 (research/apc_probe/apc_channel_dryrun.py --deep-stack 6144, 假
  callee 用 rep stosq 把整段栈填满) **原样复现**: job 被踩 → 宿主进程死亡。
- 修复 (三层):
  1. 槽位布局 v2: `SLOT_STRIDE=0x4000`, 栈顶 `slot+0x3FF0` → job 上方
     ~15.6KB 栈余量 (12KB 深栈回归绿);
  2. 载荷加固: 首次调用前把 post/queue/blob/count 读进 callee-saved 寄存器,
     调用后不再依赖内存里的 job;
  3. 三振出局 `job_intact`: 发后回读**输入字段** (输出字段本该变, 不参与比较),
     变了就标 `warning` 让上层拒绝信任该发。
- 附带教训: `apc_channel_dryrun` 这个替身跑道**必须先跑全载荷再加真机**——
  21 日定的「pre-game 规程」这次被跳过了 (只跑了只写探针), 代价是一个游戏进程;
  修好后同一替身又立刻抓到第二个编码 bug (`mov rcx,r14` 误编成 `mov rcx,r13`
  → Post 收到 Post 自己的地址), 真机上这会是又一次崩溃。
- **待办**: `find_pids` → `find_live_pids` (线程数 <8 的"僵尸 hoi4.exe"会一直
  answer tasklist, 让 `expected exactly one hoi4.exe` 恒失败; 本日踩到)。
- **观察未定案 (三次死亡的时间线, 重要)**:
  1. 20:55 第一次死 = **本通道 v1 的 bug** (BEX64 / 0xc0000005 / 偏移 0 = `call 0`),
     根因与修复见上; 留了一个**杀不掉的僵尸进程 29156** (1 线程,
     TerminateProcess → ACCESS_DENIED, 至今仍在进程表里);
  2. ~21:25 第二次死 = **静默退出** (无 Application Error 事件、无 dump、
     game.log 无收尾行); 死前 5 分钟的最后一次读数是 alive=True/job_intact=True;
  3. ~21:39 第三次死 = 同样静默; 进程 37400 在 21:35 装载成功, 21:38 还能正常
     读身份链, 21:39 就 WinError 299 了 —— **这一轮根本没有发出任何 APC**
     (apc_stress 死在发之前的 is_paused 读上)。
  → 结论: ②③ **不能归因于写通道**(③ 连一发都没发)。最可疑的是**僵尸进程
  29156 污染了后续会话**: Steam/游戏自身的单实例与 DRM 逻辑可能在稍后静默
  终止新实例 (没有异常事件正符合"被正常终止"的画像)。**下次开工前先重启机器**
  (清掉不可杀僵尸), 再在新会话上复测 APC 通道; 若重启后仍静默退出, 则开
  WER LocalDumps (需管理员写 HKLM\...\Windows Error Reporting\LocalDumps) 抓
  minidump 定位。

### 交付物
- `hoi4_mcp/inject/apc.py` (ApcChannel + 139B 载荷 + 单发单用 claim + 槽位布局);
- `inject/commands.py`: `send_apc()` / `speed_step_apc()` / `post_focus_apc()`
  (graft 的 `send_fused()` 保留为研究回退);
- MCP: `hoi4_inject_speed` 改走 APC (不再有 2s 冷却/一令一会话), 新增
  **`hoi4_inject_post(command, focus, focus_id, mode)`** (SetNationalFocus 的
  名字↔id 解析已接), `hoi4_inject_status` 增补策略位解码 + APC 通道状态;
- 研究脚本: `research/apc_probe/{matrix,victim,game_probe,apc_debug,
  apc_channel_dryrun,apc_post_test,apc_stress,relaunch_game}.py`;
- 证据: `shots/day23_speed_compare.png` (pips 4→5)、`day23_00_before_probe.png`、
  `day23_relaunch_*.png` (重启回档 UI 链)。

### 下次清单 (按优先级)
1. **SetNationalFocus E2E** (Phase I 主菜, 前置已齐): `hoi4_inject_post(
   command="SetNationalFocus", focus="GER_...")` → 存档 diff 验收 mode 语义
   (0/1/2 各自效果), 并复核 `focus.available` 的 est_days 口径;
2. **静默退出复现与定性**: 连发 N 次 + 长时间挂机, 记录是否复现; 若复现,
   开 WER LocalDumps (需管理员写 HKLM) 抓 minidump 定位;
3. 载荷加固第二层: 目标线程加"parked 且不是渲染/音频热线程"白名单 (现在只有
   parked/hot 二分); 以及多线程同时投递时的 claim 语义再测;
4. CGamePlaySettings 速度字节 diff (idler+0x6C1 已双证) → 速度脱离截图;
5. CCountry 字段带双源对齐 (Linux 表起步), live 读层 Phase II 继续。

## 24 日·写层 v3.1 (微 VM 载荷 + 崩坏护盾) + SetNationalFocus 血案与定案 ★★

### 任务面
用户要求「分析进度 + 进一步研究如何进行内存写」。上机时游戏已在跑 (GER 1936-09-19
暂停, tag=1, 机器已重启过 → 23 日的僵尸进程问题自然消失)。定下的两条线:
**A. 把通道从「固定载荷」升级成可复用的写原语**; **B. SetNationalFocus E2E**。

### ★★ 交付 1: write v3.1 = 微 VM 载荷 (`hoi4_mcp/inject/script.py`)
23 日的载荷只会一件事 (new+拷 blob+Post)。要把「内存写」做成能力, 得有能在游戏
线程上跑**一串**内存操作的载荷。新载荷 (keystone 汇编, 704B) 实现一个小 VM:

| op | 语义 |
|---|---|
| 1 CALL(func,a1..a4) | rcx/rdx/r8/r9 传参, RAX 存回 op 记录 |
| 2 WRITE_RAW(addr,val,size) | size ∈ {1,2,4,8} |
| 3 READ(local,target,size) | 目标 → 我们的 data page |
| 4 WRITE(target,local,size) | data page → 目标 |
| 6 MEMSET(addr,byte,size) | 填充 |
| **7 ALLOC_CTOR(new,ctor,size,a1..a3)** | `obj=new(size)` → `ctor(obj,a1,a2,a3)`, obj 记住 |
| **8 CALL_THIS(func,a1..a3)** | `func(obj,a1,a2,a3)` — obj 取自 op7 (即 Post(queue,cmd,force)) |

布局 (三块独立分配, 都是我们自己的): code arena (2MB, 每发一个 0x8000 槽 =
job + ~31.7KB 私有栈) / data arena (1MB, 每发 8KB 页 = 头 + op 数组 + 局部缓冲) /
job 在槽底, 一个原子 xchg 认领。
安全性质 (都写进 tests/test_inject_script.py 的断言):
- **op 程序不在栈的路径上** (独立分配), 深栈 callee 跑不坏「正在执行的程序」;
  载荷首次调用前把参数预取进寄存器 (23 日教训延续)。
- **CALL/ALLOC_CTOR/CALL_THIS 目标必须先过白名单** (游戏镜像区间), 否则拒发。
- op 记录 0x40 步长 (24 日 bug: pack 出 7 个 qword 塞 0x40 步长 → 第 2 条 op 从
  第一条中间解码; 替身跑道抓到); 局部缓冲地址在 run() 时才重定位成绝对地址。
- job 输入字段回读 (job_intact), 单发单用 claim 不变。

### ★★ 交付 2: VEH 崩坏护盾 (同一载荷内)
`AddVectoredExceptionHandler(1, handler)` 装在目标进程里; handler 只接管
① fault RIP ∈ 我们的 arena ② 或 g_guard_null=1 时 payload 在飞 (g_cur_job≠0)
且 RIP < 0x10000 的野跳 (`call 0` — 23 日的死法)。命中就把出错 CONTEXT 改写成
Rip=recover stub / Rsp=saved_rsp / Rbx=job (winnt.h: Rbx 0x90, Rsp 0x98,
Rip 0xF8, R13 0xE0), 返回 EXCEPTION_CONTINUE_EXECUTION; 其它一律
CONTINUE_SEARCH (游戏自己的异常语义不动)。recover stub 记 status=2 + fault_rip/
code + done, 还原 rsp 后正常 ret 回 APC dispatcher。
**替身跑道双相位验证** (research/apc_probe/script_dryrun.py): 相位 A = 无盾时
`call 0` 必杀宿主 (exit 0xC0000005); 相位 B = 装盾后 call 参数/read/write/
write_raw 1-2-4-8/memset/坏 op/claim 单发/alloc_ctor→call_this/24KB 深栈 ctor/
arena 内 AV/call 0/callee 内 call 0 **全绿**, 宿主存活; 32KB 故意溢出 → job_intact
翻 False (三振出局有效) 且不杀进程。**DRY RUN GREEN**。

### ★ 真机首验 (research/live_vm_probe.py, 进程 26312)
- 装盾成功 (handle 0x1fc18914400); VM **读**游戏内存: paused 字节/idler、
  gamestate 指针与 RPM 逐字节一致, gamestate vftable RVA 0x2721158 = 表 ✓;
- VM **调游戏函数**: `operator new(0x38)` 返回真堆指针 0x1fbfd440580 (可读);
- **故意从 0x10 读** (未映射页) → status=2, fault_rip 落在我们 arena, 游戏存活,
  之后 paused 字节/ gamestate 照读不误 → **护盾真机验收 ✓**。

### ★★ 血案 2: SetNationalFocus 手搓 blob 打死游戏 (23:24:22)
- 现象: 用旧 `post_focus_apc(focus_id=58147, mode=0)` 发 SetNationalFocus →
  3.1s 超时 (posted=False, claim=1/done=0), 随后 hoi4.exe **整进程消失**;
  WER: `Application Error / hoi4.exe / 0xc0000005 / 错误偏移 0x24c2f0d / PID 0x66C8`;
  游戏 log 无收尾行, 命令日志 4 个全 0 字节。
- 现场: 0x24c2f0d = `cmp qword ptr [rdi+0x18], 0xf` — 命令 kind-describe 辅助
  (0x24c2ea0 的第二变体, 被 vfn[1] 系路径尾调) 里的 std::string 判长, rdi 是
  传进来的一个空/坏串指针。
- **根因 (24 日定案)**: 21 日笔记把 **0x1146E60 当成了 SetNationalFocus 的 ctor**
  — 反汇编证明它 `lea` 的是 **0x2996070 = .?AVCSetFuelPriorityCommand@@** 的
  vtable (RTTI 三方一致)。于是 tables.py 的字段布局 (tag@0x28 / focus_id@0x2C /
  mode@0x30) 是**别的类**的。我们发出的对象 vtable 对 (0x2996458 = CSetNationalFocus
  Command ✓ RTTI), 字段全错 → 游戏收下后按错误语义描述它 → AV。
- **真 ctor = 0x1146F70** (由 vtable xref 反查, vtable lea 就在函数体第 3 条):
  ```
  xor r9d,r9d ; [rcx+8]=0 ; lea rax,[vft 0x2996458] ; [rcx+0x10]=r9d ;
  [rcx]=rax ; [rcx+0x18]=r9w ; [rcx+0x1c]=r9 ; [rcx+0xc]=-1 ; [rcx+0x14]=0xffff0000 ;
  mov eax,[rdx] ; [rcx+0x28]=eax ; mov rax,rcx ; [rcx+0x30]=r8 ; ret
  ```
  → **rdx = &tag(int32), r8 = CNationalFocus\* (指针!)**, +0x2C 从不写 (不是字段)。
  UI 调用点 (0x131e17f 起) 正是 `mov ecx,0x38; call new; mov r8,r15; mov rdx,
  [rsp+0x70]; call 0x1146F70` — r15 = 点击的国策对象。
- **教训**: blob 复刻 vtable 容易, 复刻字段布局只能靠 ctor; 「没调 ctor 也能构建」
  (21 日结论) 只对**无字段**命令成立。新纪律: **命令对象一律走真 ctor**。

### ★★ 交付 3: ctor 忠实路径 + 离线 spec 验证器 (防同类事故)
- `CommandLayer.send_ctor_apc(name, *args)`: 一次 APC 内 `new → 真 ctor → Post`,
  对象由游戏自己构造; `post_focus_ctor(focus_obj)` = tag 指向 **gamestate+0x520**
  (UI 自己传的就是这个地址) + focus 对象指针。
- **新工具链**: `research/find_vft_refs.py` (vtable xref → ctor/工厂),
  `research/command_spec_hunt.py` (RTTI vftable + ctor 字段写 + new 尺寸 +
  UI 调用点上下文), `hoi4_mcp/inject/specverify.py` (**离线**校验器):
  ① vftable 必须属于该命令的 RTTI 类 ② spec 里的 ctor 必须真的装载这个 vftable
  ③ 尺寸必须覆盖 ctor 的每一次写 (≥ 最后字段末) ④ `blob_ok=True` 只允许在
  「blob 字段覆盖 ctor 全部写」时成立。全部通过才算 verified。
- **顺带抓出两个表错** (都是「手搓 blob」潜在的雷):
  - `DecreaseGameSpeed` 真实尺寸 **0x48** (旧 0x40): ctor 在 +0x28 构造一个
    std::string (movups 清零 @+0x28, size@+0x38, cap=0xf@+0x40); UI 的
    `mov ecx,0x48; call new; call 0xf05750` 在 0xdc9197 直接可见 →
    blob 路径对它**禁用** (blob_ok=False), 必须走 ctor;
  - `SetGameSpeed` 真实尺寸 **0x30** (旧 0x28), ctor 写 dword @+0x28 → 同样
    blob_ok=False; `PauseGame` (= .?AVCPauseGame@@, ctor 未回收) 标 verified=False,
    写层直接拒发。
- `tests/test_inject_specs.py` (13 用例) 把 ①②③④ 变成回归网; pytest 70→**83** 全绿。

### 交付物 (24 日)
- `hoi4_mcp/inject/script.py` (微 VM + 护盾 + ScriptChannel + Script builder);
- `hoi4_mcp/inject/specverify.py` (离线 spec 校验), `inject/tables.py`
  (布局/尺寸/ctor 修正 + verified/blob_ok), `inject/commands.py`
  (`send_ctor_apc` / `post_focus_ctor`, blob 路径门禁, `speed_step_apc` 改走 ctor),
  `inject/focus_ids.py` (`scan_focus_ids_objects` 返回对象地址);
- MCP: `hoi4_inject_post` 改 ctor 路径 (SetNationalFocus 收名字/id → 活体对象指针),
  `hoi4_inject_status` 增 VM 通道状态;
- 研究脚本: `research/apc_probe/script_dryrun.py` (双相位替身跑道),
  `research/apc_probe/script_debug.py` (单 op 取证), `research/live_vm_probe.py`,
  `research/live_focus_e2e.py`, `research/find_vft_refs.py`,
  `research/command_spec_hunt.py`, `research/disasm_focus_cmd.py`,
  `research/focus_state.py`;
- pytest 70→**83** (新增 16 条 VM 载荷结构/编码/护栏 + 13 条 spec 验证, 其中
  spec 套件按安装目录自动 skip)。

### ★★ 血案 3 (24 日当晚): call_this 的 ABI 弄反 → 又打死一个进程
- 现象: 新会话 (pid 11200) 装盾 + VM 读/调游戏函数全绿; 随后 `speed_step_apc(+1)`
  走 ctor 路径 → job 的 done 永不为 1 (3.1s 超时, status=0, `ran_on=1852` 说明载荷
  确实起跑了), 紧接着进程消失 (第二个脚本连 hoi4.exe 都找不到)。
- **根因**: 我把 op8 实现成 `func(obj, a1, a2)` = **rcx=对象**; 而 Post 的签名是
  `Post(CSession* queue, CCommand* cmd, u8 force)` = **rcx=queue, rdx=cmd**。
  于是 Post 把 queue 当命令、把对象当队列 → 在 Post 内部 AV (游戏镜像内, 护盾按
  设计不接管) → 进程死。**知识早就在手** (21 日笔记 + 反汇编), 是实现的错。
- **更深一层的教训 (重要)**: 替身跑道的 `fake_post` 是照我(错)的假设写的
  (rcx=obj), 所以**跑道全绿**。替身只能验证「实现是否符合我的假设」, 不能验证
  「假设是否符合游戏」。对策两条:
  1. `call_obj(func, slot, args...)` —— 显式指定对象落在哪个寄存器位
     (Post → slot 1 = rdx); slot 越界/参数过多直接拒;
  2. 把 ABI 变成**离线机器可检的断言** (`tests/test_inject_specs.py::
     test_post_argument_order_from_the_binary`): 从 Post 序言里认
     `cmp byte ptr [rcx + 0x795]` (rcx 是队列) / `mov rax,[rdx]` + `call [rax+0x80]`
     (rdx 是命令对象) / `test r8b,r8b` (r8 是 force) —— **假设也要有证据**。
- 附带 bug: keystone 把 `mov byte ptr [0x20], 1` 编成 **RIP 相对** 写 (落在自己页内,
  不 fault), 让「callee 内 AV」的替身用例假绿; 改成 `movabs rax,0x20; mov [rax],1`。
- **护盾第三规则 (24 日加)**: 新增全局 `g_in_call` —— 载荷每次 call 出界前置 1、
  返回后清 0; handler 若发现「载荷在飞的调用里出现硬 fault」(0xC0000005 AV /
  0xC000001D 非法指令) 就接管恢复 (改 CONTEXT → recover stub, status=2);
  C++ 异常 (0xE06D7363) 及其它一律放行给游戏。替身新用例 `fault inside callee`
  全绿 = **这次的死法已在离线被复现并兜住** (fault_rip 落在替身 fakes 页,
  不是我们 arena, 只有第三规则能救; 宿主存活)。
- 载荷随之涨到 888B (仍 < 4KB 保留区), pytest 83→**86**。

### ★★ 真机 E2E 成功 (24 日收工前, 进程 30944)
修好 ABI 后用第三个会话完成验收, **三条互不依赖的证据链**:
1. **注入侧**: `speed_step_apc(±1)` 与 `post_focus_ctor` 全部 `posted=True`、
   `cmd` = 真堆指针、`status=0`、`job_intact=True`、latency 13-71ms、游戏存活
   (旧 blob 路径同一发就死);
2. **速度命令 (ctor 路径, pips 像素分类 `research/speed_pips.py`)**:
   +1 步 → 第 5 个 pip `dark(53)` → `grey(67,66,47)` (亮起); −1 步 → 又暗回去
   (Decrease 走 ctor 0xF05750 + 修正后的 **0x48** 尺寸 ✓✓);
3. **SetNationalFocus (Phase I 主菜) 闭环**: `post_focus_ctor(GER_accelerate_the_
   rearmament_program 的活体对象 0x217a60b0e70)` → `posted=True` (latency 71ms) →
   **存档 diff** (`research/focus_state.py`, 存档 = 真值):
   | 字段 | 注入前 | 注入后 |
   |---|---|---|
   | `current` | null | **GER_accelerate_the_rearmament_program** |
   | `duration_days` / `remaining_days` | — | 35.0 / **25.0** (银行日 10 天带入, 与离线 est_days 口径一致 ✓) |
   | `available[]` | 含 GER_accelerate... | 该项消失 (已在进行中) ✓ |
   | `completed` | [GER_the_four_year_plan] | 不变 ✓ |
   第三证据 (UI): 顶栏政治点数 tooltip 里出现 **「加速军备重整计划 −1.00」**
   —— 正是该国策的 PP 修正, 说明游戏已把它当成"正在进行的国策"在跑
   (shots/day24_hover2.png)。**Phase I 主菜完成**。
- 顺带修 UI 驱动的老毛病: `SendInput` 打到前台窗口, 而**激活点击会被 Windows 吞掉**
  —— 第一次存盘链就是这样失败的 (点 ☰ 没开菜单, 后续点击落到地图上, 还误开了
  拉布拉多海地区面板)。修法: `SessionDriver.click(..., focus=True)` 先
  `focus_window(hwnd)`; 菜单行坐标实测微调 (载入 0.242 / 保存 0.286 / 关闭 0.649),
  存档对话框 保存 = (0.569,0.811), **覆盖确认 OK = (0.569,0.666)**;
  存盘前先把将被覆盖的存档复制成 `_backup_..._pre_focus.hoi4` (本次已备份)。
- 会话收工状态: pid 30944 存活、暂停、1936-09-19 06:00, 国策
  GER_accelerate_the_rearmament_program 进行中 (剩 25 天) —— 这是**真实进度**,
  用户如不想要可在国策树里点掉。

### ☆ 24 日补记: 命令表扩张的工具链与首批候选 (只到"候选", 未上真机)
用户收工前明确"先到这里", 所以这条线**只做到离线产出候选 spec, 没有加进
tables.py、没有真机验证**。记录方法与结果, 供下一轮直接接手。

1. **参考项目的做法值得抄**: `research/clausewitz_ref/calling/cmdauto.py` 从每条命令的
   **Describe 方法 (Linux 是 vtable+0xB8)** 反推**全部 370 条**命令的字段布局 ——
   Describe 会把每个字段按类型分派给 3 个日志辅助函数 (int/bool、CString* 对象名、
   内嵌对象), 于是"字段偏移+类型"直接读出来。Linux 侧表 (`tables/commands.txt`,
   373 行) 还带 CTOR/VTABLE 地址与 ARGS 个数, 是跨平台结构对照的现成真值。
2. **本平台已落地的工具** (`research/command_spec_hunt.py --full` +
   `research/spec_batch.py`): 一条命令走
   RTTI 类名 → vftable RVA → vtable 的 `lea` xref → **ctor 入口** (往回走
   `int3` 填充定位函数头) → ctor 的字段写 (含来源寄存器) → 调用点的
   `mov ecx,size; call operator new` (尺寸) → 参数用法 (deref/直接存/可空 test),
   并自动附上参考表的同一行做结构对照。
3. **首批候选 (Windows 1.19.3.0, 仅静态推导, 未验证)**:

   | 类 | vftable | ctor | size | 参考表 ARGS/字段(kinds) |
   |---|---|---|---|---|
   | CSetResearchCommand | 0x2994F40 | 0x11479C0 | 0x40 | 4 / deref,ptr,int,bool |
   | CDropCurrentNationalFocusCommand | 0x2996520 | 0x1144800 | 0x30 | 1 / deref |
   | CBypassNationalFocusCommand | 0x29965E8 | 0x1143AD0 | 0x38 | 2 / deref,ptr |
   | CSelectDecisionCommand | 0x2996908 | 0x1146970 | 0x38 | 2 / deref,ptr |
   | CSelectEventOptionCommand | 0x2938E60 | 0x1539E40 | 0xF0 | 4 / int,handle,deref,int |
   | CAddConstructionCommand | 0x2994770 | 0x1142A00 | 0x50 | 4 / deref,handle,field0x10,int |
   | CRemoveAllConstructionCommand | 0x2994900 | 0x1149920 | ? | 4 / - |
   | CAddProductionLineFactoriesCommand | 0x2994DB0 | 0x1143520 | 0x38 | 4 / handle,int |
   | CAddIdeaCommand | 0x2995328 | 0x1142AD0 | 0x40 | 4 / - |
4. **SetResearch ctor 逐条** (最想要的一条):
   `xor r10d,r10d` → base 字段 → `mov eax,[rdx]; mov [rcx+0x28],eax` (**rdx=&tag**) →
   `mov [rcx+0x30],r8` (**r8=科技对象指针**) → `mov [rcx+0x38],r9d` (**r9d=槽位**) →
   `movzx eax, byte ptr [rsp+0x28]; mov [rcx+0x3c],al` (**第 4 个参数在栈上**, bool)。
   字段 kinds 与参考表 deref/ptr/int/bool 一一对应 ✓ (偏移差 +4/+8, 与已知平台位移一致)。
   ⚠ **设计缺口**: 现在的 `ALLOC_CTOR`/`CALL_OBJ` 只传 3 个寄存器参数 (rdx/r8/r9),
   **传不了第 4 个栈参数** —— 下轮要先把"栈参数"加进载荷 (在私有栈上摆好
   `[rsp+0x20]` 起的位置), 否则 SetResearch 这类 4 参命令调不了。
5. **下轮接手顺序** (工具链已就位, 全部离线先行):
   ① 给 VM 加栈参数支持 (替身跑道验证) → ② 把候选 spec 逐条过 `specverify`
   (vftable 归属/ctor 装载/尺寸覆盖/字段覆盖) → ③ 只把**全绿**的写进 tables.py
   (verified=True, blob_ok 按字段覆盖判定) → ④ 替身跑道 → ⑤ 真机一发一验
   (首选 DropCurrentNationalFocus: 1 个参数、与已闭环的 SetNationalFocus 同族,
   最容易做存档 diff 验收; SetResearch 次之但价值最高)。
   ⑥ 想把表一次做全: 移植 `cmdauto.py` 的 Describe 思路到 Windows (先定位本平台
   的 3 个日志辅助函数, 再由 vtable 描述槽批量抽全部命令字段)。

### 下次清单 (按优先级, 24 日收工版)
1. 命令表扩张的第一批 (候选已离线备好, 见上一条补记): 先给 VM 加**栈参数**支持,
   再把 CSetResearchCommand / CDropCurrentNationalFocusCommand / CBypassNationalFocus
   Command / CSelectDecisionCommand / CSelectEventOptionCommand / CAddConstruction
   Command 等逐条过 specverify → 替身 → 真机; 想把表一次做全就移植
   `clausewitz_ref/calling/cmdauto.py` 的 Describe 抽取思路;
2. 把 `focus.available` 的 est_days 口径用本次 E2E 的实测再回归一遍
   (35 − 银行 10 = 25 天 ✓ 已对上), 并把 `post_focus_ctor` 接进 MCP 工具的
   live 校验流 (`hoi4_inject_post` 已在用 ctor 路径 ✓);
3. 静默退出复现与定性 (23 日遗留; 24 日两次死亡都是确定性 AV, 与它无关);
4. CGamePlaySettings 速度字节 diff → 速度脱离截图; CCountry 字段带对齐;
5. read 层的 live 化: 用 VM 的 CALL/READ 直接读国策进度/速度字节
   (不必存档, 也不再猜偏移) —— 写层已经把"任意已确认函数调用 + 读回"打通。

---

## 25 日·VM 载荷定案 (op 记录布局 + 引用解析) + 命令表扩张第一发 ★★

任务面: 接着 24 日的"命令表扩张"入手顺序走 ①栈参数 → ②specverify → ③写表 →
④替身 → ⑤真机。**结论先行的坏消息**: 栈参数没做出来(见"血案 4"),
但它**不需要**——在做的过程中把 VM 的 op 记录布局彻底查清并定案,
顺带把三个真 bug 修掉, 命令表也从 4 条扩到 5 条(DropCurrentNationalFocus)。

### ★★ 定案 1: op 记录的真实布局 (24 日遗留的错位根源)

`Op.pack` 按 `code + a0..a4 + RESULT + a5` 落盘, 于是**记录里的字段偏移**是:

| 名字 | 偏移 | 说明 |
|---|---|---|
| OP_CODE | 0x00 | op 号 |
| OP_A0 | 0x08 | 第一个操作数 |
| OP_A1 | 0x10 | 第二个 |
| OP_A2 | 0x18 | 第三个 |
| OP_A3 | 0x20 | 第四个 |
| OP_A4 | 0x28 | 第五个 |
| **OP_RES** | **0x30** | **载荷写回 RAX 的位置** |
| OP_A5 | 0x38 | 第六个 |

**a4 和 a5 之间夹着 RESULT** —— 24 日的载荷按 `a0..a5` 连续读,
每次读 a5 都拿到 RESULT, 于是"寄存器少一个/多一个"的怪象一路查不出来
(今天在这个坑里烧掉约 90 步, 记录在案)。

**修法(定案)**: 每条 op 的操作数按"自己那条"显式对齐:

- **op 1 (CALL)**: `a0=目标`, `a1` 不用, `a2/a3/a4/a5 = rcx/rdx/r8/r9`
  (rcx 先存 rbp——callee-saved, 载荷在 call 前用它恢复 rcx);
- **op 7 (ALLOC_CTOR)**: `a0=operator new`, `a1=ctor`,
  `a2/a3/a4 = rdx/r8/r9`, `a5 = size << 40`(size 借 a5 高 24 位,
  因为 a4 被 r9 占了);
- **op 8 (CALL_OBJ)**: `a1 = slot + 16*count`(槽位与显式参数个数挤一个操作数)。

### ★★ 定案 2: 引用(Ref)解析 —— 结果槽就是 RESULT 字段

`Script.call()` 返回的 `Ref` 不再需要单独的 scratch 区: **生产者的 RESULT 字段
(`page + op*OP_SIZE + OP_RES`)就是它的存储**。消费者把这个地址当参数传,
载荷在调用后已经写过 `[r13+0x30] = rax`, 于是零额外操作数、零额外内存。

- `read_ptr(addr)` 返回 `Ref(op, addr=buffer 偏移)`: 它的值是**局部缓冲区**,
  解析时给**绝对地址**(`page + addr`) —— 这正是 SetResearch 那类
  `ctor(this, rdx=&tag, ...)` 需要的 **`&value` 形状**;
- 因果性双向检查: 解析前查一遍(引用必须指向**更早**的 op), 解析时再查一遍
  (防止有人组装完再插 op);
- **`_resolve_refs` 现在只允许调一次**(`Script._resolved`): 因为它原地改操作数,
  调两次会把 page 再加一遍, 参数整体错位——今天大半天的"载荷读错操作数"
  冤案就是这个: **测试脚本自己先手工解析了一次, `run()` 又解析一次**。

### ★★★ 血案 4: 栈参数(5+ 参数)为什么没做成 (诚实的负面结果)

按 24 日缺口, 给载荷加了"参数 5..8 搬到 callee 的 home space"的路径。
替身跑道上 4 参全绿、5 参必死(进程直接消失, 不是打印错误)。逐层二分:

1. 独立 shellcode 里同样的"写 `[rsp+0x20]` 再 call"→ **全绿**
   (说明目标地址计算是对的: callee 自己的 `[rsp+0x28]` = 调用者的 `[rsp+0x20]`);
2. 同样的"写 + call"放进 VM → 载荷在 **store 指令上就炸**(breadcrumb 停在
   `mov [rdi], rax` 之前); `rdi`/`rsi`/`r10` 在炸前一刻都被读出来验证过:
   地址合法、计数正确、源数据在;
3. 换成显式展开的 4 条 `mov`(不再用 `rep movsq`)→ 一样炸;
4. 把栈顶从 0x7FF0 降到 0x4000(留 16KB 余量)→ 一样炸;
5. callee 自己往 `[rsp+0x20]` 写 → **没问题**(说明那段内存本身可写)。

**结论**: 载荷在**私有栈上写 callee 的 home space** 这条路存在未定性的问题
(没有排除 VEH/内核 APC 返回上下文与影子空间的交互)。因为:
- 命令表里最大的命令是 **4 参**(DropCurrentNationalFocus 1 参 / SetResearch
  "this+tag+tech+slot+bool" 里那个 bool 可以改成不传——CanExecute 不看它),
- 再花一个游戏进程去赌不值得,
所以 **API 直接拒绝第 5 个参数**(`Script.call` 抛 `ScriptError`),
载荷里的搬家代码全部删除(968B, 比 24 日的 1176B 更小)。
**负面结果也是结果**: 下次要碰它, 先解决"为什么 VM 里的栈写会炸",
而不是继续在替身上加场景。

### ★ 交付: 命令表 4 → 6 条 (DropCurrentNationalFocus + BypassNationalFocus)

- `research/command_spec_hunt.py --full DropCurrentNationalFocus` 给出
  `.?AVCDropCurrentNationalFocusCommand@@` / vftable 0x2996520 / ctor 0x1144800 /
  `ctor(this, rdx=&tag): mov eax,[rdx]; mov [rcx+0x28],eax` / 尺寸 0x30
  (UI 自己的 `mov ecx,0x30` 立即数), 参考表 ARGS=1 `deref`;
- `research/command_spec_hunt.py --full BypassNationalFocus` 给出
  `.?AVCBypassNationalFocusCommand@@` / vftable 0x29965E8 / ctor 0x1143AD0 /
  `ctor(this, rdx=&tag, r8=CNationalFocus*): mov eax,[rdx]; mov [rcx+0x28],eax;
  mov [rcx+0x30],r8` / 尺寸 0x38, 参考表 ARGS=2 `0x24:deref, 0x28:ptr` ——
  与本平台逐条对上(偏移 +4/+8 是已知平台位移);
- 两条都写进 `tables.py` (`verified=True`, `blob_ok=True`), 过
  `python -m hoi4_mcp.inject.specverify`: vftable 归属 ✓ / ctor 装载 vftable ✓ /
  尺寸覆盖 ✓ / 字段覆盖 ✓ / 调用点尺寸 ✓ (**表内 7 条全 OK**);
- `CommandLayer.drop_focus_ctor()` 走 ctor 忠实路径 —— **真机 E2E 已跑通** (见下);
  `bypass_focus_ctor(focus_obj)` 同形, **真机待验**;
- `research/spec_batch.py` 一次跑一批 (9 条候选) 并附参考表对照 —— 下一批
  (SetResearch / SelectDecision / SelectEventOption / AddConstruction 等) 的入口。

### ★★ 真机 E2E: DropCurrentNationalFocus 闭环 (25 日)

`research/live_drop_focus_e2e.py` (pid 20532, 暂停中, GER 1936-09-19):

1. guard: `log=singleplayer tcp_open=0 save_flag=False verdict=singleplayer`;
2. `&tag = gamestate+0x520 = 0x1589acbc9b0`, tag 值 1 (GER) —— **UI 传的就是这个地址**;
3. 一发 special user APC 走 ctor 路径:
   `posted=true`, `job_intact=true`, latency **178ms**, `status=0`, 游戏存活;
4. **存档 diff** (UI 存盘 → bin5 离线解析):

   | 字段 | 注入前 (`_backup_..._pre_drop.hoi4`) | 注入后 (`GER_1936_09_19_06.hoi4`) |
   |---|---|---|
   | `focus.current` | `GER_accelerate_the_rearmament_program` | **null** |
   | `remaining_days` | 25.0 | null |
   | `banked_days` | null | **10.0** |
   | `n_completed` | 1 | 1 (不变) |

   即: 正在跑的国策被丢弃, 已投入的 10 天回到银行, 完成数不变 —— 与"Drop"语义
   完全一致, 而且**没有任何 UI 点击**参与。

5. 附带证据: 存档由 `_temp` 改名落盘 (`GER_1936_09_19_06_temp.hoi4` 是对话框
   先写的临时名), 注入前的备份 `_backup_..._pre_drop.hoi4` 保留。

### ★ 替身跑道重排 (script_dryrun.py)

- **phase B**: 全 op + 全部故障模式(在一个受害者进程里); 新增
  "5+ 参数必须被拒 / 4 参必须进寄存器";
- **phase C**: 私有栈洪水(12KB 不碰 job / 24KB 必碰)与 ctor 深栈,
  **每个场景一个全新受害者** —— 因为洪水本来就会把该进程的 job 砸烂,
  和别的场景共用进程会把后面的用例全带崩(今天踩过);
- `read_ptr` 场景的记录偏移写错过一次(读到 rdx 当 rcx, 假红)。

**结果: phase B GREEN / phase C GREEN** (2026-10-18 12:4x, 见终端输出)。

### ★ 真机 E2E: DropCurrentNationalFocus 闭环 (25 日)

`research/live_drop_focus_e2e.py` (pid 20532, 暂停中, GER 1936-09-19):

1. guard: `log=singleplayer tcp_open=0 save_flag=False verdict=singleplayer`;
2. `&tag = gamestate+0x520 = 0x1589acbc9b0`, tag 值 1 (GER) —— **UI 传的就是这个地址**;
3. 一发 special user APC 走 ctor 路径:
   `posted=true`, `job_intact=true`, latency **178ms**, `status=0`, 游戏存活;
4. **存档 diff** (UI 存盘 → bin5 离线解析):

   | 字段 | 注入前 (`_backup_..._pre_drop.hoi4`) | 注入后 (`GER_1936_09_19_06.hoi4`) |
   |---|---|---|
   | `focus.current` | `GER_accelerate_the_rearmament_program` | **null** |
   | `remaining_days` | 25.0 | null |
   | `banked_days` | null | **10.0** |
   | `n_completed` | 1 | 1 (不变) |

   即: 正在跑的国策被丢弃, 已投入的 10 天回到银行, 完成数不变 —— 与"Drop"语义
   完全一致, 而且**没有任何 UI 点击**参与。

5. 附带证据: 存档由 `_temp` 改名落盘 (`GER_1936_09_19_06_temp.hoi4` 是对话框
   先写的临时名), 注入前的备份 `_backup_..._pre_drop.hoi4` 保留。

### 交付物 (25 日)

| 文件 | 变化 |
|---|---|
| `hoi4_mcp/inject/script.py` | op 记录布局定案(a2..a5=rcx/rdx/r8/r9, op7 a5=size<<40) / Ref→RESULT 槽 / read_ptr 绝对地址 / `_resolved` 单次解析 / 栈参数删除并拒绝(968B) |
| `hoi4_mcp/inject/tables.py` | +`DropCurrentNationalFocus` (verified) +`BypassNationalFocus` (verified) |
| `hoi4_mcp/inject/commands.py` | +`drop_focus_ctor()` +`bypass_focus_ctor()` |
| `research/apc_probe/script_dryrun.py` | phase B/C 重排 + 新场景 (全绿) |
| `research/apc_probe/_abi_check.py` `_readptr_check.py` `_manual_send.py` | 一次性真机替身探针(保留) |
| `tests/test_inject_script.py` | 25 用例: 布局/引用/拒绝路径/因果性/单次解析 |

### 下次清单 (按优先级, 25 日收工版)

1. **命令表继续扩**(每条: hunt → specverify → 表 → 替身 → 真机一发一验):
   - `SetResearch`: ctor `(this, rdx=&tag, r8=CTech*, r9d=slot, [stack]=bool)`
     —— **那个 bool 可以省略**(CanExecute 不看它), 于是 4 参数正好落在
     rcx/rdx/r8/r9 里; tech 指针用 `read_ptr` 从活体科技表拿;
   - `BypassNationalFocus`: **spec 已入表并过 specverify**, `bypass_focus_ctor()`
     已就位 —— 只剩**真机一发**(两参 `&tag` + `CNationalFocus*`, 与已闭环的
     focus 族同形, 最容易);
   - `SelectEventOption`: **弹窗全自动清理**的钥匙(4 参: int/handle/deref/int);
   - `AddConstruction`: 建造队列免 UI(4 参: deref/handle/field0x10/int);
2. 想一次做全表: 移植 `clausewitz_ref/calling/cmdauto.py` 的 Describe 抽取
   (24 日补记里有工具与候选, 370 条命令的字段布局可以自动抽);
3. 栈参数的未定性问题(血案 4): 若将来真需要 5+ 参命令, 先定"为什么 VM 里的
   私有栈写会炸"(建议对照实验: 在替身上摘掉 VEH、或用 CreateRemoteThread 的
   私有线程跑同一段载荷);
4. 读层 live 化(24 日遗留): 用 VM 的 CALL/READ 直接读国策进度/速度字节
   (不必存档, 也不再猜偏移) —— 写层已经把"任意已确认函数调用 + 读回"打通;
5. 静默退出复现与定性(23 日遗留); CGamePlaySettings 速度字节 diff;
   CCountry 字段带对齐。

---

## 26 日·进度复核 + SetResearch spec 定案 + 对象解析链定位 (写层扩张第 2 批) ★★

任务面: 接 25 日下次清单第 1 条(命令表继续扩, `SetResearch` 价值最高), 同时把
仓库自述的进度对着运行中的会话复核一遍。游戏 18:37 重启, pid 13596, GER 会话,
暂停, 队列门开, 玩家 tag=1。

### ★ 复核结论: 自述全部复现

| 项 | 结果 |
|---|---|
| `pytest -q` | 96 passed / 66.75s(入表 SetResearch 后 98 passed) |
| `python -m hoi4_mcp.inject.specverify` | 8/8 OK(新增 SetResearch 在内) |
| 载荷 import 期结构断言 | 过; `PAYLOAD` = **968 B**, 入口 0 |
| 身份链(只读 `research/_probe_now.py`) | gamestate/idler/gameapp 三槽实例 vftable 全匹配 |
| guard | `log=singleplayer tcp_open=0 save_flag=False verdict=singleplayer` |
| 工具面 | `@mcp.tool()` × 22 |
| 存档真值 | GER 1936-09-19 06:00; focus current=null / banked 10 / completed 1 / available 9; research 0 完成 0 在研 **131 可研** |

复核报告落在 `research/PROGRESS_REVIEW.md`。

### ★★ 定案 1: CSetResearchCommand 的 spec(逐条来自二进制)

`research/command_spec_hunt.py CSetResearchCommand --full --ctx 0x70`:

```
ctor 0x11479C0 (size 0x40, UI `mov ecx,0x40`):
  xor r10d,r10d ; BASE 初始化(+8/+0xC/+0x10/+0x14/+0x18/+0x1C, 与 BASE_INIT 逐条一致)
  mov eax,[rdx]              ; rdx = &tag
  mov [rcx+0x28],eax         ; +0x28 tag (VALUE, UI 传 &tag)
  movzx eax,byte [rsp+0x28]  ; 第 5 个参数在【栈】上
  mov [rcx+0x3c],al          ; +0x3C bool
  mov [rcx+0x30],r8          ; +0x30 CTechnology*
  mov [rcx+0x38],r9d         ; +0x38 slot(0-based)
  ret                        ; 无外部调用、无 std::string 成员
两个 UI 调用点: 0x2ABB6B(遍历 {tech*,slot,flag} 数组, stride 0x10, 重放研究单)
与 0x13DB4AD(AI 规划: 槽 = [rcx+0x40], tech = [r15+0x160], &tag = 栈上局部)
```

参考表(Linux)同一行 `0x24:deref,0x28:ptr,0x30:int,0x34:bool` —— 字段种类与顺序
逐条对上(偏移 +4/+8 是已知平台位移)。**已写入 `tables.py`**(`verified=True`,
`blob_ok=True`), specverify: vftable 归属 ✓ / ctor 装载 ✓ / 尺寸覆盖 ✓ /
**字段覆盖完整**(11 处 ctor 写全覆盖)。

### ★★ 定案 2: CanExecute 语义(vtable +0x48 = 0x1166BC0)

```
add rcx,0x28 ; call 0xBB48F0 ; call 0x6CFCB0   ; &tag -> country -> tech manager
rdi = manager(CTechnologyStatus)
eax = cmd[+0x38] ; js fail ; cmp eax,[rdi+0xAC] ; jge fail   ; 槽位界限 = 研究槽数
cmp dword [cmd+0x28],0 ; jle fail                            ; tag 必须 > 0
0xED8F00(manager, tech, 0) 必须为真                           ; CanResearch
cmp byte [cmd+0x3C],0 ; je ...                               ; flag=1 时额外读 tech[+0x520]
```

### ★★ 派生的对象解析链(游戏自己的访问路径)

```
0x6CFCB0 = `mov rax,[rcx+0xF60]; ret`        ; country -> CTechnologyStatus
0xED5080(manager, tech):
    id = tech[+0x38]  (1-based)
    id-1 < manager[+0x94] 否则 NULL
    return manager[+0x88][id-1]
```

实测(pid 13596): `country=0x26ed401d090` → manager `0x26ed3966a00`
(vft **0x2974FA0 = .?AVCTechnologyStatus@@**), `[+0x88]` 数组 **552** 项、
`[+0x94]` = 552、`[+0xAC]` = **4**(GER 研究槽数, 与 CanExecute 的界限检查一致)。
数组元素间隔 `0x200`, 全部 vftable = 0x2974EE0(**CTechnology**, 已用
`research/_vft_identity.py` 从 COL/TypeDescriptor 直接验名, 不是 rtti.json 转述)。

### ★ 反证: vftable 扫描不是身份判据(方法论)

- 全内存扫 CTechnology vftable 得 **243,289** 个"实例" ≈ **440 国 × 552** ——
  即每国一份的实例数组; 其中 GER 那 552 个是**只有 vtable、字段全 0 的空壳**
  (`+0x30..+0x44` 全 0), 因为该档 GER 从未研究过任何科技(存档 side 亦是 0 完成)。
- 带可读 `std::string` 的只有 **380** 个(100 个不同名字), 它们**不在**玩家数组里、
  也**不**与 country 有指针互指; 其 `+0x38` 是 3/6/7/8/9… 的小整数, 名字是
  `cas`/`cv_cas`/`anti_air`/`artillery`/`light_armor` 这类 **sub-unit 风格**。
  → 同一个类的实例可以分成完全不同的种群, **扫 vftable 只能得到"候选集合",
  不能当身份**(这条对以后的 live 读层同样适用)。
- 因此 `SetResearch` 缺的**不是写通道**: spec 与发布路径都就绪, 缺的是
  "科技名 → 那个带正确 id 的活体 CTechnology*"。

### ★ 绕开"血案 4"的第一个工程解(5 参命令走 blob)

SetResearch 是命令表里第一条**第 5 个参数在栈上**的命令。VM 载荷没有栈参数通道
(25 日定案), 但该 ctor 的 11 处写全部落在 `BASE_INIT` + 4 个字段里, 于是
**blob 路径反而更强**: 它把 `+0x3C` 显式写成 0, 不必依赖私有栈里的残留值。
新增 `CommandLayer.post_research(tech_obj, slot, *, tag=None, flag=0)`。
口径: **"命令对象一律走真 ctor" 的例外条件 = specverify 报"字段覆盖完整"**,
此时 blob 逐字段可复现 ctor 输出; 不满足就仍走 ctor。

### ★★ 真机部分(26 日): 替身跑道 → 只读验证发 → 写通道一发一验

**① 替身跑道先跑**(纪律): `python research/apc_probe/script_dryrun.py` —
phase A(无盾必死: `null-in-callee` 让 victim 以 0xC0000005 退出)✓;
**phase B GREEN**(全 op + 全故障模式, 含 `fault inside callee` = 调用目标内部 AV
被盾接管)✓; **phase C GREEN**(12KB/24KB 私有栈洪水 + 深栈 ctor)✓。

**② 真机只读验证发**(`research/live_research_probe.py`, 新): 一次投递里对 3 个候选
对象调用游戏自己的访问器 `0xED5080(manager, tech)` 与 `0xED8F00(manager, tech, 0)`。
结果: `0xED5080` 用 `id=11` 的候选**返回了真实例** `0x26ed3ba28f0`(id → array[id-1]
语义坐实); 但 `0xED8F00`(CanResearch) **在游戏函数内部 AV**(rip 0xAD1E59,
`call qword ptr [rax+0x18]`, `rax=[rdi+0x48]` 是垃圾指针), **VEH 盾当场接管并恢复**
(status=2 / job_intact=True / 游戏存活 / 暂停位不变)—— 盾第一次在真机上接住
"我们自己代码之外"的 AV。

**③ 候选面与过滤**: `research/_tech_def_filter.py` 给全部 243,287 个实例加
"`id∈1..552` ∧ `[obj+0x48]` 是镜像内代码地址" 过滤 → 只剩 **2 个**(id 都是 257)。
map-only 复验 6 个候选(`research/_research_cand_probe.py --map-only`)全部映射成功、
status=0:

| 候选 | id | [obj+0x48] | 映射到的实例 |
|---|---|---|---|
| 0x26f12fbf2b0 | 257 | 0x7ff70ad385f0(镜像内) | 0x26ed3bc1af0 |
| 0x26f12fc04b0 | 257 | 0x7ff70b6a5170(镜像内) | 同上 |
| 0x26ebee5ddf0 `light_armor` | 11 | 0x7ff7d2c2a397(**非镜像**) | 0x26ed3ba28f0 |
| 0x26f17db72a0 `anti_air` | 8 | 非镜像 | 0x26ed3ba32f0 |
| 0x26ec0b210a0 `artillery` | 9 | 非镜像 | 0x26ed3ba3cf0 |
| 0x26ebee925f0 `artillery_brigade` | 17 | 非镜像 | 0x26ed3ba2ef0 |

**④ 结论(负面结果, 有证据)**: 26 日下次清单第 1 条的路线①"用 VM 调
`0xED5080/0xED8F00` 做只读验证"**被证伪为不可靠** —— `0xED8F00` 在 APC 线程的
语境里对每个候选都 AV(第二个现场 0x24BDB84: `mov rax,[rcx+8]; mov eax,[rax+8]`,
即链上某个对象的 +8 为坏指针), 说明它依赖的上下文/对象初始化程度超出我们手上的
候选。**剩下的可行路线是②**: 从游戏自己的 UI/AI 结构里取真值
(研究面板 item `{tech*, slot, flag}` stride 0x10; 或 0x13DB4AD 的 `[r15+0x160]`)。
附带确认: 命令要的 `tech` **只用来取 id**(`0xED5080` 纯按 id 索引, 与对象种类无关),
所以真正缺的是"名字 ↔ id"的对应, 而不是"哪一类对象"。

**⑤ 写通道一发一验(真机, 26 日)**: `python research/live_speed_e2e.py --direction up`
→ `IncreaseGameSpeed` 走 ctor 路径 `posted=True / status=0 / job_intact=True /
latency 17ms / ran_on=20400(parked)`; 速度 pips 条第 5 格 **dark(53) → grey(67,66,47)
(亮起)**; 随后 `--direction down` → `posted=True / 7ms`, 第 5 格 **回到 dark(53)**,
与作业前完全一致(游戏暂停中, 时间未推进, 存档未改)。两条独立命令、两次投递,
零 UI 点击。

### ★ 顺手修掉的债

- `mcp_server.hoi4_inject_post` 原先只给 `SetNationalFocus` 装参数, 于是
  `Drop`/`Bypass` 会以 **NULL &tag** 调 ctor(VEH 盾会兜住, 但那是浪费一发):
  现按命令分派参数, 并对 SetResearch 明确拒发 + 给出替代路径。
- `inject/script.py` 顶部 op 文档仍描述 25 日已删掉的栈参数通道 → 改成定案口径。

### 一次性探针(保留, 全程只读 RPM)

`research/_probe_now.py`(会话身份链) / `_rtti_lookup.py`(RTTI 类查询) /
`_vft_identity.py`(COL→类名, 权威验名) / `_tech_scan_probe{,2,3,5}.py`(实例扫描与
名称提取) / `_tech_db_probe.py`(数据库单例) / `_tech_defprobe.py`(定义-实例假设) /
`_tech_owner_probe.py` / `_country_tech_probe.py` / `_country_tech_table.py` /
`_tech_mgr_probe.py` / `_tech_defid_probe.py`(解析链与 id 字段)。

### 下次清单(26 日收工版)

1. **SetResearch 的"名字 → 对象"**(唯一剩余缺口), 两条路线:
   ① 用 VM 调 `0xED5080`/`0xED8F00` 对候选指针做**只读**验证(坏指针由 VEH 盾兜住,
      进程不死), 先确认"哪一类对象能被 CanResearch 接受";
   ② 从研究面板 item(`{tech*, slot, flag}` stride 0x10)或 0x13DB4AD 的
      `[r15+0x160]` 取游戏自己用的真值, 反查该对象的种群。
2. **BypassNationalFocus 真机一发**(spec 已入表 + specverify 绿, 与 focus 族同形)。
   **玩家等价性已证**: 本地化里存在 `BYPASS_FOCUS = "Bypass"`(UI 上的 Bypass 动作)、
   `BYPASS_FOCUS_TRIGER`("The following will bypass the focus")、`BYPASS_EFFECTS`、
   `FOCUS_CANNOT_BYPASS`("Cannot bypass a focus while a mutually-exclusive focus is in
   progress") —— 即玩家点得出来, 不是纯内部命令; GER 树(`common/national_focus/
   germany.txt`)有 114 处 `bypass = {` 块可选靶。
3. 血案 4 对照实验(摘 VEH / CRT 私有线程跑同段载荷) —— 只有真要 5+ 参命令才动。
4. `git init` + 首次提交(仓库目前无版本控制, 见 PROGRESS_REVIEW §4)。
5. 读层 live 化(24 日遗留): VM 的 CALL/READ 读国策进度/速度字节。

