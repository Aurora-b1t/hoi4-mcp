# hoi4-mcp

给外部 Agent(如 Claude/ZCode)提供一个 **Hearts of Iron IV 1.19.3.0** 的 MCP Server:
观察游戏状态,并像正常玩家一样操作游戏(暂停/调速/存档/装载/地图操作)。
**不使用控制台 cheat,不写作弊数值。**

**命名对照**(项目名 = 仓库名 = `hoi4-mcp`):

| 位置 | 名字 |
|---|---|
| 仓库 / pip 发行包 | `hoi4-mcp` |
| Python import 包 | `hoi4_mcp` |
| MCP 工具前缀 | `hoi4_*`(如 `hoi4_state`、`hoi4_inject_post`) |
| 命令行入口 | `hoi4-server` / `hoi4-selftest` |
| 本地数据目录 | `~/.hoi4_mcp/`(截图与点击录制) |

> 本项目原名 **hoi4-copilot**;更名后仓库为 `hoi4-mcp`,代码与文档里的包名同步
> 改为 `hoi4_mcp`,工具名(`hoi4_*`)与命令行入口保持不变。
> 本地 checkout 目录叫什么与项目名无关(`pip install -e .` 在仓库根执行即可)。
**v2/v3 方向(参考 Clausewitz-MCP)**:读 = 进程内存直读(实时、不暂停),写 =
CSession::Post 命令注入(玩家点击的同一队列),投递用 **special user APC**(23 日
起,见下);截图/SendInput UI 模拟降级为测试期用具。
> 23 日更正:**22 日"10-14 Windows 更新封锁了跨进程执行"的定案作废** —— 那是把
> `GetProcessMitigationPolicy(UserShadowStack)` 的 **4 字节** 返回值按 8 字节读,
> 于是把 bit 8 (`CetDynamicApisOutOfProcOnly`) 当成了 bit 2
> (`SetContextIpValidation`)。victim 五原语矩阵当日重测全绿 (graft /
> CreateRemoteThread→私有 RWX / CRT→LoadLibraryW / QueueUserAPC /
> QueueUserAPC2),细节见 `research/NOTES.md` 23 日。

> 免责声明:本项目对目标进程进行 ReadProcessMemory(读)与进程内命令注入
> (WriteProcessMemory/CreateRemoteThread,v2 主写路径);SendInput UI 模拟
> 降为测试用具。仅供单人游戏自动化研究,请勿用于多人游戏,使用风险自负。

## 安装

前提:Windows x64、HOI4 v1.19.3.0(见仓库内 pinned 版本表 `hoi4_mcp/tables/generated/`)、
Python 3.12。

```powershell
git clone https://github.com/Aurora-b1t/hoi4-mcp
cd hoi4-mcp
pip install -e .
```

游戏安装路径自动识别(`D:\Steam\steamapps\common\Hearts of Iron IV` 等候选),
也可写环境变量 `HOI4_INSTALL=D:/你的路径/Hearts of Iron IV`。

> 仓库内容边界:证据截图(`shots/`、`research/shots/`,约 700MB)与 agent 会话转储
> (`research/_session_dump/`)不入库,只在本机留存;清单见 `.gitignore`。
> 因此文档里引用的 `shots/*.png` 是本地取证路径,不是仓库文件。

## 启动 MCP Server(stdio)

```powershell
hoi4-server          # 或 python -m hoi4_mcp.mcp_server
```

接线示例(zcode-mcp.json / Claude Desktop 风格):

```json
{ "mcpServers": { "hoi4": { "command": "python", "args": ["-m", "hoi4_mcp.mcp_server"] } } }
```

> 仓库里的 `zcode-mcp.json` 是本机在用的样例:其中 `cwd` 指向本地 checkout 目录
> (名字随意,只要求该目录下有 `hoi4_mcp/` 这个包);`args` 里的模块名才是项目名相关项。

## 工具面 (v1 18 个 + v3 inject 4 个 = 22)

| 工具 | 作用 | 备注 |
|---|---|---|
| `hoi4_game_info` | 进程/版本/表兼容性 + **会话守卫(guard)结论** | 版本不符时读层表过期; guard 行 = log/TCP/存档三源 |
| `hoi4_hud(kind)` | 截图: full / topbar / date / small | DPI 感知 + 不抢焦点置顶抓屏 |
| `hoi4_state()` | **状态字形分类**（‖/▶ 列轮廓）判定+日期面板裁图 | 拿不准返回 unknown, 以回执截图为准 |
| `hoi4_pause_toggle()` | 点暂停/继续按钮后回读状态 | 鼠标等价, 不走键盘(IME 干扰) |
| `hoi4_set_speed(n)` | 调速 1..5(置底再加速,尽力而为) | 事件自动暂停会干扰, 回看截图校准 |
| `hoi4_click(x, y)` | 在客户端归一化坐标发生一次真实点击 | 通用 UI 驱动(选国策/派兵等都可点) |
| `hoi4_hover(x, y)` | **悬停不点击**+回执截图(20 日) | tooltip 读取原语: 人力 0.300/稳定度 0.155/工业 0.353 @(x,0.024) |
| `hoi4_save()` | 走游戏菜单存档(预填文件名) | 返回新建 `.hoi4` 文件名 |
| `hoi4_load(save, confirm)` | 走游戏菜单装载存档(confirm=false 半程核对) | 行序=hoi4_saves 同序; 见坐标表 |
| `hoi4_saves(filter)` | 列出存档+解码头部(玩家/意识形态/日期) | 纯离线读档目录 |
| `hoi4_dismiss(kind)` | 关覆盖层: `menu`=主菜单自带关闭钮; `outside`=外点关面板 | 二者行为不同, 见分述 |
| `hoi4_date()` | 内存 CGameDate 簇证据(活钟日期候选) | 全 RW 扫描 ~25s; 能列候选,活值靠 HUD 截图裁决 |
| `hoi4_instances()` | RTTI 实例计数(会话指标) | 全内存扫,约 1-3 分钟 |
| `hoi4_world_state(save)` | 439 国摘要(玩家/日期/PP/稳定度/…) | 离线解析存档 |
| `hoi4_country_detail(save, tag, secs)` | 单国语义细读(pol/research**+avail**/prod/**construction**/res/units/**师名重建**/diplo/decisions/**focus+可用清单**/fuel/mp/**chars**/**theatres**) | 离线, 数字与 UI 对表 |
| `hoi4_popup(recall)` | **事件弹窗证据套件**：icon 复核+全屏/日期/弹窗区裁图; recall=N 复读最近 N 张已存截图 | 无通用关闭坐标——读图后自行 hoi4_click 选项 |
| `hoi4_record(action)` | 点击序列录制 start/stop/status → JSONL | **start 时并存起点帧截图**, 供 replay 前置校验 |
| `hoi4_replay(path, speed, force)` | 按原 dt 重放录制的点击序列 | **点前先比当前帧 vs 录制起点帧**(diff>8 拒,force 豁免) |

### v3 inject 组 (24 日: ctor 忠实路径 + 微 VM 载荷 + 崩坏护盾)

| 工具 | 作用 | 风险标注 |
|---|---|---|
| `hoi4_inject_status()` | 注入层身份链/队列门/暂停位/策略位解码/v3.0+v3.1 两条通道状态 (无 UI、无存档) | 只读安全 |
| `hoi4_inject_speed(delta)` | **CIncrease/DecreaseGameSpeedCommand** 走真 ctor → CSession::Post (玩家同通道; ±1/±2), 每发一条 special user APC | 实测可用: HUD 速度 pips 视觉复核 ✓; 游戏自己拒绝时 posted=False (CanExecute 活着) |
| `hoi4_inject_post(command, focus, focus_id)` | **(25 日)** 单条命令投递, **对象由游戏自己的构造函数建立** (`operator new` → 真 ctor → `Post`); SetNationalFocus 收名字/id (内部解析成活体 CNationalFocus 指针), **DropCurrentNationalFocus** 只收 tag (内部用 `&tag`) | 与 UI 点击同队列; 读 `job_intact`/`status` 判断该发是否干净; 未验证 spec 直接拒发 |
| `hoi4_focus_ids(prefix)` | (22 日) 只读重建 SetNationalFocus 的 focus 数字 id↔名映射 — CNationalFocus 实例 (+0x08 id / +0x18 MSVC 串)。GER_ 前缀 438 条, 全库 10,668 | 只读安全 (~20s vftable 扫描) |

**写通道原理 (25 日定案)**:两条通道, 都用 `QueueUserAPC2` +
`QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC` 把载荷投到**游戏自己的线程**上 ——
不挂起任何线程、不新建线程 (新线程没有游戏的线程局部状态), 载荷在该线程的 TLS
语境里跑, APC 返回后 ntdll 用 NtContinue 原样续跑。
- **v3.0 (`inject/apc.py`, 23 日)**: 固定载荷 = `operator new` + 拷 blob + `Post`。
  只适用于「blob 字段覆盖 ctor 全部写」的命令 (现在表里用 `blob_ok` 标注)。
- **v3.1 (`inject/script.py`, 24 日; 25 日定案)**: 微 VM 载荷 (968B, keystone 汇编),
  一次投递可跑一串内存操作: `CALL` / `READ` / `WRITE` / `WRITE_RAW` / `MEMSET` /
  **`ALLOC_CTOR`**(new + 真 ctor) / **`CALL_THIS`**(rcx=刚建的对象 → 即 Post)。
  命令对象一律走 `ALLOC_CTOR`, 因为**字段布局只有 ctor 说了算**。
  另带 **VEH 崩坏护盾**: 只接管 ①载荷 arena 内的 fault ②payload 在飞时的空页野跳
  (`call 0`), 改写 CONTEXT 跳到 recover stub, 进程不死; 其它异常一律放行给游戏。
  **op 记录布局**: `[code, a0, a1, a2, a3, a4, RESULT, a5]` —— **a4 与 a5 之间夹着
  RESULT**; `CALL` 读 `a2..a5 = rcx/rdx/r8/r9`, `ALLOC_CTOR` 读 `a2..a4 = rdx/r8/r9`
  且 `a5 = size<<40`。**引用(Ref)的存储就是生产者的 RESULT 字段**; `read_ptr`
  给出局部缓冲区的绝对地址(SetResearch 那类 `ctor(..., rdx=&tag, ...)` 的 `&value`
  形状)。**一次投递 = 一次 `_resolve_refs`**(`Script._resolved` 守住; 重复解析会把
  page 加两遍, 参数整体错位 —— 25 日查了大半天的"载荷读错操作数"就是这个)。
  **栈参数(5+ 参)不支持**: `Script.call` 拒绝第 5 个参数(见 NOTES 25 日"血案 4")。
  **上真机前必须先在替身跑道全绿**: `research/apc_probe/script_dryrun.py`
  (三相位: 无盾必死 / 全 op + 全故障 / 私有栈洪水)。

**命令 spec 必须离线验证 (24 日新纪律)**:`python -m hoi4_mcp.inject.specverify`
检查 ①vftable 属于该命令的 RTTI 类 ②表里的 ctor 真的装载这个 vftable ③对象尺寸
覆盖 ctor 的每一次写 ④`blob_ok=True` 仅在 blob 字段覆盖全部 ctor 写时成立。
24 日血案就是 ①的缺失: 21 日把 **CSetFuelPriorityCommand 的 ctor 当成了
SetNationalFocus 的**, 手搓 blob 于是 vtable 对、字段全错 → 游戏 AV 死亡
(0xc0000005 @ 0x24c2f0d)。现在未验证的 spec 写层**直接拒发**。

### 安全层 (19 日)

- **仅单人盟约强制**: 9 个写工具(含 replay/record/hover)全部过 `_write_refusal()`:
  ① `HOI4_READ_ONLY=1` → 一律拒; ② 三源守卫(`hoi4_mcp/safety.py`)判出
  多人会话(game.log `[[ Launching MULTIPLAYER-game ]]` / hoi4.exe 活 TCP 连接 /
  存档 `multiplayer` token) → 拒, `HOI4_ALLOW_MP=1` 为开发者显式豁免。
- 守卫证据随时可查: `hoi4-selftest guard`。
- 命令队列日志小发现: 游戏自带 `logs/{posted,sent,received,executed}_commands.log`
  —— CCommandQueue::Post 攻坚 (路线图#4) 的官方参考文本。(20 日实测: SP 会话
  四乎全空, 非空样本要 MP 会话或 -debug 才有)

### 离线读层 (不碰游戏, 存档即数据)

| 模块 | 能力 |
|---|---|
| `saveparse.bin5` | HOI4bin5 语法层递归解析器(1.8M 语句/档, 全档吃满) |
| `saveparse.tokens` | save-key id→名注册表(10763 条, 从运行时镜像提取, `python -m hoi4_mcp.saveparse.tokens` 重建) |
| `saveparse.saveinfo` | 存档头部快解: 玩家/意识形态/难度/**日期**(`date = 60759359 + 1936-01-01 起游戏小时`, 无闰年历法) |
| `readstate.country_sem` | 单国语义提取器(14 区块; 数值口径: 0x000D=/1e5、0x0167=/1e6 定点、party%/1e5 直接是百分比) |
| `readstate.global_tables` | 全局 join 表: 装备 archetype(生产线/库存 id→名)、师模板名、自定义变体名、角色名(12545 角色) |
| `readstate.techdata` | common/technologies 解析: research_cost/start_year/**leads_to 前置图** → 在研科技 invested_days + **avail 可研推导**(SP 门槛/隐藏/国别三重过滤) |
| `readstate.focusdata` | (20 日新增) common/national_focus 解析: focus id/cost/**prerequisite OR-block 前置图**/mutually_exclusive/available 触发标记 → **可用国策推导**(树归属按存档 focus_tree↔tag 映射过滤) |
| `selftest` | `hoi4-selftest token-scan`、`hoi4-selftest save-info`、`country-detail <path> [tag]` |
| `research/bin5_render.py` | 语义树渲染 + 双档差分(8 游戏小时档 diff=92 个语义键) |
| `research/find_vft_refs.py` | (24 日) vtable xref 扫描: 找出装载某个 vftable 的 ctor/工厂与 UI 调用点 |
| `research/command_spec_hunt.py` | (24 日) 命令 spec 猎人: RTTI vftable + ctor 入口(含 `--full` 参数用法推导) + `operator new` 尺寸 + UI 调用点上下文 |
| `research/spec_batch.py` | (24 日) 批量跑 spec 猎人, 并附参考项目(Linux)表同一行做结构对照 — 命令表扩张的入口 |
| `hoi4_mcp/inject/specverify.py` | (24 日) spec 离线校验器 (RTTI/ctor/尺寸/字段覆盖), 未过验证的命令写层拒发 |
| `tests/` | (25 日) pytest 回归套件 **96 用例**: bin5 配平/saveinfo 日期/守卫三源/synthetic MP token/focus 树解析+avail/country_sem 语义/techdata 图/inject 表静态检查/APC+VM 载荷字节级断言(op 记录布局·引用解析·因果性·单次解析)/命令 spec 对二进制验证 |

读状态的黄金路径(两条):
1. **快**:暂停 → `hoi4_save()` → `hoi4_country_detail('latest', tag)` 存档闭环;
2. **细**:暂停 → `hoi4_hud('all')` 截图读顶栏 → `hoi4_click` 逐面板导航 →
   tooltip 数值拆解用 `hoi4_hover(x, y)`(悬停不点击)。

**选国策工作流(20 日起全自动)**: `hoi4_country_detail(..., sections='focus')` →
读 `current/remaining_days`(在研剩余天) + `available[]`(现在就能排的国策,
带 cost/est_days/前置/GATED 标记) → UI 点国策树图标选一个 → 复核。
口径: duration=cost×7 天(defines FOCUS_POINT_DAYS); 无选中时进度字段=银行日
(上限 10, MAX_SAVED_FOCUS_PROGRESS), 选中国策瞬间带入 → est_days 已扣。
GATED 行带不可离线求值的 available 触发器——选前 UI 复核一眼。

## 关键坐标(客户端归一化; 17 日补充校准, 客户区映射)

- 日期面板:调速- `0.759,0.024`、暂停/继续 `0.776,0.024`、调速+ `0.897,0.024`
- **政治面板 = 顶栏稳定度图标 `0.155,0.024`**(第二排没有政治!);
  稳定度 tooltip(基础值+修正)悬停即出
- 第二排图标(y=0.095):阵营 `0.089`、决议 `0.1205`、情报 `0.1615`、
  科研 `0.19-0.227`、国际市场 `0.261`、**建造 `0.331`**、生产 `~0.361`
- 游戏内菜单(☰ 在 `0.978,0.024`):载入 `0.502,0.257`、保存 `0.502,0.30`、关闭 `0.502,0.660`
  - **24 日实测微调** (菜单行中心): 载入 `0.242`、保存 `0.286`、关闭 `0.649`;
    **点击前先 `focus_window(hwnd)`** —— SendInput 打到前台窗口, 而激活窗口的那一下
    会被 Windows 吞掉 (24 日存盘链第一次失败的真因); `SessionDriver.click(..., focus=True)`
  - 存档对话框:「保存」`0.569,0.811`;**覆盖确认框 OK `0.569,0.666`**(覆盖前先手工备份存档)
- **载入对话框(18 日 live 重标)**:列表首行 `0.45,0.382`、行距 `0.066`(6 行全可见,
  不滚动);「载入游戏」`0.567,0.810`、「返回」`0.449,0.810`;行序=mtime 倒序
  (= hoi4_saves 顺序);悬停行出详情框(文件名/日期/多人=否)可作核对证据。
  ~~旧表 首行`0.115,0.393`/行距0.07/开始`0.876,0.942` 系误测,勿用~~
- 主菜单(非会话):单人 `0.498,0.196` → 载入 `0.498,0.387`
- **窗口漂移保护**:`ensure_onscreen` 在 SessionDriver 初始化时把越出虚拟屏的窗口
  平移回来(OS 级,玩家拖窗等价);截图右侧黑带 = 客户端出屏,先修位置再操作
- 地区/省面板(点地图省名弹出)标题栏 X:`0.335,0.205`
- 大西洋安全空点(外点关闭紧张度类面板):`0.030,0.900`
- **顶栏人力 tooltip 悬停 (0.300, 0.024)**(move 不点击): 可征召% / 兵役法
  名义值 / 剩余人力同框; `0.353` = 工业经济 tooltip(军民工厂占用)
- **事件弹窗(19 日实弹)**: 无通用关闭坐标! 两类已知布局——
  - 条约类(单钮): 盒 x 0.316-0.685 / y 0.258-0.733, 「好的」`(0.499,0.685)`
  - 通知类(双钮): 盒 x 0.332-0.708 / y 0.306-0.606, 「详情」`(0.398,0.577)`,
    「好的」`(0.642,0.577)`; 弹窗逐个排队, 处理完一个立刻浮下一个
- 状态字形 ‖/▶ 图标 patch 中心 `(0.773, 0.022)`(icon_state 分类用);
  日期数字带(参考投票) `(0.787,0.010)-(0.885,0.042)`, 旧带
  `(0.800,0.048)-(0.888,0.078)` 是 1295x837 小窗时代的值, 大窗勿用

> 坐标框架已统一:点击映射与截图都按 **客户区矩形**(GetClientRect+ClientToScreen)。
> 旧表里 `y=0.059/0.062` 的值是窗口系(含标题栏)净值,勿再使用。
> **窗口尺寸变了坐标表就可能漂**: 19 日窗口从 1295x837 小窗变回 1920x1200
> 无边框,日期数字带即失效一次——先抓一张 full 截图核对再引发坐标。

## 架构

```
外部 Agent (MCP client) ⇄ hoi4_mcp.mcp_server (stdio)
   ├─ 读: tools/screenshot (DPI感知/TOPMOST/PrintWindow→mss 兜底)
   │      process/attach + rtti + instances (ReadProcessMemory 实例索引, 只读安全)
   │      runtime_state.read_date (CGameDate vftable 扫描 → 日期候选)
   ├─ 离线读: saveparse/bin5 + tokens(10763 键名) + saveinfo(头部/日期解码)
   │          存档即全局状态: hoi4_save() 落盘 → saveinfo/bin5_render 离线破译
   │          techdata + focusdata: common 数据盘 → 可研科技/可用国策前置图推导
   ├─ 写(v2 主路径): inject/ 命令注入 — CSession::Post(玩家点击同一队列,
   │      CanExecute 校验照常生效); 主线程劫持原语(挂起全线程→只 graft
   │      RIP∈镜像的冻结线程→轮询→还原); **21 日速度命令真机闭环 ✓**
   │      (fused 单冻结窗 new+拷贝+Post; 同会话 2+ 发概率性死亡→一令一会话)
   ├─ 写(测试用具): ui/session + ui/menu (SendInput 鼠标真实点击 = 玩家等价)
   │      recorder 起点帧校验; hover 原语(topbar tooltip 读取)
   └─ 数据: tables/generated (rtti.json 18k 类; tokens.json 10763 存档键名; offsets 待补)
```

核心安全观(v2):读 = RPM 直读(不暂停、无副作用);写 = 命令注入走玩家点击的
同一队列,游戏自身 CanExecute 合法性检查照常生效——Agent 依然做不出
「玩家点不出来的操作」;但句柄类型混淆/未验证地址会崩游戏,注入只走反汇编
确认过的地址表 + handle 白名单。多人检测 & read_only 锁对两条写通道同时生效。

## 已知边界 / 废话

- **军队编组不在存档里(20 日定案)**: 全档无 army 级序列化体(10834 个
  `army={` 命中全在 character_manager 头像区),军显示名("1. Armee")更不在;
  战区体直接挂师句柄。师个体标识 = `division_name.name_order` 序号 →
  units 区块已重建显示名("1. Panzer-Division" / "18. Strelkovaya Diviziya" 双文化
  实证)。军级指挥链就到 theatres:theatre→division 为止,再多要 live UI 或
  CArmy 实例遍历(写层增强,另议)。

- 键盘输入(Space 切暂停)因 IME 吞键不生效 → 一律鼠标点击。
- PrintWindow 对 HOI4 的 DX11 交换链恒黑 → mss 抓屏兜底(需要游戏不被完全遮挡)。
- 事件弹窗会自动暂停并遮挡 UI,且**无通用关闭坐标**(19 日实弹定案):
  `hoi4_popup()` 取证据,读图后点选项;**弹窗逐个排队**,点完一个还会浮下一个。
- `is_running()` 以**状态字形分类**(‖/▶ 列轮廓)为主判据:日期带像素投票会被
  横幅动画污染(暂停时也在动)、窗口尺寸变化也会让旧校准失效;拿不准一律 unknown
  并以截图复核。game.log 不记录暂停切换(只有 Launching 会话类型)。
- 每次游戏更新都会使偏移表过期:`rtti.json` 走 `hoi4-selftest rtti-scan` 重扫,
  **tokens.json 走 `hoi4-selftest token-scan` 重扫**(表在镜像运行时空洞,必须
  游戏在跑才有,磁盘上没有;majors: 节点步长 0x48, 长名串指针出镜像需解引用)。
- bin5 深树解析 **v3 语法已完全破解** (opens==closes 字节级配平): F32=10B定点、
  字符串无尾缀——v1 的 0.96% 键噪声全部为 F32 长度错读造成的漂移。见
  research/NOTES.md 15 日晚·三番战。
- 月度自动存档**在运行中自动落盘**(autosave.hoi4, 月初): 载入"最新"前先看
  `hoi4_saves` 的头部日期,自动档可能比手动档新也可能更早。

## 路线图 v2 (方向变更, 参考 Clausewitz-MCP: 命令注入为主, UI 降为测试用具)

> 参考: https://github.com/smerss/Clausewitz-MCP —— Linux 端已验证「内存读 +
> CCommandQueue::Post 命令注入」架构在 1.19.x 同代引擎成立。本项目同源资产
> 已备齐且部分更强: MSVC RTTI 18,316 类(rtti.json)/ **402 条命令类清单**
> (research/commands.txt, 现有 UI 写操作全部有对应命令类, 含
> CSelectEventOptionCommand 事件弹窗选项)/ tokens 10,763 / bin5 字节级破解
> (= 序列化器输出, 天然的字段偏移字典)/ vftable 实例索引 /
> **CInGameIdler 四个 vftable RVA 已落点**(参考项目取命令队列的入口类)。
> **UI 写层(SendInput)降级为: 测试期联调用具 + inject 交付前的过渡通道 +
> 启动/装载存档等 frontend 动作。**

### 为什么要换轨 —— 时效性(21 日定案)

- **存档读端到端 ~15-40s**:菜单存档 UI 链(~5-10s, 纪律性单击间隔)+ 38-55MB
  序列化落盘 + bin5 全档解析(lex3 ~13s / scaffold ~5s; chars 首建 ~70s 有缓存),
  且**全程必须暂停** → 真实时钟冻结;speed5 下数秒一游戏小时量级,15-40s =
  数个游戏日的数据漂移——决策建立在旧数据上。
- **内存读:字段直读毫秒级**;实例索引一次建表(~1-3min)后逐字段直读;
  参考项目 per-tick 语义包优化到 **46ms**(2.6 万省, 万省对比验证);
  不暂停、无副作用、可 10-20Hz 轮询。
- **瞬时态(战斗 org/伤害速率/师移动目标/事件队列)只在堆里**——存档快照
  原理上不可得,这不是快慢问题,是有无问题。
- **存档层不废弃**:它是字段偏移字典(live 读层的偏移映射正要从 tokens/bin5
  反推)、离线开发语料、UI 对表真值、崩溃恢复与兜底读端;慢变量(科研剩余
  天数/建造队列/PP)存档读仍够用。

### Phase I — inject 写层 (主攻坚) — **25 日: op 记录布局定案 + 引用解析 + 命令表第 5 条**

> **25 日结论先行**: 24 日留下的"载荷读错操作数"不是玄学, 是**操作数对齐**:
> op 记录按 `code + a0..a4 + RESULT + a5` 落盘 (**a4 与 a5 之间夹着 RESULT**),
> 载荷必须按 `a2/a3/a4/a5 = rcx/rdx/r8/r9` 显式读。定案后:
> **4 参调用全绿**(1..4 参矩阵在替身上逐条验证), 引用解析改为"结果槽 = RESULT 字段",
> `read_ptr` 给出局部缓冲区的**绝对地址**(= SetResearch 那类 `&tag` 形状)。
>
> **栈参数(5+ 参)没做出来, 也不做**: 载荷在**私有栈上写 callee home space** 这条路
> 在替身上必炸(独立 shellcode 同样指令全绿 → 问题在 VM 环境; 展开复制/降低栈顶/
> 换 callee 自写都不解决)。因为命令表里最大的命令是 **4 参**, 所以 API
> **直接拒绝第 5 个参数**(`ScriptError`), 载荷里搬家代码全部删除(968B < 24 日 1176B)。
> 负面结果与未定性范围记录在 `research/NOTES.md` 25 日"血案 4"。
>
> **命令表 4 → 6 条**: `DropCurrentNationalFocus`(ctor 0x1144800, `ctor(this, rdx=&tag)`,
> 尺寸 0x30)与 `BypassNationalFocus`(ctor 0x1143AD0, `ctor(this, rdx=&tag,
> r8=CNationalFocus*)`, 尺寸 0x38)都过 `specverify` 全绿后写入 `tables.py`;
> `CommandLayer.drop_focus_ctor()` / `bypass_focus_ctor()` 走 ctor 忠实路径。
> **真机一发**: `posted=true` / `job_intact=true` / latency 658ms+178ms / 游戏存活 ✓
> (存档 diff 见 25 日验收段)。下一批候选: SetResearch / SelectDecision /
> SelectEventOption / AddConstruction (`research/spec_batch.py` 一次跑一批)。
>
> **替身跑道重排**: phase B = 全 op + 全故障模式(一个受害者); phase C = 私有栈洪水
> (12KB 不碰 job / 24KB 必碰)与 ctor 深栈, **每场景一个全新受害者**(洪水本来就会
> 砸烂该进程的 job, 共用进程会带崩后面所有用例)。两相全绿。

> **26 日进展(命令表 6 → 8 条 spec, 但 SetResearch 只差一步)**: 复核确认自述
> 全绿(96 用例 / specverify 8 条 / 身份链 / 22 工具; 加 SetResearch 条目后 98 用例), 并把 **SetResearch** 推到
> "只差对象解析":
> ①ctor `0x11479C0`(size 0x40) 定案 —— `rdx=&tag`、`r8=CTechnology*`、
> `r9d=slot`、**第 5 个参数(bool)在栈上** `[rsp+0x20]` → `+0x3C`; 11 处 ctor 写
> 被 `BASE_INIT` + 4 字段全覆盖, 于是 **blob 路径反而绕开了"VM 无栈参数"的限制**
> (`CommandLayer.post_research`, `blob_ok=True` 的正确用法: 显式写那个 bool);
> ②CanExecute 语义反解: `0 ≤ slot < tech_manager[+0xAC]`(研究槽数, GER 实测 4)、
> `tag > 0`、`0xED8F00(manager, tech, 0)` 为真;
> ③**对象解析链定位**: `country+0xF60 → CTechnologyStatus(vft 0x2974FA0)`,
> `[+0x88]` 该国 CTechnology 实例数组(552)、`[+0x94]` 数量、`[+0xAC]` 槽数,
> 而 `0xED5080(manager, tech) = array[tech[+0x38] - 1]` —— **命令要的对象自带
> 1-based id**;
> ④**反证**: 按 vftable 扫 CTechnology 得 243,289 个实例 ≈ 440 国 × 552 个实例槽,
> 且多数是空壳、带名对象(380 个)是另一个种群 —— **vftable 扫描不是身份判据**;
> ⑤因此 SetResearch 缺的是"科技名 → 活体对象", 不是写通道;
> ⑥顺手修掉 `hoi4_inject_post` 的参数路由缺口(Drop/Bypass 原先会拿 NULL `&tag`
> 打 ctor)与 `script.py` 的过期 op 文档。复核报告见 `research/PROGRESS_REVIEW.md`。
> **真机部分(同日)**: 替身跑道三相位 A/B/C 全绿(含 `fault inside callee`);
> 写通道一发一验 = 速度 +1/−1(`posted=True`/`status=0`/`job_intact=True`, 17ms/7ms,
> pips 第 5 格 **dark→亮→dark** 复原); 只读验证发证明 `0xED5080` 的
> **id → 实例**语义(6 候选全映射), 但 `0xED8F00`(CanResearch)在 APC 线程语境里
> **对每个候选都 AV**(两个现场), **VEH 盾两次当场接管、游戏存活** ——
> "用 VM 调谓词验证候选指针"这条路被证伪, 剩余路线是从游戏自己的 UI/AI 结构取真值。

1. ~~`-debug` 启动采样~~ (未做; 备选对照文本源)
2. ~~`inject/call.py` 远程调用原语~~ → **已交付 ``21 日**: 协议 A=主线程劫持
   (挂起全线程→只 graft RIP∈镜像的冻结线程→轮询→存档式还原, rearm 60 次;
   协议 B=CreateRemoteThread→只用于无-TLS 调用, 游戏代码被游戏私 TLS 封死);
   替身干跑全绿后才上真机——**pre-game 规程固化**。
3. ~~Post 链定位~~ → **已交付**: Post=0x2250B00 (门=[queue+0x795]≠0 → stamp →
   [CSession+0x58]容器 vfn[+0x28]); operator new=0x21C9AF0; queue=[CGameApp+0x380];
   静态全局槽位 G_GAMESTATE=0x332F260 (类=CCurrentGameState!)/G_IDLER=0x332F698/
   G_GAMEAPP=0x3452450/G_QUEUE=0x3451DA8; 玩家 tag=gamestate+0x520 (Linux +8)。
   全表在 `hoi4_mcp/inject/tables.py` (RVA 锚定 spp, 版本锁 "1.19.3.0")。
4. ~~命令构造器~~ → **速度族已闭环**: CIncrease/DecreaseGameSpeed 走真 ctor
   (`send_ctor_apc`) 或 blob (Increase 的字段覆盖完整) → 注入 → **HUD 速度 pips
   真机验证 ✓**。**24 日定案: SetNationalFocus 的字段布局是 `tag@0x28`(来自
   `*(int32*)rdx`) + `CNationalFocus*@0x30`; 21 日记的 `focus_id@0x2C / mode@0x30`
   属于 CSetFuelPriorityCommand 的 ctor, 照它手搓 blob 会打死游戏**。命令对象
   从现在起一律由真 ctor 构造。**25 日定案**: 载荷的 op 记录布局是
   `[code, a0, a1, a2, a3, a4, RESULT, a5]` —— a4 与 a5 之间夹着 RESULT,
   读 a5 必须用 `+0x38`(这条错了会得到"寄存器错位/少一个参数"的怪象)。
5. ~~**未决首要**: 同会话第 2+ 次注入概率性崩游戏~~ → **23 日关闭**: 该现象与
   挂起窗竞态/惨案 3(劫持冻结在内核等待里的线程)同源, 换 APC 通道后不再存在
   (真机连发 6 次全绿); graft 协议保留为研究回退。**23 日新战场**: 通道 v1
   私有栈过小被真实 `operator new` 栈帧踩坏 job → `call 0` → 游戏 BEX64 死亡
   (替身 `--deep-stack` 原样复现); 修复 = 槽位 0x4000 布局 + 首次调用前寄存器
   预取 + `job_intact` 输入字段回读。**新纪律: 新载荷先在替身跑道全绿再上真机**。
6. **(25 日余项) 栈参数**: 只有 5+ 参命令需要, 命令表里没有 —— 真要做先定
   "为什么 VM 里的私有栈写会炸"(建议对照实验: 摘掉 VEH / 换 CreateRemoteThread
   私有线程跑同一段载荷)。

### Phase II — live 读层(时效关键)

1. CGamePlaySettings(1 实例已定位):pause/speed 字段锚定 → 暂停态判定脱离截图。
   **(21 日进展: 暂停位 = idler+0x6C1 与 icon_state 双证合流, 已可无 UI 读;
   速度字节在 PlaySettings 内待 diff)**
2. 活钟单值锚定(clock_walk 材料已存)→ 日期脱离截图。
3. CCountry 字段带重攻(15 日败因 = 当时无 tokens/bin5;现在用「存档键名↔
   内存偏移」双源对齐 + 440 国连续数组 + 多档值域筛选)→ 顶栏数字脱离截图。
   **(21 日补: 参考项目 Linux 表已入手 (research/clausewitz_ref): CCountry
   ν±0x310 数组在本平台已实证([G_GAMESTATE+0x310], cap=size=440 ✓; 字段
   偏移 Windows 自证中)**
4. CArmy 遍历(4872 实例):军级组织(存档定案无此数据,内存唯一途径)+
   瞬时态 org/strength/移动目标/战斗伤害。
5. 事件队列枚举 + CSelectEventOptionCommand → 弹窗全自动清理
   (不再逐类标定几何坐标)。
6. 性能预算:语义读包 <100ms/tick;大静态数据(province/state 归属)走磁盘
   文件,不进每 tick 内存扫(参考项目 1s→46ms 的打法)。

### Phase III — 工具面收编

- MCP 新组:`hoi4_inject_*`(命令投递)/ `hoi4_live_*`(实时读);
  工具文档标注延迟预算。
- UI 写工具(pause_toggle/set_speed/click/hover/save/load/dismiss/record/replay)
  文档标注 **test-only**,现役期间兼作 inject 故障回退。
- 仍保留 UI:启动游戏、装载存档(frontend 动作,命令队列无等价物)。

### v1 既有项(历史, 大部分已交付)

1. ~~存档 bin5 token 表(进程内解析器)~~ → **已破**: tokens.json 10763 键 + bin5 解析 +
   日期编码 + saveinfo 全量头部快解(见 research/NOTES.md 15 日晚纪录)
2. ~~存档驱动读层封装~~ → **已交付**: `hoi4_world_state()` = 439 国摘要 +
   `hoi4_country_detail()` = 单国 14 区块语义细读 (research/production/资源/师/
   外交/决议/焦点/燃油/人力/**建造队列/角色/战区**)全离线零侵入 (16-18 日)。
3. ~~建造队列 + 装备命名 + 科研成本~~ → **已交付 17 日**; 18 日 research.avail/
   theatres/hoi4_load 全链路 ✓。**17 日遗留已再收两条 19 日**: manpower.ratio
   =ratio/1e5=有效可征召% (UI 2.50% 对表 ✓); 稳定度/战争支持度=基础值口径已案。
4. CCommandQueue::Post 注入(Plan A)/ C++ DLL 命名管道(Plan B)（写层增强项;
   19 日找到官方命令日志 `logs/*_commands.log` 可作格式参考）
5. ~~状态检测/多人检测/read_only/录制回放~~ → **已交付 19 日**:
   icon_state 字形检测器（免疫横幅动画假象）、三源 MP 守卫 + 8 写工具门禁、
   hoi4_record/hoi4_replay E2E ✓、hoi4_popup 证据套件 + 两类弹窗几何实弹标定。
6. (余) 多人态正向样本(拿一份 MP 档验证 multiplayer token)、
   会话录制起点校验 → **已交付 20 日**(replay 前置帧校验三路径 live ✓)、
   ~~军级视角~~ → **20 日定案: 存档不含军队编组**(负面结果, 见已知边界);
   师个体名重建 ✓, 再往上的指挥链读法只剩 live UI / CArmy 遍历。
7. (20 日新增交付) **可用国策推导**(focusdata: 前置图+互斥+树归属过滤+
   银行日折算, GER/SOV 双档回归 ✓)、`hoi4_hover` tooltip 原语、
   `hoi4_popup(recall)` 免重抓、pytest 回归套件 24 用例全绿、
   bin5._value 窗口末溢出 bug 修复(会吞真 MP 判定的假阴性)。
8. (24 日新增交付) **write v3.1**: `inject/script.py` 微 VM 载荷 (CALL/READ/WRITE/
   WRITE_RAW/MEMSET/ALLOC_CTOR/CALL_THIS) + **VEH 崩坏护盾** (真机验收: 故意 fault
   后游戏存活且读数不变); **ctor 忠实投递** (`send_ctor_apc`: new→真 ctor→Post) +
   `hoi4_mcp/inject/specverify.py` 离线 spec 校验 (RTTI/ctor/尺寸/字段覆盖) +
   写层对未验证 spec 的拒发门禁; 修正表错: SetNationalFocus 真布局 (tag@0x28,
   **CNationalFocus\* @0x30** — 旧 focus_id@0x2C/mode@0x30 属别的类)、
   DecreaseGameSpeed 尺寸 0x40→**0x48** (ctor 里有个 std::string)、SetGameSpeed
   0x28→**0x30**; 替身跑道 `apc_probe/script_dryrun.py` 双相位全绿; pytest 70→**83**。

验收闭环 (15-16 日两轮): ①暂停 → 政治 → 选国策『四年计划』→ 科研 → 菜单存档 →
`hoi4_world_state()` 读回对表 ✓;②16 日全链路(live 暂停↔运行往返 → 菜单 →
存档 `GER_1936_03_31_16.hoi4` → `hoi4_country_detail('latest')` 数字与 UI 一致)✓。
③18 日:`hoi4_load('latest')` live 全链路 ×2 ✓;research.avail/theatres GER+PRC
离线双档回归 ✓。④19 日:MP守卫/read_only 门禁函数级三路径 ✓;录制回放 live
E2E ✓;manpower.ratio UI 对表 ✓;事件弹窗两类实弹关闭 ✓。
⑤20 日:focus 可用清单双档回归 ✓(GER 银行 10d 带入/SOV 剩 18d 对表);
`hoi4_hover` tooltip live 读数 ✓(66.25M 中的 2.50%↔ratio);replay 起点校验
拒绝/放行 live ✓;pytest 24/24 ✓。
⑥21 日:v2 写层 (CSession::Post 命令注入) 首次真机闭环 ✓ (速度命令 HUD pips
1→2 可视化验证; 同会话 2+ 发概率性崩 → 一令一会话纪律先行); 工具 18→20。
⑦22 日:①**环境级阻断定案** — 10-14 Windows 安全更新 (今天重启生效) 引入
系统级 SetContextIpValidation/线程启动校验, victim 全矩阵证实跨进程 graft
通道被内核拦截 (详见 NOTES.md 22 日) — 写层攻坚转入自启动豁免路线;
②**focus 数字 id↔名映射闭环** ✓ (live 10,668/10,668 全提取, 存档 join
GER_the_four_year_plan=58138 ✓, GER 438 条 + DLC 树 live 独有 779 个) —
SetNationalFocus 命令的最后一块前置就位; 工具 +`hoi4_focus_ids`; pytest
30→**36** 全绿。
⑧23 日:①**22 日平台级阻断作废** — `GetProcessMitigationPolicy(UserShadowStack)`
是 4 字节 DWORD, 0x100 = bit 8 `CetDynamicApisOutOfProcOnly`, 不是 bit 2
`SetContextIpValidation`(本机 SDK winnt.h + phnt 一致); victim 五原语矩阵
(graft / CRT→私有 RWX / CRT→LoadLibraryW / QueueUserAPC / QueueUserAPC2)
**全部可用**。②**APC 写通道真机闭环** ✓ — special user APC 在游戏自己的线程里
跑 `operator new + 拷 blob + Post`, HUD 速度 pips **4→5** 视觉复核, latency
14-190ms, `job_intact=True`, 连发 6 次不死; 游戏自己拒绝时 Post 返回 0
(CanExecute 活着)。③新增 `hoi4_inject_post`(SetNationalFocus 名字解析已接),
tools 21→**22**; 新增 `inject/apc.py`; pytest 36→**54** 全绿; 替身跑道
(`apc_channel_dryrun.py` 含 `--deep-stack` 深栈回归)成为上真机前的必经步骤。
⑨24 日:①**write v3.1 微 VM 载荷** (`inject/script.py`, 704B) — 一次投递可跑
CALL/READ/WRITE/WRITE_RAW/MEMSET/ALLOC_CTOR/CALL_THIS; 真机首验: VM 读游戏内存
与 RPM 逐字节一致、`operator new` 返回真堆指针 ✓。②**VEH 崩坏护盾** — 替身双相位
(无盾 call 0 必杀 / 有盾全故障存活) + **真机故意 fault 后游戏存活且读数不变** ✓。
③**ctor 忠实路径** — 21 日「不用调 ctor 也能构建」只对无字段命令成立; 24 日
SetNationalFocus 手搓 blob 打死游戏 (vtable 对/字段错, WER 0xc0000005 @
0x24c2f0d), 真 ctor 0x1146F70 定案: **rdx=&tag, r8=CNationalFocus\***,
+0x2C 不是字段。④新增 `specverify.py` 离线校验 + 写层拒发未验证 spec;
顺带修正 DecreaseGameSpeed 尺寸 0x48 (含 std::string)、SetGameSpeed 0x30;
⑤`hoi4_mcp/inject/specverify.py` 离线 spec 校验 + 写层拒发未验证 spec;
顺带修正 DecreaseGameSpeed 尺寸 0x48 (含 std::string)、SetGameSpeed 0x30;
`find_vft_refs.py` / `command_spec_hunt.py` = 命令 spec 猎人工具链;
pytest 54→**83**。⑩24 日真机验收 (**三条独立证据链**): **SetNationalFocus E2E 闭环** ✓
— ctor 路径注入 (`posted=True`, latency 71ms, job_intact) → **存档 diff**:
`focus.current` null → `GER_accelerate_the_rearmament_program`, duration 35 天 /
**remaining 25 天**(银行 10 天带入, 与离线 est_days 口径一致), 该项从 `available`
消失, `completed` 不变 → **UI 证据**: 政治点数 tooltip 出现「加速军备重整计划 −1.00」
修正; **速度命令 ctor 路径** ✓ — `speed_pips` 像素分类: +1 第 5 个 pip 亮起、−1 暗回,
Decrease 走修正后的 0x48 规格; 旧 blob 路径同一发必死 (两次血案见 NOTES.md 24 日)。
⑪25 日 (**VM 定案 + 命令表第 5 条 + 真机 E2E**):
①**op 记录布局定案** — `[code, a0, a1, a2, a3, a4, RESULT, a5]`, 载荷按
`a2..a5 = rcx/rdx/r8/r9` 显式对齐; 替身上 **1..4 参矩阵逐条 GREEN**;
②**引用解析改造** — Ref 的存储 = 生产者的 RESULT 字段(零额外内存),
`read_ptr` 给出局部缓冲区**绝对地址**(`&value` 形状); `_resolve_refs` 单次化
(`Script._resolved`), 顺带定案 24 日"载荷读错操作数"的真因 = 解析跑了两次;
③**栈参数(5+ 参)明确不支持** — 载荷在私有栈上写 callee home space 在 VM 里必炸
(独立 shellcode 全绿 → 是 VM 环境问题), 而命令表最大 4 参, 于是 API 直接拒绝并
删掉搬家代码(968B); 未定性与对照实验建议留 NOTES 25 日"血案 4";
④**命令表 4 → 6**: `DropCurrentNationalFocus`(ctor 0x1144800, `ctor(this, rdx=&tag)`,
size 0x30)与 `BypassNationalFocus`(ctor 0x1143AD0, `ctor(this, rdx=&tag,
r8=CNationalFocus*)`, size 0x38)过 specverify 全绿入表; ⑤**真机 E2E 闭环** — 一发 APC
(`posted=true`/`job_intact=true`/latency 178ms) → **存档 diff**:
`focus.current` `GER_accelerate_the_rearmament_program`(剩 25 天) → **null**,
`banked_days` 10 天回归, `n_completed` 不变 → 游戏存活;
⑥替身跑道重排三相位 (无盾必死 / 全 op + 全故障 / 私有栈洪水各用独立受害者),
phase B+C 全绿; pytest 83→**96**。
⑫26 日 (**进度复核 + SetResearch 推进**): ①自述复核全绿 — `pytest` **96/96**、
`specverify` **8/8**、载荷 968B、22 个工具、live 身份链三方匹配、
guard `verdict=singleplayer`; ②`SetResearch` spec 入表并过 specverify
(ctor 0x11479C0 / size 0x40 / 字段 tag@0x28·tech@0x30·slot@0x38·bool@0x3C),
**blob 路径显式写第 5 个栈参数** → `post_research()` 就位(真机待验);
③CanExecute 语义与对象解析链从二进制反解到位(`country+0xF60` →
`CTechnologyStatus[+0x88]`, `0xED5080` 用 `tech[+0x38]` 索引);
④反证 vftable 扫描非身份判据(243,289 ≈ 440×552 实例槽, 多为空壳);
⑤修 `hoi4_inject_post` 参数路由 + `script.py` 过期文档;
复核报告 `research/PROGRESS_REVIEW.md`, 细节见 NOTES 26 日。

研究现状与逆向笔记在 `research/NOTES.md`。
