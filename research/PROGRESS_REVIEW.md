# 项目进度复核（26 日）— 外部复核 + 内存写研究追加

> 复核口径：**只把"我这一轮亲自跑出来的"算证据**，其余标注为"仓库自述"。
> 复核时间 2026-10-18 18:39-19:10；游戏进程 pid 13596（18:37 启动，GER 存档会话）。
> 相关技术细节写进 `research/NOTES.md` 26 日段。

## 0. 本轮实测（硬证据）

| 复核项 | 命令 | 结果 |
|---|---|---|
| 回归套件 | `python -m pytest -q` | **96 passed / 66.75s**（与 README 自述一致）；加入 SetResearch 条目后复跑 **98 passed** |
| 命令 spec 离线校验 | `python -m hoi4copilot.inject.specverify` | **8/8 OK**（7 条原有 + 今日新增 SetResearch） |
| 载荷可汇编性 | `import hoi4copilot.inject.script` | PAYLOAD = **968 B**，入口 0，import 期结构断言全过 |
| 会话身份链（只读） | `research/_probe_now.py` | gamestate/idler/gameapp 三个全局槽 → 实例 vftable **三方全匹配**（0x2721158 / 0x2968FF0 / 0x27182E0） |
| 队列门 & 暂停位 | 同上 | `gate_open=True`、`paused=True`、player `tag=1`、`&tag=0x26e66926130` |
| 多人守卫 | 同上 | `log=singleplayer tcp_open=0 save_flag=False verdict=singleplayer` |
| 工具面 | `grep ^@mcp.tool()` | **22 个**（与 README 自述一致） |
| 存档真值 | `research/focus_state.py latest GER` | GER 1936-09-19 06:00；`focus.current=null`、`banked_days=10`、`n_completed=1`、`available=9`；research：0 完成 / 0 在研 / **131 可研** |

结论：仓库自述的"96 用例全绿 / 22 工具 / 6 条已验 spec / APC 写通道在线"**全部复现**，
没有发现虚假声明。

## 1. 能力盘点（按层，附证据等级）

证据等级：**A=真机闭环（存档 diff 或 HUD 视觉）**、**B=离线校验（二进制/单元测试）**、**C=仅候选/未验**。

| 层 | 交付 | 等级 | 备注 |
|---|---|---|---|
| 存档读层 | bin5 解析 / 14 区块 `country_detail` / `avail` 推导 / focus 可用清单 | B+ | 本轮复跑了 focus/research 两区块，数字自洽 |
| 截图读层 | `hud/state/hover/popup/record/replay` | A | 19-20 日实弹；本轮未复跑（需要 UI 操作） |
| 安全层 | 三源 MP 守卫 + read_only + 写工具门禁 | A | 本轮 guard 复验 singleplayer |
| 写层 v3.0 | APC 固定载荷（new+blob+Post） | A | 23 日速度 pips 4→5 |
| 写层 v3.1 | 微 VM（CALL/READ/WRITE/MEMSET/ALLOC_CTOR/CALL_OBJ）+ VEH 盾 | A | 24 日真机故意 fault 后存活 |
| 命令表 | 8 条 spec：速度×3 / SetNationalFocus / DropCurrentNationalFocus / BypassNationalFocus / SetResearch / PauseGame(未验) | B（SetResearch 今日）、A（SetNationalFocus、Drop） | 可发 6 条（PauseGame 无 ctor；SetResearch 缺对象解析） |

## 2. 今日新增：内存写研究（SetResearch 线）

> **26 日 19:0x 追加（真机部分）**：替身跑道三相位跑过（A 无盾必死 / B 全 op+全故障
> GREEN / C 私有栈洪水 GREEN）；真机只读验证发证明 `0xED5080` 的 **id → 实例**语义
> （6 个候选全部映射成功），但 `0xED8F00`(CanResearch) **在 APC 线程语境里对每个候选
> 都 AV**（两个现场：0xAD1E59 的 `call [rax+0x18]`、0x24BDB84 的 `mov eax,[rax+8]`），
> **VEH 盾两次当场接管、游戏存活、暂停位不变** → 「用 VM 调谓词验证候选指针」这条路
> **被证伪为不可靠**，剩余可行路线是从游戏自己的 UI/AI 结构取真值。
> 另: 写通道真机一发一验 —— 速度 +1/−1 两次投递 `posted=True / status=0 /
> job_intact=True`(17ms / 7ms), pips 第 5 格 **dark → 亮 → dark** 复原一致,
> 暂停中时间未推进、存档未改。

25 日下次清单第一条是"命令表继续扩，SetResearch 价值最高"。本轮把它推到了
**只差一步**：

1. **spec 定案并从二进制逐条验证**（`research/command_spec_hunt.py CSetResearchCommand --full`）：
   ctor `0x11479C0`，size `0x40`，
   `ctor(this, rdx=&tag, r8=CTechnology*, r9d=slot, [rsp+0x20]=bool)`
   → 字段 `+0x28 tag / +0x30 tech / +0x38 slot / +0x3C bool`，**已入 `tables.py`**，
   `specverify`：vftable 归属 ✓ / ctor 装载 ✓ / 尺寸覆盖 ✓ / **字段覆盖完整**（11 处写全覆盖）。
2. **绕开"血案 4"限制的第一个工程解**：第 5 个参数在栈上，VM 载荷没有栈参数通道，
   但该命令 **`blob_ok=True`** —— blob 路径可以显式写 `+0x3C`。
   `CommandLayer.post_research(tech_obj, slot, flag=0)` 已就位。
3. **CanExecute 语义反解**（vtable +0x48）：
   `slot ≥ 0 且 slot < tech_manager[+0xAC]`（=研究槽数，实测 GER=4）→ `tag > 0` →
   `0xED8F00(manager, tech, 0)` 为真；flag 分支还读 `tech[+0x520]`。
4. **对象解析链定位**（从游戏自己的代码里读出来的）：
   `&tag → 0xBB48F0 → country(+0xF60) → CTechnologyStatus（vft 0x2974FA0）`
   → `[+0x88]` 该国的 CTechnology 实例数组、`[+0x94]` 数量（实测 **552**）、`[+0xAC]` 槽数；
   而 `0xED5080(manager, tech)` = `array[tech[+0x38] - 1]`，即 **tech 对象自带 1-based id**。
5. **反证与坑（重要方法论）**：
   - 按 vftable 扫 CTechnology 得到 **243,289 个实例 ≈ 440 国 × 552** —— 它们是国家数组
     里的"实例槽"，绝大多数是**只有 vtable、字段全 0 的空壳**；
   - 带可读名字的只有 380 个，且**不是**玩家数组里的元素、与 country 无指针关联，
     其 id/名字（`cas`/`cv_cas`/`anti_air`… id 3/6/8/9）更像 sub-unit 一族；
   - 结论：**vftable 扫描不是身份判据**（同名类实例可以是完全不同的种群），
     定位"命令真正要的那个对象"必须走游戏自己的访问链。
   - 因此 SetResearch 目前**缺的不是写通道，而是"名字 → 活体对象"这一步**。

## 3. 本轮顺手修掉的债

| 问题 | 位置 | 处置 |
|---|---|---|
| `hoi4_inject_post` 只给 SetNationalFocus 装参数 → Drop/Bypass 会拿 **NULL &tag** 打 ctor | `mcp_server.py` | 已按命令分派参数（Drop 只传 `&tag`；Bypass 走 focus 名字解析；SetResearch 明确拒发并给替代路径） |
| `script.py` 顶部 op 文档仍描述 25 日已删除的"栈参数"通道 | `inject/script.py` | 已改为与定案一致，并写明 5+ 参命令改用 blob 路径 |
| 上一条的连带的文档口径 | `inject/tables.py` | SetResearch 条目带 CanExecute 语义 + 解析链 + 未决项注释 |

## 4. 风险 / 技术债（按严重度）

1. **仓库没有版本控制**（`git log` → not a repository）。写层实验会杀游戏进程、结论会被
   推翻（22 日"平台级阻断"→23 日作废就是例子），却没有分支/回滚能力。
   建议立刻 `git init` + 首次提交（纯本地，不涉网络）。
2. **README 架构段落仍把 21 日 graft 主线程劫持写成主路径**，与顶部 v3 "APC 主路径"
   口径矛盾（文档债，不影响功能）。
3. **PauseGame 无 ctor** → 暂停写通道仍缺口（读暂停位已解决，写暂停还得点 UI）。
4. **命令表扩张的边际成本高**：每条命令 = 离线 hunter + specverify + 替身跑道 + 真机一发；
   目前 8 条 spec / 6 条可发。想"一次做全表"仍需移植 `cmdauto.py` 的 Describe 抽取。
5. **真机验证的破坏面**：25 日 E2E 改动了用户存档（丢弃在研国策）。写层 E2E 前应有
   存档备份纪律（脚本已做 `_backup_*_pre_*.hoi4`，值得写进 README 的验收段）。

## 5. 下一步建议（优先级）

1. **SetResearch 的"名字 → 对象"**：两条候选路线
   ① 用 VM 调 `0xED5080`/`0xED8F00` 对候选指针做**只读**验证（VEH 盾可兜住坏指针）；
   ② 从研究面板 item（`{tech*, slot, flag}`，stride 0x10）取游戏自己用的指针真值。
2. **BypassNationalFocus 真机一发**：spec 已入表并过 specverify，与 focus 族同形，成本最低。
3. **血案 4 的对照实验**（摘 VEH / CreateRemoteThread 私有线程跑同一段载荷），
   若要支持 5+ 参命令再动。
4. SelectEventOption（弹窗全自动）——先定 event handle 语义；AddConstruction 次之。
5. live 读层用 VM 的 CALL/READ 读国策进度/速度字节（写层已把"任意已确认调用 + 读回"打通）。
