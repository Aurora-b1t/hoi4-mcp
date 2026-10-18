"""inject/ — v2 写层 (Phase I): 远程调用 + 玩家命令通道.

写路径 = CCommandQueue::Post(CSession*, CCommand*, force) —— 玩家点击的
同一队列, CanExecute 合法性检查照常生效。UI 点击(SendInput)降为测试用具。

铁律 (AGENTS.md 预留条款 + Clausewitz-MCP 三条踩坑):
  1. 只调反汇编确认过签名的地址 (tables.py 全部来自 UI 代码路径的静态反汇编);
  2. 循环内禁止注入 —— 每次远程调用 = 挂起全线程→劫持主线程→恢复;
     单帧语义读/每 tick 写都严禁走这条通道;
  3. 句柄类型混淆 = 崩溃 —— 命令字段先离线校验再写入。
"""
