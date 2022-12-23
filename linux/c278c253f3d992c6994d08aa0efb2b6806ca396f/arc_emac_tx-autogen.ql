/**
 * @name linux-c278c253f3d992c6994d08aa0efb2b6806ca396f-arc_emac_tx
 * @id cpp/linux/c278c253f3d992c6994d08aa0efb2b6806ca396f/arc_emac_tx
 * @description linux-c278c253f3d992c6994d08aa0efb2b6806ca396f-arc_emac_tx 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(AsmStmt target_0 |
		target_0.toString() = "asm statement"
		and (func.getEntryPoint().(BlockStmt).getStmt(19)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(19).getFollowingStmt()=target_0))
}

from Function func
where
not func_0(func)
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
