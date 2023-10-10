/**
 * @name linux-073d0552ead5bfc7a3a9c01de590e924f11b5dd2-__xen_evtchn_do_upcall
 * @id cpp/linux/073d0552ead5bfc7a3a9c01de590e924f11b5dd2/__xen_evtchn_do_upcall
 * @description linux-073d0552ead5bfc7a3a9c01de590e924f11b5dd2-__xen_evtchn_do_upcall 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="1551"
		and not target_0.getValue()="1549"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="1552"
		and not target_1.getValue()="1550"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("_raw_read_lock")
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("rwlock_t")
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_2))
}

predicate func_3(Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(FunctionCall).getTarget().hasName("_raw_read_unlock")
		and target_3.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("rwlock_t")
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_3))
}

from Function func
where
func_0(func)
and func_1(func)
and not func_2(func)
and not func_3(func)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
