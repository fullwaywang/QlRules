/**
 * @name linux-3f4093e2bf4673f218c0bf17d8362337c400e77b-idt77252_exit
 * @id cpp/linux/3f4093e2bf4673f218c0bf17d8362337c400e77b/idt77252-exit
 * @description linux-3f4093e2bf4673f218c0bf17d8362337c400e77b-idt77252_exit 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcard_3746) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("del_timer_sync")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="tst_timer"
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcard_3746)
}

predicate func_1(Variable vcard_3746) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="next"
		and target_1.getQualifier().(VariableAccess).getTarget()=vcard_3746)
}

from Function func, Variable vcard_3746
where
not func_0(vcard_3746)
and vcard_3746.getType().hasName("idt77252_dev *")
and func_1(vcard_3746)
and vcard_3746.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
