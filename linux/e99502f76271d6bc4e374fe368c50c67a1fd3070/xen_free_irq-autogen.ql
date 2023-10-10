/**
 * @name linux-e99502f76271d6bc4e374fe368c50c67a1fd3070-xen_free_irq
 * @id cpp/linux/e99502f76271d6bc4e374fe368c50c67a1fd3070/xen-free-irq
 * @description linux-e99502f76271d6bc4e374fe368c50c67a1fd3070-xen_free_irq 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="1499"
		and not target_0.getValue()="1506"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="1500"
		and not target_1.getValue()="1507"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(Literal target_2 |
		target_2.getValue()="1501"
		and not target_2.getValue()="1508"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Function func) {
	exists(Literal target_3 |
		target_3.getValue()="1502"
		and not target_3.getValue()="1509"
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Function func) {
	exists(Literal target_4 |
		target_4.getValue()="1503"
		and not target_4.getValue()="1510"
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Function func) {
	exists(Literal target_5 |
		target_5.getValue()="1504"
		and not target_5.getValue()="1511"
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(Variable vinfo_493, Function func) {
	exists(IfStmt target_6 |
		target_6.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("list_empty")
		and target_6.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="eoi_list"
		and target_6.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinfo_493
		and target_6.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("lateeoi_list_del")
		and target_6.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinfo_493
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_6 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_6))
}

predicate func_7(Variable vinfo_493) {
	exists(NotExpr target_7 |
		target_7.getOperand().(VariableAccess).getTarget()=vinfo_493)
}

from Function func, Variable vinfo_493
where
func_0(func)
and func_1(func)
and func_2(func)
and func_3(func)
and func_4(func)
and func_5(func)
and not func_6(vinfo_493, func)
and vinfo_493.getType().hasName("irq_info *")
and func_7(vinfo_493)
and vinfo_493.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
