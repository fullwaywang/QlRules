/**
 * @name linux-e99502f76271d6bc4e374fe368c50c67a1fd3070-xen_irq_init
 * @id cpp/linux/e99502f76271d6bc4e374fe368c50c67a1fd3070/xen-irq-init
 * @description linux-e99502f76271d6bc4e374fe368c50c67a1fd3070-xen_irq_init 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vinfo_431) {
	exists(SizeofExprOperator target_0 |
		target_0.getValue()="48"
		and target_0.getExprOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vinfo_431)
}

predicate func_1(Variable vinfo_431, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("INIT_LIST_HEAD")
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="eoi_list"
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinfo_431
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_1))
}

predicate func_2(Variable vinfo_431, Parameter virq_429) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("set_info_for_irq")
		and target_2.getArgument(0).(VariableAccess).getTarget()=virq_429
		and target_2.getArgument(1).(VariableAccess).getTarget()=vinfo_431)
}

from Function func, Variable vinfo_431, Parameter virq_429
where
func_0(vinfo_431)
and not func_1(vinfo_431, func)
and vinfo_431.getType().hasName("irq_info *")
and func_2(vinfo_431, virq_429)
and virq_429.getType().hasName("unsigned int")
and vinfo_431.getParentScope+() = func
and virq_429.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
