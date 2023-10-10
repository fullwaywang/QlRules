/**
 * @name linux-5535be3099717646781ce1540cf725965d680e7b-faultin_page
 * @id cpp/linux/5535be3099717646781ce1540cf725965d680e7b/faultin_page
 * @description linux-5535be3099717646781ce1540cf725965d680e7b-faultin_page CVE-2016-5195
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vflags_926, Variable vret_930, Parameter vvma_925, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vret_930
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="vm_flags"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvma_925
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="2"
		and target_0.getThen().(ExprStmt).getExpr().(AssignOrExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vflags_926
		and target_0.getThen().(ExprStmt).getExpr().(AssignOrExpr).getRValue().(Literal).getValue()="16384"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0)
}

from Function func, Parameter vflags_926, Variable vret_930, Parameter vvma_925
where
func_0(vflags_926, vret_930, vvma_925, func)
and vflags_926.getType().hasName("unsigned int *")
and vret_930.getType().hasName("vm_fault_t")
and vvma_925.getType().hasName("vm_area_struct *")
and vflags_926.getParentScope+() = func
and vret_930.getParentScope+() = func
and vvma_925.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
