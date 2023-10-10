/**
 * @name linux-17743798d81238ab13050e8e2833699b54e15467-hugetlb_sysctl_handler_common
 * @id cpp/linux/17743798d81238ab13050e8e2833699b54e15467/hugetlb_sysctl_handler_common
 * @description linux-17743798d81238ab13050e8e2833699b54e15467-hugetlb_sysctl_handler_common 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vwrite_3469, Parameter vbuffer_3470, Parameter vlength_3470, Parameter vppos_3470, Parameter vtable_3469) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("proc_doulongvec_minmax")
		and not target_0.getTarget().hasName("proc_hugetlb_doulongvec_minmax")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vtable_3469
		and target_0.getArgument(1).(VariableAccess).getTarget()=vwrite_3469
		and target_0.getArgument(2).(VariableAccess).getTarget()=vbuffer_3470
		and target_0.getArgument(3).(VariableAccess).getTarget()=vlength_3470
		and target_0.getArgument(4).(VariableAccess).getTarget()=vppos_3470)
}

predicate func_1(Variable vtmp_3473) {
	exists(AddressOfExpr target_1 |
		target_1.getOperand().(VariableAccess).getTarget()=vtmp_3473
		and target_1.getParent().(AssignExpr).getRValue() = target_1
		and target_1.getParent().(AssignExpr).getLValue() instanceof PointerFieldAccess)
}

predicate func_3(Parameter vtable_3469) {
	exists(AssignExpr target_3 |
		target_3.getLValue().(PointerFieldAccess).getTarget().getName()="data"
		and target_3.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtable_3469
		and target_3.getRValue() instanceof AddressOfExpr)
}

predicate func_4(Parameter vtable_3469, Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="maxlen"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtable_3469
		and target_4.getExpr().(AssignExpr).getRValue().(SizeofTypeOperator).getType() instanceof LongType
		and target_4.getExpr().(AssignExpr).getRValue().(SizeofTypeOperator).getValue()="8"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4)
}

predicate func_7(Variable vret_3474, Function func) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_3474
		and target_7.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_7)
}

from Function func, Parameter vwrite_3469, Parameter vbuffer_3470, Parameter vlength_3470, Parameter vppos_3470, Variable vtmp_3473, Variable vret_3474, Parameter vtable_3469
where
func_0(vwrite_3469, vbuffer_3470, vlength_3470, vppos_3470, vtable_3469)
and func_1(vtmp_3473)
and func_3(vtable_3469)
and func_4(vtable_3469, func)
and func_7(vret_3474, func)
and vwrite_3469.getType().hasName("int")
and vbuffer_3470.getType().hasName("void *")
and vlength_3470.getType().hasName("size_t *")
and vppos_3470.getType().hasName("loff_t *")
and vtmp_3473.getType().hasName("unsigned long")
and vret_3474.getType().hasName("int")
and vtable_3469.getType().hasName("ctl_table *")
and vwrite_3469.getParentScope+() = func
and vbuffer_3470.getParentScope+() = func
and vlength_3470.getParentScope+() = func
and vppos_3470.getParentScope+() = func
and vtmp_3473.getParentScope+() = func
and vret_3474.getParentScope+() = func
and vtable_3469.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
