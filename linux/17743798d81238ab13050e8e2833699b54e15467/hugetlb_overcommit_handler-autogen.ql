/**
 * @name linux-17743798d81238ab13050e8e2833699b54e15467-hugetlb_overcommit_handler
 * @id cpp/linux/17743798d81238ab13050e8e2833699b54e15467/hugetlb_overcommit_handler
 * @description linux-17743798d81238ab13050e8e2833699b54e15467-hugetlb_overcommit_handler 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vbuffer_3510, Parameter vlength_3510, Parameter vppos_3510, Parameter vtable_3509, Parameter vwrite_3509) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("proc_doulongvec_minmax")
		and not target_0.getTarget().hasName("proc_hugetlb_doulongvec_minmax")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vtable_3509
		and target_0.getArgument(1).(VariableAccess).getTarget()=vwrite_3509
		and target_0.getArgument(2).(VariableAccess).getTarget()=vbuffer_3510
		and target_0.getArgument(3).(VariableAccess).getTarget()=vlength_3510
		and target_0.getArgument(4).(VariableAccess).getTarget()=vppos_3510)
}

predicate func_1(Variable vtmp_3513) {
	exists(AddressOfExpr target_1 |
		target_1.getOperand().(VariableAccess).getTarget()=vtmp_3513
		and target_1.getParent().(AssignExpr).getRValue() = target_1
		and target_1.getParent().(AssignExpr).getLValue() instanceof PointerFieldAccess)
}

predicate func_3(Parameter vtable_3509) {
	exists(AssignExpr target_3 |
		target_3.getLValue().(PointerFieldAccess).getTarget().getName()="data"
		and target_3.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtable_3509
		and target_3.getRValue() instanceof AddressOfExpr)
}

predicate func_4(Parameter vtable_3509, Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="maxlen"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtable_3509
		and target_4.getExpr().(AssignExpr).getRValue().(SizeofTypeOperator).getType() instanceof LongType
		and target_4.getExpr().(AssignExpr).getRValue().(SizeofTypeOperator).getValue()="8"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4)
}

predicate func_7(Variable vret_3514, Function func) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_3514
		and target_7.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_7)
}

from Function func, Parameter vbuffer_3510, Parameter vlength_3510, Parameter vppos_3510, Variable vtmp_3513, Variable vret_3514, Parameter vtable_3509, Parameter vwrite_3509
where
func_0(vbuffer_3510, vlength_3510, vppos_3510, vtable_3509, vwrite_3509)
and func_1(vtmp_3513)
and func_3(vtable_3509)
and func_4(vtable_3509, func)
and func_7(vret_3514, func)
and vbuffer_3510.getType().hasName("void *")
and vlength_3510.getType().hasName("size_t *")
and vppos_3510.getType().hasName("loff_t *")
and vtmp_3513.getType().hasName("unsigned long")
and vret_3514.getType().hasName("int")
and vtable_3509.getType().hasName("ctl_table *")
and vwrite_3509.getType().hasName("int")
and vbuffer_3510.getParentScope+() = func
and vlength_3510.getParentScope+() = func
and vppos_3510.getParentScope+() = func
and vtmp_3513.getParentScope+() = func
and vret_3514.getParentScope+() = func
and vtable_3509.getParentScope+() = func
and vwrite_3509.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
