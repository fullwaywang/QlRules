/**
 * @name postgresql-c33c42362256382ed398df9dcda559cd547c68a7-scalararraysel_containment
 * @id cpp/postgresql/c33c42362256382ed398df9dcda559cd547c68a7/scalararraysel-containment
 * @description postgresql-c33c42362256382ed398df9dcda559cd547c68a7-src/backend/utils/adt/array_selfuncs.c-scalararraysel_containment CVE-2017-7484
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vvardata_88, Variable vcmpfunc_91, BlockStmt target_2, ValueFieldAccess target_3, EqualityOperation target_1, ExprStmt target_4, ExprStmt target_5) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getAnOperand().(FunctionCall).getTarget().hasName("statistic_proc_security_check")
		and target_0.getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vvardata_88
		and target_0.getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="fn_oid"
		and target_0.getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcmpfunc_91
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getQualifier().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(VariableAccess).getLocation()))
}

predicate func_1(Variable vvardata_88, BlockStmt target_2, EqualityOperation target_1) {
		target_1.getAnOperand().(ValueFieldAccess).getTarget().getName()="statsTuple"
		and target_1.getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata_88
		and target_1.getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Variable vvardata_88, BlockStmt target_2) {
		target_2.getStmt(7).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("Form_pg_statistic")
		and target_2.getStmt(7).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="t_data"
		and target_2.getStmt(7).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="statsTuple"
		and target_2.getStmt(7).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata_88
		and target_2.getStmt(7).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="t_hoff"
		and target_2.getStmt(7).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="t_data"
		and target_2.getStmt(7).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="statsTuple"
}

predicate func_3(Variable vvardata_88, ValueFieldAccess target_3) {
		target_3.getTarget().getName()="statsTuple"
		and target_3.getQualifier().(VariableAccess).getTarget()=vvardata_88
}

predicate func_4(Variable vcmpfunc_91, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcmpfunc_91
		and target_4.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cmp_proc_finfo"
		and target_4.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("TypeCacheEntry *")
}

predicate func_5(Variable vcmpfunc_91, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("Selectivity")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("mcelem_array_contain_overlap_selec")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("Datum *")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("int")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("float4 *")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType().hasName("int")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("Datum")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(Literal).getValue()="1"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(Literal).getValue()="2751"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vcmpfunc_91
}

from Function func, Variable vvardata_88, Variable vcmpfunc_91, EqualityOperation target_1, BlockStmt target_2, ValueFieldAccess target_3, ExprStmt target_4, ExprStmt target_5
where
not func_0(vvardata_88, vcmpfunc_91, target_2, target_3, target_1, target_4, target_5)
and func_1(vvardata_88, target_2, target_1)
and func_2(vvardata_88, target_2)
and func_3(vvardata_88, target_3)
and func_4(vcmpfunc_91, target_4)
and func_5(vcmpfunc_91, target_5)
and vvardata_88.getType().hasName("VariableStatData")
and vcmpfunc_91.getType().hasName("FmgrInfo *")
and vvardata_88.(LocalVariable).getFunction() = func
and vcmpfunc_91.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
