/**
 * @name postgresql-c33c42362256382ed398df9dcda559cd547c68a7-calc_arraycontsel
 * @id cpp/postgresql/c33c42362256382ed398df9dcda559cd547c68a7/calc-arraycontsel
 * @description postgresql-c33c42362256382ed398df9dcda559cd547c68a7-src/backend/utils/adt/array_selfuncs.c-calc_arraycontsel CVE-2017-7484
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vvardata_346, Variable vcmpfunc_351, BlockStmt target_2, EqualityOperation target_1, ExprStmt target_3, ExprStmt target_4) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getAnOperand().(FunctionCall).getTarget().hasName("statistic_proc_security_check")
		and target_0.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvardata_346
		and target_0.getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="fn_oid"
		and target_0.getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcmpfunc_351
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_0.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(9).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vvardata_346, BlockStmt target_2, EqualityOperation target_1) {
		target_1.getAnOperand().(PointerFieldAccess).getTarget().getName()="statsTuple"
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata_346
		and target_1.getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Parameter vvardata_346, BlockStmt target_2) {
		target_2.getStmt(7).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("Form_pg_statistic")
		and target_2.getStmt(7).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="t_data"
		and target_2.getStmt(7).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="statsTuple"
		and target_2.getStmt(7).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata_346
		and target_2.getStmt(7).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="t_hoff"
		and target_2.getStmt(7).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="t_data"
		and target_2.getStmt(7).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="statsTuple"
}

predicate func_3(Variable vcmpfunc_351, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcmpfunc_351
		and target_3.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cmp_proc_finfo"
		and target_3.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("TypeCacheEntry *")
}

predicate func_4(Variable vcmpfunc_351, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("Selectivity")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("mcelem_array_selec")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("ArrayType *")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("TypeCacheEntry *")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("Datum *")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType().hasName("int")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget().getType().hasName("float4 *")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget().getType().hasName("int")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getTarget().getType().hasName("float4 *")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(VariableAccess).getTarget().getType().hasName("int")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(8).(VariableAccess).getTarget().getType().hasName("Oid")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(9).(VariableAccess).getTarget()=vcmpfunc_351
}

from Function func, Parameter vvardata_346, Variable vcmpfunc_351, EqualityOperation target_1, BlockStmt target_2, ExprStmt target_3, ExprStmt target_4
where
not func_0(vvardata_346, vcmpfunc_351, target_2, target_1, target_3, target_4)
and func_1(vvardata_346, target_2, target_1)
and func_2(vvardata_346, target_2)
and func_3(vcmpfunc_351, target_3)
and func_4(vcmpfunc_351, target_4)
and vvardata_346.getType().hasName("VariableStatData *")
and vcmpfunc_351.getType().hasName("FmgrInfo *")
and vvardata_346.getFunction() = func
and vcmpfunc_351.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
