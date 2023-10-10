/**
 * @name postgresql-c33c42362256382ed398df9dcda559cd547c68a7-var_eq_const
 * @id cpp/postgresql/c33c42362256382ed398df9dcda559cd547c68a7/var-eq-const
 * @description postgresql-c33c42362256382ed398df9dcda559cd547c68a7-src/backend/utils/adt/selfuncs.c-var_eq_const CVE-2017-7484
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vvardata_263, BlockStmt target_4, DivExpr target_5, EqualityOperation target_2) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getAnOperand().(FunctionCall).getTarget().hasName("statistic_proc_security_check")
		and target_0.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvardata_263
		and target_0.getAnOperand().(FunctionCall).getArgument(1).(AssignExpr).getLValue().(VariableAccess).getType().hasName("Oid")
		and target_0.getAnOperand().(FunctionCall).getArgument(1).(AssignExpr).getRValue() instanceof FunctionCall
		and target_0.getParent().(IfStmt).getThen()=target_4
		and target_5.getRightOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vvardata_263, BlockStmt target_4, EqualityOperation target_2) {
		target_2.getAnOperand().(PointerFieldAccess).getTarget().getName()="statsTuple"
		and target_2.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata_263
		and target_2.getAnOperand().(Literal).getValue()="0"
		and target_2.getParent().(IfStmt).getThen()=target_4
}

predicate func_3(Parameter voperator_263, FunctionCall target_3) {
		target_3.getTarget().hasName("get_opcode")
		and target_3.getArgument(0).(VariableAccess).getTarget()=voperator_263
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fmgr_info")
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("FmgrInfo")
}

predicate func_4(Parameter vvardata_263, BlockStmt target_4) {
		target_4.getStmt(7).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("Form_pg_statistic")
		and target_4.getStmt(7).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="t_data"
		and target_4.getStmt(7).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="statsTuple"
		and target_4.getStmt(7).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata_263
		and target_4.getStmt(7).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="t_hoff"
		and target_4.getStmt(7).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="t_data"
		and target_4.getStmt(7).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="statsTuple"
}

predicate func_5(Parameter vvardata_263, DivExpr target_5) {
		target_5.getLeftOperand().(Literal).getValue()="1.0"
		and target_5.getRightOperand().(PointerFieldAccess).getTarget().getName()="tuples"
		and target_5.getRightOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rel"
		and target_5.getRightOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata_263
}

from Function func, Parameter vvardata_263, Parameter voperator_263, EqualityOperation target_2, FunctionCall target_3, BlockStmt target_4, DivExpr target_5
where
not func_0(vvardata_263, target_4, target_5, target_2)
and func_2(vvardata_263, target_4, target_2)
and func_3(voperator_263, target_3)
and func_4(vvardata_263, target_4)
and func_5(vvardata_263, target_5)
and vvardata_263.getType().hasName("VariableStatData *")
and voperator_263.getType().hasName("Oid")
and vvardata_263.getFunction() = func
and voperator_263.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
