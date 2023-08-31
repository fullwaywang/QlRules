/**
 * @name postgresql-37a795a60-ExpandRowReference
 * @id cpp/postgresql/37a795a60/ExpandRowReference
 * @description postgresql-37a795a60-src/backend/parser/parse_target.c-ExpandRowReference CVE-2017-15098
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vexpr_1357, Variable vtupleDesc_1361, FunctionCall target_0) {
		target_0.getTarget().hasName("lookup_rowtype_tupdesc_copy")
		and not target_0.getTarget().hasName("get_expr_result_tupdesc")
		and target_0.getArgument(0).(FunctionCall).getTarget().hasName("exprType")
		and target_0.getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexpr_1357
		and target_0.getArgument(1).(FunctionCall).getTarget().hasName("exprTypmod")
		and target_0.getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexpr_1357
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_0.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtupleDesc_1361
}

predicate func_1(Parameter vexpr_1357, VariableAccess target_1) {
		target_1.getTarget()=vexpr_1357
		and target_1.getParent().(FunctionCall).getParent().(NEExpr).getAnOperand() instanceof FunctionCall
}

predicate func_3(Parameter vexpr_1357, Variable vtupleDesc_1361, LogicalAndExpr target_6, IfStmt target_3) {
		target_3.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("get_expr_result_type")
		and target_3.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexpr_1357
		and target_3.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1) instanceof Literal
		and target_3.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vtupleDesc_1361
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtupleDesc_1361
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof FunctionCall
		and target_3.getParent().(IfStmt).getCondition()=target_6
}

predicate func_4(Parameter vexpr_1357, FunctionCall target_8, VariableAccess target_4) {
		target_4.getTarget()=vexpr_1357
		and target_4.getParent().(FunctionCall).getParent().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("exprType")
		and target_4.getLocation().isBefore(target_8.getArgument(0).(VariableAccess).getLocation())
}

predicate func_5(Parameter vexpr_1357, FunctionCall target_9, ExprStmt target_10, VariableAccess target_5) {
		target_5.getTarget()=vexpr_1357
		and target_5.getParent().(FunctionCall).getParent().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("exprTypmod")
		and target_9.getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getLocation())
		and target_5.getLocation().isBefore(target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_6(Parameter vexpr_1357, LogicalAndExpr target_6) {
		target_6.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vexpr_1357
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="vartype"
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vexpr_1357
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="2249"
}

predicate func_8(Parameter vexpr_1357, FunctionCall target_8) {
		target_8.getTarget().hasName("exprTypmod")
		and target_8.getArgument(0).(VariableAccess).getTarget()=vexpr_1357
}

predicate func_9(Parameter vexpr_1357, FunctionCall target_9) {
		target_9.getTarget().hasName("exprType")
		and target_9.getArgument(0).(VariableAccess).getTarget()=vexpr_1357
}

predicate func_10(Parameter vexpr_1357, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="arg"
		and target_10.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("FieldSelect *")
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("copyObjectImpl")
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexpr_1357
}

from Function func, Parameter vexpr_1357, Variable vtupleDesc_1361, FunctionCall target_0, VariableAccess target_1, IfStmt target_3, VariableAccess target_4, VariableAccess target_5, LogicalAndExpr target_6, FunctionCall target_8, FunctionCall target_9, ExprStmt target_10
where
func_0(vexpr_1357, vtupleDesc_1361, target_0)
and func_1(vexpr_1357, target_1)
and func_3(vexpr_1357, vtupleDesc_1361, target_6, target_3)
and func_4(vexpr_1357, target_8, target_4)
and func_5(vexpr_1357, target_9, target_10, target_5)
and func_6(vexpr_1357, target_6)
and func_8(vexpr_1357, target_8)
and func_9(vexpr_1357, target_9)
and func_10(vexpr_1357, target_10)
and vexpr_1357.getType().hasName("Node *")
and vtupleDesc_1361.getType().hasName("TupleDesc")
and vexpr_1357.getFunction() = func
and vtupleDesc_1361.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
