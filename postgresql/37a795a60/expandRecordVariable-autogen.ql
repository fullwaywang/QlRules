/**
 * @name postgresql-37a795a60-expandRecordVariable
 * @id cpp/postgresql/37a795a60/expandRecordVariable
 * @description postgresql-37a795a60-src/backend/parser/parse_target.c-expandRecordVariable CVE-2017-15098
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vtupleDesc_1458, Variable vexpr_1462, FunctionCall target_0) {
		target_0.getTarget().hasName("lookup_rowtype_tupdesc_copy")
		and not target_0.getTarget().hasName("get_expr_result_tupdesc")
		and target_0.getArgument(0).(FunctionCall).getTarget().hasName("exprType")
		and target_0.getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexpr_1462
		and target_0.getArgument(1).(FunctionCall).getTarget().hasName("exprTypmod")
		and target_0.getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexpr_1462
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_0.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtupleDesc_1458
}

predicate func_1(Variable vexpr_1462, VariableAccess target_1) {
		target_1.getTarget()=vexpr_1462
		and target_1.getParent().(FunctionCall).getParent().(NEExpr).getAnOperand() instanceof FunctionCall
}

predicate func_3(Variable vtupleDesc_1458, Variable vexpr_1462, Function func, IfStmt target_3) {
		target_3.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("get_expr_result_type")
		and target_3.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexpr_1462
		and target_3.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1) instanceof Literal
		and target_3.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vtupleDesc_1458
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtupleDesc_1458
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof FunctionCall
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3
}

predicate func_4(Variable vexpr_1462, FunctionCall target_8, VariableAccess target_4) {
		target_4.getTarget()=vexpr_1462
		and target_4.getParent().(FunctionCall).getParent().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("exprType")
		and target_4.getLocation().isBefore(target_8.getArgument(0).(VariableAccess).getLocation())
}

predicate func_5(Variable vexpr_1462, FunctionCall target_9, VariableAccess target_5) {
		target_5.getTarget()=vexpr_1462
		and target_5.getParent().(FunctionCall).getParent().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("exprTypmod")
		and target_9.getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getLocation())
}

predicate func_6(Variable vtupleDesc_1458, VariableAccess target_6) {
		target_6.getTarget()=vtupleDesc_1458
}

predicate func_8(Variable vexpr_1462, FunctionCall target_8) {
		target_8.getTarget().hasName("exprTypmod")
		and target_8.getArgument(0).(VariableAccess).getTarget()=vexpr_1462
}

predicate func_9(Variable vexpr_1462, FunctionCall target_9) {
		target_9.getTarget().hasName("exprType")
		and target_9.getArgument(0).(VariableAccess).getTarget()=vexpr_1462
}

from Function func, Variable vtupleDesc_1458, Variable vexpr_1462, FunctionCall target_0, VariableAccess target_1, IfStmt target_3, VariableAccess target_4, VariableAccess target_5, VariableAccess target_6, FunctionCall target_8, FunctionCall target_9
where
func_0(vtupleDesc_1458, vexpr_1462, target_0)
and func_1(vexpr_1462, target_1)
and func_3(vtupleDesc_1458, vexpr_1462, func, target_3)
and func_4(vexpr_1462, target_8, target_4)
and func_5(vexpr_1462, target_9, target_5)
and func_6(vtupleDesc_1458, target_6)
and func_8(vexpr_1462, target_8)
and func_9(vexpr_1462, target_9)
and vtupleDesc_1458.getType().hasName("TupleDesc")
and vexpr_1462.getType().hasName("Node *")
and vtupleDesc_1458.(LocalVariable).getFunction() = func
and vexpr_1462.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
