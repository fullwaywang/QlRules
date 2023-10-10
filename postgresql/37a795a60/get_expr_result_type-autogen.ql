/**
 * @name postgresql-37a795a60-get_expr_result_type
 * @id cpp/postgresql/37a795a60/get-expr-result-type
 * @description postgresql-37a795a60-src/backend/utils/fmgr/funcapi.c-get_expr_result_type CVE-2017-15098
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vtypid_248, VariableAccess target_0) {
		target_0.getTarget()=vtypid_248
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("lookup_rowtype_tupdesc_copy")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-1"
}

predicate func_1(Variable vtypid_248) {
	exists(AddressOfExpr target_1 |
		target_1.getOperand().(VariableAccess).getType().hasName("Oid")
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("get_type_func_class")
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtypid_248)
}

predicate func_2(Variable vresult_231, ExprStmt target_4, ExprStmt target_5) {
	exists(LogicalOrExpr target_2 |
		target_2.getAnOperand() instanceof EqualityOperation
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vresult_231
		and target_2.getParent().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget().getType().hasName("TupleDesc *")
		and target_2.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_4
		and target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_3(Variable vresult_231, ExprStmt target_4, EqualityOperation target_3) {
		target_3.getAnOperand().(VariableAccess).getTarget()=vresult_231
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget().getType().hasName("TupleDesc *")
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_4
}

predicate func_4(Variable vtypid_248, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget().getType().hasName("TupleDesc *")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("lookup_rowtype_tupdesc_copy")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtypid_248
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-1"
}

predicate func_5(Variable vresult_231, Variable vtypid_248, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_231
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("get_type_func_class")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtypid_248
}

from Function func, Variable vresult_231, Variable vtypid_248, VariableAccess target_0, EqualityOperation target_3, ExprStmt target_4, ExprStmt target_5
where
func_0(vtypid_248, target_0)
and not func_1(vtypid_248)
and not func_2(vresult_231, target_4, target_5)
and func_3(vresult_231, target_4, target_3)
and func_4(vtypid_248, target_4)
and func_5(vresult_231, vtypid_248, target_5)
and vresult_231.getType().hasName("TypeFuncClass")
and vtypid_248.getType().hasName("Oid")
and vresult_231.(LocalVariable).getFunction() = func
and vtypid_248.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
