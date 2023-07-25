/**
 * @name json-c-d07b91014986900a3a75f306d302e13e005e9d67-lh_table_insert_w_hash
 * @id cpp/json-c/d07b91014986900a3a75f306d302e13e005e9d67/lh-table-insert-w-hash
 * @description json-c-d07b91014986900a3a75f306d302e13e005e9d67-linkhash.c-lh_table_insert_w_hash CVE-2020-12762
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vt_578, ReturnStmt target_3) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vt_578
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="2147483647"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("lh_table_resize")
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vt_578
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("int")
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getParent().(IfStmt).getThen()=target_3)
}

predicate func_2(Parameter vt_578, MulExpr target_2) {
		target_2.getLeftOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_2.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vt_578
		and target_2.getRightOperand().(Literal).getValue()="2"
		and target_2.getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getTarget().hasName("lh_table_resize")
		and target_2.getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vt_578
}

predicate func_3(ReturnStmt target_3) {
		target_3.getExpr().(UnaryMinusExpr).getValue()="-1"
}

from Function func, Parameter vt_578, MulExpr target_2, ReturnStmt target_3
where
not func_0(vt_578, target_3)
and func_2(vt_578, target_2)
and func_3(target_3)
and vt_578.getType().hasName("lh_table *")
and vt_578.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
