/**
 * @name sqlite3-527cbd4a104cb93bf3994b3dd3619a6299a78b13-sqlite3EndTable
 * @id cpp/sqlite3/527cbd4a104cb93bf3994b3dd3619a6299a78b13/sqlite3EndTable
 * @description sqlite3-527cbd4a104cb93bf3994b3dd3619a6299a78b13-src/build.c-sqlite3EndTable CVE-2019-19603
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vp_2181, Variable vdb_2182, BlockStmt target_1, FunctionCall target_0) {
		target_0.getTarget().hasName("isShadowTableName")
		and not target_0.getTarget().hasName("sqlite3ShadowTableName")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vdb_2182
		and target_0.getArgument(1).(PointerFieldAccess).getTarget().getName()="zName"
		and target_0.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_2181
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("Select *")
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_1
}

predicate func_1(Variable vp_2181, BlockStmt target_1) {
		target_1.getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="tabFlags"
		and target_1.getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_2181
		and target_1.getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(Literal).getValue()="4096"
}

from Function func, Variable vp_2181, Variable vdb_2182, FunctionCall target_0, BlockStmt target_1
where
func_0(vp_2181, vdb_2182, target_1, target_0)
and func_1(vp_2181, target_1)
and vp_2181.getType().hasName("Table *")
and vdb_2182.getType().hasName("sqlite3 *")
and vp_2181.(LocalVariable).getFunction() = func
and vdb_2182.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
