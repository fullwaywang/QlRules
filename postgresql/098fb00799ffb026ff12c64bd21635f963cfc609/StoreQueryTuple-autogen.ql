/**
 * @name postgresql-098fb00799ffb026ff12c64bd21635f963cfc609-StoreQueryTuple
 * @id cpp/postgresql/098fb00799ffb026ff12c64bd21635f963cfc609/StoreQueryTuple
 * @description postgresql-098fb00799ffb026ff12c64bd21635f963cfc609-src/bin/psql/common.c-StoreQueryTuple CVE-2020-25696
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vpset, Variable vvarname_783) {
	exists(IfStmt target_0 |
		target_0.getCondition().(FunctionCall).getTarget().hasName("VariableHasHook")
		and target_0.getCondition().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="vars"
		and target_0.getCondition().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vpset
		and target_0.getCondition().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vvarname_783
        and target_0.getThen().(BlockStmt).getAStmt() instanceof ContinueStmt)
}

predicate func_5(Variable vpset, Variable vvarname_783, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vvarname_783
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("psprintf")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(StringLiteral).getValue()="%s%s"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="gset_prefix"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vpset
}

predicate func_7(Variable vpset, Variable vvarname_783, IfStmt target_7) {
		target_7.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("SetVariable")
		and target_7.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="vars"
		and target_7.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vpset
		and target_7.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vvarname_783
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("free")
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvarname_783
		and target_7.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_8(Variable vvarname_783, ExprStmt target_8) {
		target_8.getExpr().(FunctionCall).getTarget().hasName("free")
		and target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvarname_783
}

from Function func, Variable vpset, Variable vvarname_783, ExprStmt target_5, IfStmt target_7, ExprStmt target_8
where
not func_0(vpset, vvarname_783)
and func_5(vpset, vvarname_783, target_5)
and func_7(vpset, vvarname_783, target_7)
and func_8(vvarname_783, target_8)
and vpset.getType().hasName("PsqlSettings")
and vvarname_783.getType().hasName("char *")
and not vpset.getParentScope+() = func
and vvarname_783.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
