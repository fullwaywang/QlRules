/**
 * @name postgresql-3d2aed664ee8271fd6c721ed0aa10168cda112ea-dumpTableConstraintComment
 * @id cpp/postgresql/3d2aed664ee8271fd6c721ed0aa10168cda112ea/dumpTableConstraintComment
 * @description postgresql-3d2aed664ee8271fd6c721ed0aa10168cda112ea-src/bin/pg_dump/pg_dump.c-dumpTableConstraintComment CVE-2018-1058
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Initializer target_0) {
		target_0.getExpr().(FunctionCall).getTarget().hasName("createPQExpBuffer")
		and target_0.getExpr().getEnclosingFunction() = func
}

predicate func_1(Variable vlabelq_16810, VariableAccess target_1) {
		target_1.getTarget()=vlabelq_16810
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("appendPQExpBuffer")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="CONSTRAINT %s "
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("fmtId")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="name"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("ConstraintInfo *")
}

/*predicate func_2(Function func, StringLiteral target_2) {
		target_2.getValue()="CONSTRAINT %s "
		and not target_2.getValue()="CONSTRAINT %s ON"
		and target_2.getEnclosingFunction() = func
}

*/
predicate func_3(Variable vtbinfo_16809, Variable vlabelq_16810, VariableAccess target_3) {
		target_3.getTarget()=vlabelq_16810
		and target_3.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("dumpComment")
		and target_3.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("Archive *")
		and target_3.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="data"
		and target_3.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="name"
		and target_3.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_3.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="namespace"
		and target_3.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_3.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="rolname"
		and target_3.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtbinfo_16809
		and target_3.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getTarget().getName()="catId"
		and target_3.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_3.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("ConstraintInfo *")
		and target_3.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_3.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(ConditionalExpr).getCondition().(PointerFieldAccess).getTarget().getName()="separate"
		and target_3.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(ConditionalExpr).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("ConstraintInfo *")
		and target_3.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(ConditionalExpr).getThen().(ValueFieldAccess).getTarget().getName()="dumpId"
		and target_3.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(ConditionalExpr).getThen().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_3.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(ConditionalExpr).getThen().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("ConstraintInfo *")
		and target_3.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(ConditionalExpr).getElse().(ValueFieldAccess).getTarget().getName()="dumpId"
		and target_3.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(ConditionalExpr).getElse().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_3.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(ConditionalExpr).getElse().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtbinfo_16809
}

predicate func_4(Variable vlabelq_16810, VariableAccess target_4) {
		target_4.getTarget()=vlabelq_16810
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("destroyPQExpBuffer")
}

predicate func_5(Variable vlabelq_16810, FunctionCall target_5) {
		target_5.getTarget().hasName("appendPQExpBuffer")
		and not target_5.getTarget().hasName("free")
		and target_5.getArgument(0).(VariableAccess).getTarget()=vlabelq_16810
		and target_5.getArgument(1).(StringLiteral).getValue()="ON %s"
		and target_5.getArgument(2) instanceof FunctionCall
}

predicate func_6(Function func) {
	exists(AssignExpr target_6 |
		target_6.getLValue().(VariableAccess).getType().hasName("char *")
		and target_6.getRValue().(FunctionCall).getTarget().hasName("pg_strdup")
		and target_6.getRValue().(FunctionCall).getArgument(0) instanceof FunctionCall
		and target_6.getEnclosingFunction() = func)
}

predicate func_8(Function func) {
	exists(ExprStmt target_8 |
		target_8.getExpr().(FunctionCall).getTarget().hasName("free")
		and target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("char *")
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_8 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_8))
}

predicate func_10(Variable vtbinfo_16809, FunctionCall target_10) {
		target_10.getTarget().hasName("fmtId")
		and target_10.getArgument(0).(ValueFieldAccess).getTarget().getName()="name"
		and target_10.getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_10.getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtbinfo_16809
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

from Function func, Variable vtbinfo_16809, Variable vlabelq_16810, Initializer target_0, VariableAccess target_1, VariableAccess target_3, VariableAccess target_4, FunctionCall target_5, FunctionCall target_10
where
func_0(func, target_0)
and func_1(vlabelq_16810, target_1)
and func_3(vtbinfo_16809, vlabelq_16810, target_3)
and func_4(vlabelq_16810, target_4)
and func_5(vlabelq_16810, target_5)
and not func_6(func)
and not func_8(func)
and func_10(vtbinfo_16809, target_10)
and vtbinfo_16809.getType().hasName("TableInfo *")
and vlabelq_16810.getType().hasName("PQExpBuffer")
and vtbinfo_16809.(LocalVariable).getFunction() = func
and vlabelq_16810.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
