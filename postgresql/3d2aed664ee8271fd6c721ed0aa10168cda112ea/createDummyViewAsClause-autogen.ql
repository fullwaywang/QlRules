/**
 * @name postgresql-3d2aed664ee8271fd6c721ed0aa10168cda112ea-createDummyViewAsClause
 * @id cpp/postgresql/3d2aed664ee8271fd6c721ed0aa10168cda112ea/createDummyViewAsClause
 * @description postgresql-3d2aed664ee8271fd6c721ed0aa10168cda112ea-src/bin/pg_dump/pg_dump.c-createDummyViewAsClause CVE-2018-1058
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

/*predicate func_0(Function func, StringLiteral target_0) {
		target_0.getValue()=" COLLATE %s."
		and not target_0.getValue()=" COLLATE %s"
		and target_0.getEnclosingFunction() = func
}

*/
predicate func_1(Variable vresult_15468, Variable vcoll_15487, FunctionCall target_1) {
		target_1.getTarget().hasName("fmtId")
		and not target_1.getTarget().hasName("fmtQualifiedId")
		and target_1.getArgument(0).(ValueFieldAccess).getTarget().getName()="name"
		and target_1.getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_1.getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="namespace"
		and target_1.getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_1.getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcoll_15487
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("appendPQExpBuffer")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vresult_15468
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()=" COLLATE %s."
}

predicate func_2(Parameter vfout_15466) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="remoteVersion"
		and target_2.getQualifier().(VariableAccess).getTarget()=vfout_15466)
}

predicate func_3(Variable vcoll_15487, ValueFieldAccess target_3) {
		target_3.getTarget().getName()="name"
		and target_3.getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_3.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcoll_15487
}

predicate func_4(Variable vresult_15468, VariableAccess target_5, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("appendPQExpBufferStr")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vresult_15468
		and target_4.getExpr().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("fmtId")
		and target_4.getExpr().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0) instanceof ValueFieldAccess
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
}

predicate func_5(Variable vcoll_15487, VariableAccess target_5) {
		target_5.getTarget()=vcoll_15487
}

from Function func, Parameter vfout_15466, Variable vresult_15468, Variable vcoll_15487, FunctionCall target_1, ValueFieldAccess target_3, ExprStmt target_4, VariableAccess target_5
where
func_1(vresult_15468, vcoll_15487, target_1)
and not func_2(vfout_15466)
and func_3(vcoll_15487, target_3)
and func_4(vresult_15468, target_5, target_4)
and func_5(vcoll_15487, target_5)
and vfout_15466.getType().hasName("Archive *")
and vresult_15468.getType().hasName("PQExpBuffer")
and vcoll_15487.getType().hasName("CollInfo *")
and vfout_15466.getFunction() = func
and vresult_15468.(LocalVariable).getFunction() = func
and vcoll_15487.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
