/**
 * @name postgresql-582edc369cdbd348d68441fc50fa26a84afd0c1a-prepare_vacuum_command
 * @id cpp/postgresql/582edc369cdbd348d68441fc50fa26a84afd0c1a/prepare-vacuum-command
 * @description postgresql-582edc369cdbd348d68441fc50fa26a84afd0c1a-src/bin/scripts/vacuumdb.c-prepare_vacuum_command CVE-2018-1058
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtable_622, Parameter vsql_621, FunctionCall target_0) {
		target_0.getTarget().hasName("appendPQExpBuffer")
		and not target_0.getTarget().hasName("appendPQExpBufferChar")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vsql_621
		and target_0.getArgument(1).(StringLiteral).getValue()=" %s"
		and target_0.getArgument(2).(VariableAccess).getTarget()=vtable_622
}

predicate func_1(Parameter vsql_621, VariableAccess target_6, ExprStmt target_7) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("appendPQExpBufferChar")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsql_621
		and target_1.getExpr().(FunctionCall).getArgument(1).(CharLiteral).getValue()="32"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_3(Parameter vconn_621, Parameter vtable_622, Parameter vsql_621, VariableAccess target_6, RelationalOperation target_8) {
	exists(IfStmt target_3 |
		target_3.getCondition().(VariableAccess).getType().hasName("bool")
		and target_3.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("appendPQExpBufferStr")
		and target_3.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsql_621
		and target_3.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vtable_622
		and target_3.getElse().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("appendQualifiedRelation")
		and target_3.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsql_621
		and target_3.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vtable_622
		and target_3.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vconn_621
		and target_3.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getType().hasName("const char *")
		and target_3.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getType().hasName("bool")
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
		and target_8.getGreaterOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

/*predicate func_4(Parameter vtable_622, Parameter vsql_621) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("appendPQExpBufferStr")
		and target_4.getArgument(0).(VariableAccess).getTarget()=vsql_621
		and target_4.getArgument(1).(VariableAccess).getTarget()=vtable_622)
}

*/
predicate func_5(Parameter vtable_622, VariableAccess target_5) {
		target_5.getTarget()=vtable_622
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_6(Parameter vtable_622, VariableAccess target_6) {
		target_6.getTarget()=vtable_622
}

predicate func_7(Parameter vsql_621, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("appendPQExpBufferChar")
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsql_621
		and target_7.getExpr().(FunctionCall).getArgument(1).(CharLiteral).getValue()="59"
}

predicate func_8(Parameter vconn_621, RelationalOperation target_8) {
		 (target_8 instanceof GEExpr or target_8 instanceof LEExpr)
		and target_8.getGreaterOperand().(FunctionCall).getTarget().hasName("PQserverVersion")
		and target_8.getGreaterOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconn_621
		and target_8.getLesserOperand().(Literal).getValue()="90000"
}

from Function func, Parameter vconn_621, Parameter vtable_622, Parameter vsql_621, FunctionCall target_0, VariableAccess target_5, VariableAccess target_6, ExprStmt target_7, RelationalOperation target_8
where
func_0(vtable_622, vsql_621, target_0)
and not func_1(vsql_621, target_6, target_7)
and not func_3(vconn_621, vtable_622, vsql_621, target_6, target_8)
and func_5(vtable_622, target_5)
and func_6(vtable_622, target_6)
and func_7(vsql_621, target_7)
and func_8(vconn_621, target_8)
and vconn_621.getType().hasName("PGconn *")
and vtable_622.getType().hasName("const char *")
and vsql_621.getType().hasName("PQExpBuffer")
and vconn_621.getFunction() = func
and vtable_622.getFunction() = func
and vsql_621.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
