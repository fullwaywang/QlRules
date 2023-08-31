/**
 * @name postgresql-3d2aed664ee8271fd6c721ed0aa10168cda112ea-binary_upgrade_extension_member
 * @id cpp/postgresql/3d2aed664ee8271fd6c721ed0aa10168cda112ea/binary-upgrade-extension-member
 * @description postgresql-3d2aed664ee8271fd6c721ed0aa10168cda112ea-src/bin/pg_dump/pg_dump.c-binary_upgrade_extension_member CVE-2018-1058
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

/*predicate func_0(Function func, StringLiteral target_0) {
		target_0.getValue()="ALTER EXTENSION %s ADD %s;\n"
		and not target_0.getValue()="ALTER EXTENSION %s ADD %s "
		and target_0.getEnclosingFunction() = func
}

*/
predicate func_1(Parameter vobjlabel_4368, Parameter vupgrade_buffer_4366, VariableAccess target_1) {
		target_1.getTarget()=vobjlabel_4368
		and vobjlabel_4368.getIndex() = 2
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("appendPQExpBuffer")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vupgrade_buffer_4366
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="ALTER EXTENSION %s ADD %s;\n"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("fmtId")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="name"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("DumpableObject *")
}

/*predicate func_2(Function func, StringLiteral target_2) {
		target_2.getValue()="could not find parent extension for %s\n"
		and not target_2.getValue()="could not find parent extension for %s %s\n"
		and target_2.getEnclosingFunction() = func
}

*/
predicate func_3(Parameter vobjlabel_4368, VariableAccess target_3) {
		target_3.getTarget()=vobjlabel_4368
		and vobjlabel_4368.getIndex() = 2
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("exit_horribly")
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="could not find parent extension for %s\n"
}

predicate func_5(Parameter vupgrade_buffer_4366, ExprStmt target_7, Function func) {
	exists(IfStmt target_5 |
		target_5.getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getType().hasName("const char *")
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getType().hasName("const char *")
		and target_5.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("appendPQExpBuffer")
		and target_5.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vupgrade_buffer_4366
		and target_5.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="%s."
		and target_5.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("fmtId")
		and target_5.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("const char *")
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_5 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_5)
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_6(Parameter vupgrade_buffer_4366, Function func) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(FunctionCall).getTarget().hasName("appendPQExpBuffer")
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vupgrade_buffer_4366
		and target_6.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="%s;\n"
		and target_6.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getType().hasName("const char *")
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_6 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_6))
}

predicate func_7(Parameter vobjlabel_4368, Parameter vupgrade_buffer_4366, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("appendPQExpBuffer")
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vupgrade_buffer_4366
		and target_7.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_7.getExpr().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("fmtId")
		and target_7.getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="name"
		and target_7.getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("DumpableObject *")
		and target_7.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vobjlabel_4368
}

from Function func, Parameter vobjlabel_4368, Parameter vupgrade_buffer_4366, VariableAccess target_1, VariableAccess target_3, ExprStmt target_7
where
func_1(vobjlabel_4368, vupgrade_buffer_4366, target_1)
and func_3(vobjlabel_4368, target_3)
and not func_5(vupgrade_buffer_4366, target_7, func)
and not func_6(vupgrade_buffer_4366, func)
and func_7(vobjlabel_4368, vupgrade_buffer_4366, target_7)
and vobjlabel_4368.getType().hasName("const char *")
and vupgrade_buffer_4366.getType().hasName("PQExpBuffer")
and vobjlabel_4368.getFunction() = func
and vupgrade_buffer_4366.getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
