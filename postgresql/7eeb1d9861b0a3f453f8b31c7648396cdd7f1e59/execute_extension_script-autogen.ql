/**
 * @name postgresql-7eeb1d9861b0a3f453f8b31c7648396cdd7f1e59-execute_extension_script
 * @id cpp/postgresql/7eeb1d9861b0a3f453f8b31c7648396cdd7f1e59/execute-extension-script
 * @description postgresql-7eeb1d9861b0a3f453f8b31c7648396cdd7f1e59-src/backend/commands/extension.c-execute_extension_script CVE-2020-14350
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(VariableAccess).getType().hasName("bool")
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("set_config_option")
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="check_function_bodies"
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="off"
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(Literal).getValue()="1"
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(Literal).getValue()="0"
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(7).(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(13)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(13).getFollowingStmt()=target_0))
}

predicate func_1(Variable vreqname_925, ExprStmt target_4, IfStmt target_5) {
	exists(LogicalAndExpr target_1 |
		target_1.getAnOperand().(VariableAccess).getTarget()=vreqname_925
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("strcmp")
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vreqname_925
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="pg_catalog"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen()=target_4
		and target_1.getAnOperand().(VariableAccess).getLocation().isBefore(target_5.getCondition().(VariableAccess).getLocation()))
}

predicate func_2(Variable vpathbuf_846, AddressOfExpr target_6, ValueFieldAccess target_7, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("appendStringInfoString")
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vpathbuf_846
		and target_2.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()=", pg_temp"
		and (func.getEntryPoint().(BlockStmt).getStmt(17)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(17).getFollowingStmt()=target_2)
		and target_6.getOperand().(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation())
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation().isBefore(target_7.getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Variable vreqname_925, ExprStmt target_4, VariableAccess target_3) {
		target_3.getTarget()=vreqname_925
		and target_3.getParent().(IfStmt).getThen()=target_4
}

predicate func_4(Variable vpathbuf_846, Variable vreqname_925, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("appendStringInfo")
		and target_4.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vpathbuf_846
		and target_4.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()=", %s"
		and target_4.getExpr().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("quote_identifier")
		and target_4.getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vreqname_925
}

predicate func_5(Variable vpathbuf_846, Variable vreqname_925, IfStmt target_5) {
		target_5.getCondition().(VariableAccess).getTarget()=vreqname_925
		and target_5.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("appendStringInfo")
		and target_5.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vpathbuf_846
		and target_5.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()=", %s"
		and target_5.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("quote_identifier")
		and target_5.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vreqname_925
}

predicate func_6(Variable vpathbuf_846, AddressOfExpr target_6) {
		target_6.getOperand().(VariableAccess).getTarget()=vpathbuf_846
}

predicate func_7(Variable vpathbuf_846, ValueFieldAccess target_7) {
		target_7.getTarget().getName()="data"
		and target_7.getQualifier().(VariableAccess).getTarget()=vpathbuf_846
}

from Function func, Variable vpathbuf_846, Variable vreqname_925, VariableAccess target_3, ExprStmt target_4, IfStmt target_5, AddressOfExpr target_6, ValueFieldAccess target_7
where
not func_0(func)
and not func_1(vreqname_925, target_4, target_5)
and not func_2(vpathbuf_846, target_6, target_7, func)
and func_3(vreqname_925, target_4, target_3)
and func_4(vpathbuf_846, vreqname_925, target_4)
and func_5(vpathbuf_846, vreqname_925, target_5)
and func_6(vpathbuf_846, target_6)
and func_7(vpathbuf_846, target_7)
and vpathbuf_846.getType().hasName("StringInfoData")
and vreqname_925.getType().hasName("char *")
and vpathbuf_846.(LocalVariable).getFunction() = func
and vreqname_925.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
