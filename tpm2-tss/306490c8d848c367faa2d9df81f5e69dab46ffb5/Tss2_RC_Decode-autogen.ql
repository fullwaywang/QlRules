/**
 * @name tpm2-tss-306490c8d848c367faa2d9df81f5e69dab46ffb5-Tss2_RC_Decode
 * @id cpp/tpm2-tss/306490c8d848c367faa2d9df81f5e69dab46ffb5/Tss2-RC-Decode
 * @description tpm2-tss-306490c8d848c367faa2d9df81f5e69dab46ffb5-src/tss2-rc/tss2_rc.c-Tss2_RC_Decode CVE-2023-22745
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vbuf_966, Variable vhandler_972, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(VariableAccess).getTarget()=vhandler_972
		and target_0.getThen().(BlockStmt).getStmt(2) instanceof IfStmt
		and target_0.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(Literal).getValue()="0"
		and target_0.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_catbuf")
		and target_0.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_966
		and target_0.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SizeofExprOperator).getValue()="530"
		and target_0.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="%s"
		and target_0.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getType().hasName("const char *")
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_0))
}

predicate func_2(Function func, DeclStmt target_2) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

predicate func_3(Function func, DeclStmt target_3) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_3
}

predicate func_4(Variable vbuf_966, Variable verr_bits_988, Variable ve_989, Function func, IfStmt target_4) {
		target_4.getCondition().(VariableAccess).getTarget()=ve_989
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_catbuf")
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_966
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SizeofExprOperator).getValue()="530"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="%s"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=ve_989
		and target_4.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_catbuf")
		and target_4.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_966
		and target_4.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SizeofExprOperator).getValue()="530"
		and target_4.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="0x%X"
		and target_4.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=verr_bits_988
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4
}

predicate func_5(Variable vhandler_972, VariableAccess target_5) {
		target_5.getTarget()=vhandler_972
}

predicate func_6(Variable vhandler_972, AssignExpr target_6) {
		target_6.getLValue().(VariableAccess).getTarget()=vhandler_972
		and target_6.getRValue().(ConditionalExpr).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vhandler_972
		and target_6.getRValue().(ConditionalExpr).getElse().(VariableAccess).getTarget()=vhandler_972
}

from Function func, Variable vbuf_966, Variable vhandler_972, Variable verr_bits_988, Variable ve_989, DeclStmt target_2, DeclStmt target_3, IfStmt target_4, VariableAccess target_5, AssignExpr target_6
where
not func_0(vbuf_966, vhandler_972, func)
and func_2(func, target_2)
and func_3(func, target_3)
and func_4(vbuf_966, verr_bits_988, ve_989, func, target_4)
and func_5(vhandler_972, target_5)
and func_6(vhandler_972, target_6)
and vbuf_966.getType().hasName("char[530]")
and vhandler_972.getType().hasName("TSS2_RC_HANDLER")
and verr_bits_988.getType().hasName("UINT16")
and ve_989.getType().hasName("const char *")
and vbuf_966.getParentScope+() = func
and vhandler_972.getParentScope+() = func
and verr_bits_988.getParentScope+() = func
and ve_989.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
