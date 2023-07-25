/**
 * @name lua-066e0f93c4901e601d93e31fb700f8f66f95feb8-funcnamefromcode
 * @id cpp/lua/066e0f93c4901e601d93e31fb700f8f66f95feb8/funcnamefromcode
 * @description lua-066e0f93c4901e601d93e31fb700f8f66f95feb8-ldebug.c-funcnamefromcode CVE-2021-44964
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vname_601, PointerDereferenceExpr target_0) {
		target_0.getOperand().(VariableAccess).getTarget()=vname_601
		and target_0.getParent().(AssignExpr).getLValue() = target_0
		and target_0.getParent().(AssignExpr).getRValue() instanceof StringLiteral
}

predicate func_1(Function func, DeclStmt target_1) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_1
}

predicate func_2(Function func, DeclStmt target_2) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

predicate func_3(Parameter vci_600, Function func, IfStmt target_3) {
		target_3.getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="callstatus"
		and target_3.getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vci_600
		and target_3.getCondition().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="8"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue() instanceof PointerDereferenceExpr
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(StringLiteral).getValue()="?"
		and target_3.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(StringLiteral).getValue()="hook"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3
}

/*predicate func_4(BitwiseAndExpr target_6, Function func, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue() instanceof PointerDereferenceExpr
		and target_4.getExpr().(AssignExpr).getRValue().(StringLiteral).getValue()="?"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
		and target_4.getEnclosingFunction() = func
}

*/
/*predicate func_5(BitwiseAndExpr target_6, Function func, ReturnStmt target_5) {
		target_5.getExpr().(StringLiteral).getValue()="hook"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
		and target_5.getEnclosingFunction() = func
}

*/
predicate func_6(Parameter vci_600, BitwiseAndExpr target_6) {
		target_6.getLeftOperand().(PointerFieldAccess).getTarget().getName()="callstatus"
		and target_6.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vci_600
		and target_6.getRightOperand() instanceof BinaryBitwiseOperation
}

from Function func, Parameter vname_601, Parameter vci_600, PointerDereferenceExpr target_0, DeclStmt target_1, DeclStmt target_2, IfStmt target_3, BitwiseAndExpr target_6
where
func_0(vname_601, target_0)
and func_1(func, target_1)
and func_2(func, target_2)
and func_3(vci_600, func, target_3)
and func_6(vci_600, target_6)
and vname_601.getType().hasName("const char **")
and vci_600.getType().hasName("CallInfo *")
and vname_601.getFunction() = func
and vci_600.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
