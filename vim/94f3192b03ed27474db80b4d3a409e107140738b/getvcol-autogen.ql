/**
 * @name vim-94f3192b03ed27474db80b4d3a409e107140738b-getvcol
 * @id cpp/vim/94f3192b03ed27474db80b4d3a409e107140738b/getvcol
 * @description vim-94f3192b03ed27474db80b4d3a409e107140738b-src/charset.c-getvcol CVE-2021-4193
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vptr_1226, ExprStmt target_6, ExprStmt target_7) {
	exists(ArrayExpr target_1 |
		target_1.getArrayBase().(VariableAccess).getTarget()=vptr_1226
		and target_1.getArrayOffset().(VariableAccess).getType().hasName("colnr_T")
		and target_1.getParent().(EQExpr).getAnOperand() instanceof PointerDereferenceExpr
		and target_1.getParent().(EQExpr).getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_6
		and target_7.getExpr().(AssignExpr).getRValue().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getArrayBase().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vpos_1220, EqualityOperation target_9, EqualityOperation target_10, ExprStmt target_11) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="col"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpos_1220
		and target_2.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("colnr_T")
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
		and target_10.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_11.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(EqualityOperation target_9, Function func) {
	exists(BreakStmt target_3 |
		target_3.toString() = "break;"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Variable vptr_1226, ExprStmt target_6, PointerDereferenceExpr target_4) {
		target_4.getOperand().(VariableAccess).getTarget()=vptr_1226
		and target_4.getParent().(EQExpr).getAnOperand().(Literal).getValue()="0"
		and target_4.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_6
}

predicate func_5(Parameter vpos_1220, PointerFieldAccess target_5) {
		target_5.getTarget().getName()="col"
		and target_5.getQualifier().(VariableAccess).getTarget()=vpos_1220
		and target_5.getParent().(AssignExpr).getLValue() = target_5
		and target_5.getParent().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_6(Parameter vpos_1220, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="col"
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpos_1220
		and target_6.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_7(Parameter vpos_1220, Variable vptr_1226, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getRValue().(AssignExpr).getLValue().(VariableAccess).getTarget()=vptr_1226
		and target_7.getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ml_get_buf")
		and target_7.getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="w_buffer"
		and target_7.getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="lnum"
		and target_7.getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpos_1220
		and target_7.getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="0"
}

predicate func_9(EqualityOperation target_9) {
		target_9.getAnOperand() instanceof PointerDereferenceExpr
		and target_9.getAnOperand().(Literal).getValue()="0"
}

predicate func_10(Parameter vpos_1220, EqualityOperation target_10) {
		target_10.getAnOperand().(PointerFieldAccess).getTarget().getName()="col"
		and target_10.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpos_1220
		and target_10.getAnOperand().(Literal).getValue()="2147483647"
}

predicate func_11(Parameter vpos_1220, Variable vptr_1226, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vptr_1226
		and target_11.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="col"
		and target_11.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpos_1220
}

from Function func, Parameter vpos_1220, Variable vptr_1226, PointerDereferenceExpr target_4, PointerFieldAccess target_5, ExprStmt target_6, ExprStmt target_7, EqualityOperation target_9, EqualityOperation target_10, ExprStmt target_11
where
not func_1(vptr_1226, target_6, target_7)
and not func_2(vpos_1220, target_9, target_10, target_11)
and not func_3(target_9, func)
and func_4(vptr_1226, target_6, target_4)
and func_5(vpos_1220, target_5)
and func_6(vpos_1220, target_6)
and func_7(vpos_1220, vptr_1226, target_7)
and func_9(target_9)
and func_10(vpos_1220, target_10)
and func_11(vpos_1220, vptr_1226, target_11)
and vpos_1220.getType().hasName("pos_T *")
and vptr_1226.getType().hasName("char_u *")
and vpos_1220.getParentScope+() = func
and vptr_1226.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
