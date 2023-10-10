/**
 * @name vim-826bfe4bbd7594188e3d74d2539d9707b1c6a14b-win_redr_status
 * @id cpp/vim/826bfe4bbd7594188e3d74d2539d9707b1c6a14b/win-redr-status
 * @description vim-826bfe4bbd7594188e3d74d2539d9707b1c6a14b-src/drawscreen.c-win_redr_status CVE-2021-3872
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vlen_415, PointerArithmeticOperation target_13, Literal target_0) {
		target_0.getValue()="3"
		and not target_0.getValue()="4096"
		and target_0.getParent().(AssignAddExpr).getParent().(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vlen_415
		and target_0.getParent().(AssignAddExpr).getParent().(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_13.getAnOperand().(VariableAccess).getLocation())
}

predicate func_1(Variable vlen_415, ExprStmt target_19, PointerArithmeticOperation target_7) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("vim_snprintf")
		and target_1.getArgument(0) instanceof PointerArithmeticOperation
		and target_1.getArgument(1).(SubExpr).getLeftOperand().(Literal).getValue()="4096"
		and target_1.getArgument(1).(SubExpr).getRightOperand().(VariableAccess).getTarget()=vlen_415
		and target_1.getArgument(2).(StringLiteral).getValue()="%s"
		and target_1.getArgument(3) instanceof FunctionCall
		and target_19.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_1.getArgument(1).(SubExpr).getRightOperand().(VariableAccess).getLocation())
		and target_1.getArgument(1).(SubExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_7.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable vlen_415, PointerArithmeticOperation target_20, PointerArithmeticOperation target_11) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("vim_snprintf")
		and target_2.getArgument(0) instanceof PointerArithmeticOperation
		and target_2.getArgument(1).(SubExpr).getLeftOperand().(Literal).getValue()="4096"
		and target_2.getArgument(1).(SubExpr).getRightOperand().(VariableAccess).getTarget()=vlen_415
		and target_2.getArgument(2).(StringLiteral).getValue()="%s"
		and target_2.getArgument(3) instanceof FunctionCall
		and target_20.getAnOperand().(VariableAccess).getLocation().isBefore(target_2.getArgument(1).(SubExpr).getRightOperand().(VariableAccess).getLocation())
		and target_2.getArgument(1).(SubExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_11.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_3(Variable vlen_415, PointerArithmeticOperation target_21, PointerArithmeticOperation target_12) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("vim_snprintf")
		and target_3.getArgument(0) instanceof PointerArithmeticOperation
		and target_3.getArgument(1).(SubExpr).getLeftOperand().(Literal).getValue()="4096"
		and target_3.getArgument(1).(SubExpr).getRightOperand().(VariableAccess).getTarget()=vlen_415
		and target_3.getArgument(2).(StringLiteral).getValue()="%s"
		and target_3.getArgument(3) instanceof StringLiteral
		and target_21.getAnOperand().(VariableAccess).getLocation().isBefore(target_3.getArgument(1).(SubExpr).getRightOperand().(VariableAccess).getLocation())
		and target_3.getArgument(1).(SubExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_12.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_4(Variable vp_414, Variable vlen_415, PointerArithmeticOperation target_12, PointerArithmeticOperation target_13, ExprStmt target_22) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("vim_snprintf")
		and target_4.getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vp_414
		and target_4.getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vlen_415
		and target_4.getArgument(1).(SubExpr).getLeftOperand().(Literal).getValue()="4096"
		and target_4.getArgument(1).(SubExpr).getRightOperand().(VariableAccess).getTarget()=vlen_415
		and target_4.getArgument(2).(StringLiteral).getValue()="%s"
		and target_4.getArgument(3) instanceof FunctionCall
		and target_12.getAnOperand().(VariableAccess).getLocation().isBefore(target_4.getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation())
		and target_4.getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_13.getAnOperand().(VariableAccess).getLocation())
		and target_4.getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_22.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_6(Variable vp_414, Variable vlen_415, PointerFieldAccess target_23, ExprStmt target_6) {
		target_6.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vlen_415
		and target_6.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getTarget().hasName("strlen")
		and target_6.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vp_414
		and target_6.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vlen_415
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_23
}

predicate func_7(Variable vp_414, Variable vlen_415, PointerArithmeticOperation target_7) {
		target_7.getAnOperand().(VariableAccess).getTarget()=vp_414
		and target_7.getAnOperand().(VariableAccess).getTarget()=vlen_415
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_8(Function func, FunctionCall target_8) {
		target_8.getTarget().hasName("dcgettext")
		and target_8.getArgument(0).(Literal).getValue()="0"
		and target_8.getArgument(1).(StringLiteral).getValue()="[Help]"
		and target_8.getArgument(2).(Literal).getValue()="5"
		and target_8.getEnclosingFunction() = func
}

predicate func_9(Function func, FunctionCall target_9) {
		target_9.getTarget().hasName("dcgettext")
		and target_9.getArgument(0).(Literal).getValue()="0"
		and target_9.getArgument(1).(StringLiteral).getValue()="[Preview]"
		and target_9.getArgument(2).(Literal).getValue()="5"
		and target_9.getEnclosingFunction() = func
}

predicate func_10(Function func, FunctionCall target_10) {
		target_10.getTarget().hasName("dcgettext")
		and target_10.getArgument(0).(Literal).getValue()="0"
		and target_10.getArgument(1).(StringLiteral).getValue()="[RO]"
		and target_10.getArgument(2).(Literal).getValue()="5"
		and target_10.getEnclosingFunction() = func
}

predicate func_11(Variable vp_414, Variable vlen_415, PointerArithmeticOperation target_11) {
		target_11.getAnOperand().(VariableAccess).getTarget()=vp_414
		and target_11.getAnOperand().(VariableAccess).getTarget()=vlen_415
		and target_11.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_12(Variable vp_414, Variable vlen_415, PointerArithmeticOperation target_12) {
		target_12.getAnOperand().(VariableAccess).getTarget()=vp_414
		and target_12.getAnOperand().(VariableAccess).getTarget()=vlen_415
		and target_12.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_13(Variable vp_414, Variable vlen_415, PointerArithmeticOperation target_13) {
		target_13.getAnOperand().(VariableAccess).getTarget()=vp_414
		and target_13.getAnOperand().(VariableAccess).getTarget()=vlen_415
		and target_13.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_15(Function func, FunctionCall target_15) {
		target_15.getTarget().hasName("strcpy")
		and target_15.getArgument(0) instanceof PointerArithmeticOperation
		and target_15.getArgument(1) instanceof FunctionCall
		and target_15.getEnclosingFunction() = func
}

predicate func_16(Function func, FunctionCall target_16) {
		target_16.getTarget().hasName("strcpy")
		and target_16.getArgument(0) instanceof PointerArithmeticOperation
		and target_16.getArgument(1) instanceof FunctionCall
		and target_16.getEnclosingFunction() = func
}

predicate func_17(Function func, FunctionCall target_17) {
		target_17.getTarget().hasName("strcpy")
		and target_17.getArgument(0) instanceof PointerArithmeticOperation
		and target_17.getArgument(1) instanceof StringLiteral
		and target_17.getEnclosingFunction() = func
}

predicate func_18(Function func, FunctionCall target_18) {
		target_18.getTarget().hasName("strcpy")
		and target_18.getArgument(0) instanceof PointerArithmeticOperation
		and target_18.getArgument(1) instanceof FunctionCall
		and target_18.getEnclosingFunction() = func
}

predicate func_19(Variable vp_414, Variable vlen_415, ExprStmt target_19) {
		target_19.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vp_414
		and target_19.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vlen_415
		and target_19.getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="32"
}

predicate func_20(Variable vp_414, Variable vlen_415, PointerArithmeticOperation target_20) {
		target_20.getAnOperand().(VariableAccess).getTarget()=vp_414
		and target_20.getAnOperand().(VariableAccess).getTarget()=vlen_415
}

predicate func_21(Variable vp_414, Variable vlen_415, PointerArithmeticOperation target_21) {
		target_21.getAnOperand().(VariableAccess).getTarget()=vp_414
		and target_21.getAnOperand().(VariableAccess).getTarget()=vlen_415
}

predicate func_22(Variable vlen_415, ExprStmt target_22) {
		target_22.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vlen_415
		and target_22.getExpr().(AssignAddExpr).getRValue() instanceof Literal
}

predicate func_23(PointerFieldAccess target_23) {
		target_23.getTarget().getName()="b_p_ro"
		and target_23.getQualifier().(PointerFieldAccess).getTarget().getName()="w_buffer"
}

from Function func, Variable vp_414, Variable vlen_415, Literal target_0, ExprStmt target_6, PointerArithmeticOperation target_7, FunctionCall target_8, FunctionCall target_9, FunctionCall target_10, PointerArithmeticOperation target_11, PointerArithmeticOperation target_12, PointerArithmeticOperation target_13, FunctionCall target_15, FunctionCall target_16, FunctionCall target_17, FunctionCall target_18, ExprStmt target_19, PointerArithmeticOperation target_20, PointerArithmeticOperation target_21, ExprStmt target_22, PointerFieldAccess target_23
where
func_0(vlen_415, target_13, target_0)
and not func_1(vlen_415, target_19, target_7)
and not func_2(vlen_415, target_20, target_11)
and not func_3(vlen_415, target_21, target_12)
and not func_4(vp_414, vlen_415, target_12, target_13, target_22)
and func_6(vp_414, vlen_415, target_23, target_6)
and func_7(vp_414, vlen_415, target_7)
and func_8(func, target_8)
and func_9(func, target_9)
and func_10(func, target_10)
and func_11(vp_414, vlen_415, target_11)
and func_12(vp_414, vlen_415, target_12)
and func_13(vp_414, vlen_415, target_13)
and func_15(func, target_15)
and func_16(func, target_16)
and func_17(func, target_17)
and func_18(func, target_18)
and func_19(vp_414, vlen_415, target_19)
and func_20(vp_414, vlen_415, target_20)
and func_21(vp_414, vlen_415, target_21)
and func_22(vlen_415, target_22)
and func_23(target_23)
and vp_414.getType().hasName("char_u *")
and vlen_415.getType().hasName("int")
and vp_414.getParentScope+() = func
and vlen_415.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
