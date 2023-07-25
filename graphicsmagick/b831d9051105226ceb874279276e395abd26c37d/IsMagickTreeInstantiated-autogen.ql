/**
 * @name graphicsmagick-b831d9051105226ceb874279276e395abd26c37d-IsMagickTreeInstantiated
 * @id cpp/graphicsmagick/b831d9051105226ceb874279276e395abd26c37d/IsMagickTreeInstantiated
 * @description graphicsmagick-b831d9051105226ceb874279276e395abd26c37d-MagickCore/magick.c-IsMagickTreeInstantiated CVE-2016-3715
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vmagick_info_1005, EqualityOperation target_15, ExprStmt target_0) {
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmagick_info_1005
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("AcquireMagickInfo")
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(StringLiteral).getValue()="EPHEMERAL"
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="EPHEMERAL"
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Internal format"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_15
}

predicate func_1(Variable vmagick_info_1005, EqualityOperation target_15, ExprStmt target_1) {
		target_1.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="flags"
		and target_1.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmagick_info_1005
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_15
}

predicate func_2(Variable vmagick_list, Variable vstatus_1002, Variable vmagick_info_1005, EqualityOperation target_15, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstatus_1002
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("AddValueToSplayTree")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmagick_list
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="name"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmagick_info_1005
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vmagick_info_1005
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_15
}

predicate func_3(Variable vstatus_1002, Variable v__func__, Variable vfatal_message_1016, Variable vfatal_exception_1016, EqualityOperation target_15, IfStmt target_3) {
		target_3.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vstatus_1002
		and target_3.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfatal_exception_1016
		and target_3.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("AcquireExceptionInfo")
		and target_3.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfatal_message_1016
		and target_3.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("GetExceptionMessage")
		and target_3.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__errno_location")
		and target_3.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ThrowMagickException")
		and target_3.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfatal_exception_1016
		and target_3.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_3.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=v__func__
		and target_3.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_3.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(StringLiteral).getValue()="MemoryAllocationFailed"
		and target_3.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_3.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(StringLiteral).getValue()="unknown"
		and target_3.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(StringLiteral).getValue()="MemoryAllocationFailed"
		and target_3.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="`%s'"
		and target_3.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vfatal_message_1016
		and target_3.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfatal_message_1016
		and target_3.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("DestroyString")
		and target_3.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfatal_message_1016
		and target_3.getThen().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("CatchException")
		and target_3.getThen().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfatal_exception_1016
		and target_3.getThen().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("DestroyExceptionInfo")
		and target_3.getThen().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfatal_exception_1016
		and target_3.getThen().(BlockStmt).getStmt(8).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("MagickCoreTerminus")
		and target_3.getThen().(BlockStmt).getStmt(9).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_exit")
		and target_3.getThen().(BlockStmt).getStmt(9).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddExpr).getValue()="1"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_15
}

predicate func_4(EqualityOperation target_16, Function func, DeclStmt target_4) {
		target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_16
		and target_4.getEnclosingFunction() = func
}

predicate func_5(EqualityOperation target_16, Function func, DeclStmt target_5) {
		target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_16
		and target_5.getEnclosingFunction() = func
}

/*predicate func_6(Variable vfatal_exception_1016, EqualityOperation target_16, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfatal_exception_1016
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("AcquireExceptionInfo")
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_16
}

*/
/*predicate func_7(Variable vfatal_message_1016, EqualityOperation target_16, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfatal_message_1016
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("GetExceptionMessage")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__errno_location")
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_16
}

*/
/*predicate func_8(Variable v__func__, Variable vfatal_message_1016, Variable vfatal_exception_1016, EqualityOperation target_16, ExprStmt target_17, ExprStmt target_8) {
		target_8.getExpr().(FunctionCall).getTarget().hasName("ThrowMagickException")
		and target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfatal_exception_1016
		and target_8.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_8.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=v__func__
		and target_8.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_8.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(StringLiteral).getValue()="MemoryAllocationFailed"
		and target_8.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_8.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(StringLiteral).getValue()="unknown"
		and target_8.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(StringLiteral).getValue()="MemoryAllocationFailed"
		and target_8.getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="`%s'"
		and target_8.getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vfatal_message_1016
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_16
		and target_17.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_8.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
}

*/
/*predicate func_9(Variable vfatal_message_1016, EqualityOperation target_16, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfatal_message_1016
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("DestroyString")
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfatal_message_1016
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_16
}

*/
/*predicate func_10(Variable vfatal_exception_1016, EqualityOperation target_16, ExprStmt target_10) {
		target_10.getExpr().(FunctionCall).getTarget().hasName("CatchException")
		and target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfatal_exception_1016
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_16
}

*/
/*predicate func_11(Variable vfatal_exception_1016, EqualityOperation target_16, ExprStmt target_11) {
		target_11.getExpr().(FunctionCall).getTarget().hasName("DestroyExceptionInfo")
		and target_11.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfatal_exception_1016
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_16
}

*/
/*predicate func_12(EqualityOperation target_16, Function func, ExprStmt target_12) {
		target_12.getExpr().(FunctionCall).getTarget().hasName("MagickCoreTerminus")
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_16
		and target_12.getEnclosingFunction() = func
}

*/
/*predicate func_13(EqualityOperation target_16, Function func, ExprStmt target_13) {
		target_13.getExpr().(FunctionCall).getTarget().hasName("_exit")
		and target_13.getExpr().(FunctionCall).getArgument(0).(AddExpr).getValue()="1"
		and target_13.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_16
		and target_13.getEnclosingFunction() = func
}

*/
predicate func_14(EqualityOperation target_15, Function func, EmptyStmt target_14) {
		target_14.toString() = ";"
		and target_14.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_15
		and target_14.getEnclosingFunction() = func
}

predicate func_15(Variable vmagick_list, EqualityOperation target_15) {
		target_15.getAnOperand().(VariableAccess).getTarget()=vmagick_list
		and target_15.getAnOperand().(Literal).getValue()="0"
}

predicate func_16(Variable vstatus_1002, EqualityOperation target_16) {
		target_16.getAnOperand().(VariableAccess).getTarget()=vstatus_1002
		and target_16.getAnOperand() instanceof EnumConstantAccess
}

predicate func_17(Variable v__func__, ExprStmt target_17) {
		target_17.getExpr().(FunctionCall).getTarget().hasName("ThrowMagickException")
		and target_17.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_17.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=v__func__
		and target_17.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_17.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(StringLiteral).getValue()="MemoryAllocationFailed"
		and target_17.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_17.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(StringLiteral).getValue()="unknown"
		and target_17.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(StringLiteral).getValue()="MemoryAllocationFailed"
		and target_17.getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="`%s'"
}

from Function func, Variable vmagick_list, Variable vstatus_1002, Variable vmagick_info_1005, Variable v__func__, Variable vfatal_message_1016, Variable vfatal_exception_1016, ExprStmt target_0, ExprStmt target_1, ExprStmt target_2, IfStmt target_3, DeclStmt target_4, DeclStmt target_5, EmptyStmt target_14, EqualityOperation target_15, EqualityOperation target_16, ExprStmt target_17
where
func_0(vmagick_info_1005, target_15, target_0)
and func_1(vmagick_info_1005, target_15, target_1)
and func_2(vmagick_list, vstatus_1002, vmagick_info_1005, target_15, target_2)
and func_3(vstatus_1002, v__func__, vfatal_message_1016, vfatal_exception_1016, target_15, target_3)
and func_4(target_16, func, target_4)
and func_5(target_16, func, target_5)
and func_14(target_15, func, target_14)
and func_15(vmagick_list, target_15)
and func_16(vstatus_1002, target_16)
and func_17(v__func__, target_17)
and vmagick_list.getType().hasName("SplayTreeInfo *")
and vstatus_1002.getType().hasName("MagickBooleanType")
and vmagick_info_1005.getType().hasName("MagickInfo *")
and v__func__.getType() instanceof ArrayType
and vfatal_message_1016.getType().hasName("char *")
and vfatal_exception_1016.getType().hasName("ExceptionInfo *")
and not vmagick_list.getParentScope+() = func
and vstatus_1002.getParentScope+() = func
and vmagick_info_1005.getParentScope+() = func
and not v__func__.getParentScope+() = func
and vfatal_message_1016.getParentScope+() = func
and vfatal_exception_1016.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
