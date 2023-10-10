/**
 * @name curl-0b664ba968437715819bfe4c7ada5679d16ebbc3-setcharset
 * @id cpp/curl/0b664ba968437715819bfe4c7ada5679d16ebbc3/setcharset
 * @description curl-0b664ba968437715819bfe4c7ada5679d16ebbc3-lib/curl_fnmatch.c-setcharset CVE-2017-8817
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, CharLiteral target_0) {
		target_0.getValue()="0"
		and not target_0.getValue()="93"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func, Literal target_1) {
		target_1.getValue()="0"
		and not target_1.getValue()="1"
		and target_1.getParent().(ReturnStmt).getParent().(BlockStmt).getStmt(0) instanceof ReturnStmt
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Variable vc_133, BlockStmt target_13, ExprStmt target_14, ExprStmt target_15) {
	exists(NotExpr target_2 |
		target_2.getOperand().(VariableAccess).getTarget()=vc_133
		and target_2.getParent().(IfStmt).getThen()=target_13
		and target_14.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_2.getOperand().(VariableAccess).getLocation())
		and target_2.getOperand().(VariableAccess).getLocation().isBefore(target_15.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_3(Variable vc_133, BlockStmt target_13, BitwiseAndExpr target_3) {
		target_3.getLeftOperand().(ArrayExpr).getArrayBase().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__ctype_b_loc")
		and target_3.getLeftOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vc_133
		and target_3.getParent().(IfStmt).getThen()=target_13
}

predicate func_4(Variable vc_133, BlockStmt target_16, EqualityOperation target_4) {
		target_4.getAnOperand().(VariableAccess).getTarget()=vc_133
		and target_4.getAnOperand().(CharLiteral).getValue()="91"
		and target_4.getParent().(IfStmt).getThen()=target_16
}

predicate func_5(Variable vc_133, BlockStmt target_17, EqualityOperation target_5) {
		target_5.getAnOperand().(VariableAccess).getTarget()=vc_133
		and target_5.getAnOperand().(CharLiteral).getValue()="93"
		and target_5.getParent().(IfStmt).getThen()=target_17
}

predicate func_6(EqualityOperation target_10, Function func, ReturnStmt target_6) {
		target_6.getExpr().(Literal).getValue()="0"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10
		and target_6.getEnclosingFunction() = func
}

predicate func_7(Parameter vp_127, Parameter vcharset_127, Variable vsomething_found_132, Variable vc_133, EqualityOperation target_18, BlockStmt target_7) {
		target_7.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vcharset_127
		and target_7.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vc_133
		and target_7.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_7.getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vp_127
		and target_7.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsomething_found_132
		and target_7.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_7.getParent().(IfStmt).getParent().(IfStmt).getCondition()=target_18
}

predicate func_8(EqualityOperation target_19, Function func, ReturnStmt target_8) {
		target_8.getExpr() instanceof Literal
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_19
		and target_8.getEnclosingFunction() = func
}

predicate func_9(Variable vc_133, BlockStmt target_20, VariableAccess target_9) {
		target_9.getTarget()=vc_133
		and target_9.getParent().(EQExpr).getAnOperand() instanceof CharLiteral
		and target_9.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_20
}

predicate func_10(Variable vc_133, BlockStmt target_20, ExprStmt target_14, ExprStmt target_15, EqualityOperation target_10) {
		target_10.getAnOperand().(VariableAccess).getTarget()=vc_133
		and target_10.getAnOperand().(CharLiteral).getValue()="0"
		and target_10.getParent().(IfStmt).getThen()=target_20
		and target_14.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_10.getAnOperand().(VariableAccess).getLocation())
		and target_10.getAnOperand().(VariableAccess).getLocation().isBefore(target_15.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation())
}

predicate func_11(Variable vstate_129, Variable vc_133, EqualityOperation target_4, IfStmt target_11) {
		target_11.getCondition() instanceof EqualityOperation
		and target_11.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(Literal).getValue()="1"
		and target_11.getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vc_133
		and target_11.getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand() instanceof CharLiteral
		and target_11.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof ReturnStmt
		and target_11.getElse().(IfStmt).getElse().(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__ctype_b_loc")
		and target_11.getElse().(IfStmt).getElse().(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vc_133
		and target_11.getElse().(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_11.getElse().(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstate_129
		and target_11.getParent().(IfStmt).getCondition()=target_4
}

predicate func_12(Function func, ReturnStmt target_12) {
		target_12.getExpr().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_12
}

predicate func_13(Parameter vcharset_127, Variable vc_133, BlockStmt target_13) {
		target_13.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("unsigned char")
		and target_13.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vc_133
		and target_13.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vcharset_127
		and target_13.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vc_133
		and target_13.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
}

predicate func_14(Variable vc_133, ExprStmt target_14) {
		target_14.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("unsigned char")
		and target_14.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vc_133
}

predicate func_15(Parameter vcharset_127, Variable vc_133, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vcharset_127
		and target_15.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vc_133
		and target_15.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
}

predicate func_16(Parameter vp_127, Parameter vcharset_127, Variable vstate_129, Variable vc_133, BlockStmt target_16) {
		target_16.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstate_129
		and target_16.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vcharset_127
		and target_16.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vc_133
		and target_16.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_16.getStmt(2).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vp_127
}

predicate func_17(BlockStmt target_17) {
		target_17.getStmt(0).(ReturnStmt).getExpr().(Literal).getValue()="1"
}

predicate func_18(Variable vc_133, EqualityOperation target_18) {
		target_18.getAnOperand().(VariableAccess).getTarget()=vc_133
		and target_18.getAnOperand().(CharLiteral).getValue()="92"
}

predicate func_19(Variable vc_133, EqualityOperation target_19) {
		target_19.getAnOperand().(VariableAccess).getTarget()=vc_133
		and target_19.getAnOperand() instanceof CharLiteral
}

predicate func_20(BlockStmt target_20) {
		target_20.getStmt(0) instanceof ReturnStmt
}

from Function func, Parameter vp_127, Parameter vcharset_127, Variable vstate_129, Variable vsomething_found_132, Variable vc_133, CharLiteral target_0, Literal target_1, BitwiseAndExpr target_3, EqualityOperation target_4, EqualityOperation target_5, ReturnStmt target_6, BlockStmt target_7, ReturnStmt target_8, VariableAccess target_9, EqualityOperation target_10, IfStmt target_11, ReturnStmt target_12, BlockStmt target_13, ExprStmt target_14, ExprStmt target_15, BlockStmt target_16, BlockStmt target_17, EqualityOperation target_18, EqualityOperation target_19, BlockStmt target_20
where
func_0(func, target_0)
and func_1(func, target_1)
and not func_2(vc_133, target_13, target_14, target_15)
and func_3(vc_133, target_13, target_3)
and func_4(vc_133, target_16, target_4)
and func_5(vc_133, target_17, target_5)
and func_6(target_10, func, target_6)
and func_7(vp_127, vcharset_127, vsomething_found_132, vc_133, target_18, target_7)
and func_8(target_19, func, target_8)
and func_9(vc_133, target_20, target_9)
and func_10(vc_133, target_20, target_14, target_15, target_10)
and func_11(vstate_129, vc_133, target_4, target_11)
and func_12(func, target_12)
and func_13(vcharset_127, vc_133, target_13)
and func_14(vc_133, target_14)
and func_15(vcharset_127, vc_133, target_15)
and func_16(vp_127, vcharset_127, vstate_129, vc_133, target_16)
and func_17(target_17)
and func_18(vc_133, target_18)
and func_19(vc_133, target_19)
and func_20(target_20)
and vp_127.getType().hasName("unsigned char **")
and vcharset_127.getType().hasName("unsigned char *")
and vstate_129.getType().hasName("setcharset_state")
and vsomething_found_132.getType().hasName("bool")
and vc_133.getType().hasName("unsigned char")
and vp_127.getFunction() = func
and vcharset_127.getFunction() = func
and vstate_129.(LocalVariable).getFunction() = func
and vsomething_found_132.(LocalVariable).getFunction() = func
and vc_133.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
