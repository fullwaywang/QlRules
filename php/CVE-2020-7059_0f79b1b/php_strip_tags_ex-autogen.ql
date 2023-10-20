/**
 * @name php-0f79b1bf301f455967676b5129240140c5c45b09-php_strip_tags_ex
 * @id cpp/php/0f79b1bf301f455967676b5129240140c5c45b09/php-strip-tags-ex
 * @description php-0f79b1bf301f455967676b5129240140c5c45b09-ext/standard/string.c-php_strip_tags_ex CVE-2020-7059
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vbuf_4717, Variable vp_4717, BlockStmt target_6, LogicalAndExpr target_7, LogicalAndExpr target_8, LogicalAndExpr target_9) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vp_4717
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vbuf_4717
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and target_0.getParent().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vp_4717
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getRightOperand().(Literal).getValue()="1"
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="92"
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_6
		and target_7.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_8.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_9.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vbuf_4717, Variable vp_4717, Variable vstate_4719, BlockStmt target_10, LogicalAndExpr target_8, LogicalAndExpr target_11, ExprStmt target_12, LogicalAndExpr target_13) {
	exists(LogicalAndExpr target_1 |
		target_1.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vstate_4719
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vp_4717
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vbuf_4717
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and target_1.getParent().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vp_4717
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getRightOperand().(Literal).getValue()="1"
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="60"
		and target_1.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_10
		and target_8.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation())
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_11.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation())
		and target_12.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_13.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable vbuf_4717, Variable vp_4717, Variable vstate_4719, BlockStmt target_14, LogicalAndExpr target_11, LogicalAndExpr target_16, ExprStmt target_17) {
	exists(LogicalAndExpr target_2 |
		target_2.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vstate_4719
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vp_4717
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vbuf_4717
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and target_2.getParent().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vp_4717
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getRightOperand().(Literal).getValue()="1"
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="60"
		and target_2.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_14
		and target_11.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation())
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_16.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation())
		and target_17.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_3(Variable vp_4717, Variable vstate_4719, BlockStmt target_10, EqualityOperation target_3) {
		target_3.getAnOperand().(VariableAccess).getTarget()=vstate_4719
		and target_3.getAnOperand().(Literal).getValue()="1"
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vp_4717
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getRightOperand().(Literal).getValue()="1"
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="60"
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_10
}

predicate func_4(Variable vp_4717, Variable vstate_4719, BlockStmt target_14, EqualityOperation target_4) {
		target_4.getAnOperand().(VariableAccess).getTarget()=vstate_4719
		and target_4.getAnOperand().(Literal).getValue()="1"
		and target_4.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vp_4717
		and target_4.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getRightOperand().(Literal).getValue()="1"
		and target_4.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="60"
		and target_4.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_14
}

predicate func_5(Variable vp_4717, Variable vstate_4719, BlockStmt target_6, EqualityOperation target_5) {
		target_5.getAnOperand().(VariableAccess).getTarget()=vstate_4719
		and target_5.getAnOperand().(Literal).getValue()="2"
		and target_5.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vp_4717
		and target_5.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getRightOperand().(Literal).getValue()="1"
		and target_5.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="92"
		and target_5.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_6
}

predicate func_6(BlockStmt target_6) {
		target_6.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="0"
		and target_6.getStmt(0).(IfStmt).getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="92"
}

predicate func_7(Variable vbuf_4717, Variable vp_4717, LogicalAndExpr target_7) {
		target_7.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vp_4717
		and target_7.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vbuf_4717
		and target_7.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="2"
		and target_7.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vp_4717
		and target_7.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getRightOperand().(Literal).getValue()="1"
		and target_7.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="45"
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vp_4717
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getRightOperand().(Literal).getValue()="2"
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="45"
}

predicate func_8(Variable vbuf_4717, Variable vp_4717, Variable vstate_4719, LogicalAndExpr target_8) {
		target_8.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vstate_4719
		and target_8.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vp_4717
		and target_8.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vbuf_4717
		and target_8.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vstate_4719
		and target_8.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_8.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vp_4717
		and target_8.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getRightOperand().(Literal).getValue()="1"
		and target_8.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="92"
		and target_8.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vp_4717
}

predicate func_9(Variable vp_4717, LogicalAndExpr target_9) {
		target_9.getAnOperand() instanceof EqualityOperation
		and target_9.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vp_4717
		and target_9.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getRightOperand().(Literal).getValue()="1"
		and target_9.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="92"
}

predicate func_10(Variable vstate_4719, BlockStmt target_10) {
		target_10.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstate_4719
		and target_10.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="3"
}

predicate func_11(Variable vbuf_4717, Variable vp_4717, Variable vstate_4719, LogicalAndExpr target_11) {
		target_11.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vstate_4719
		and target_11.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="3"
		and target_11.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vp_4717
		and target_11.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vbuf_4717
		and target_11.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="2"
		and target_11.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vp_4717
		and target_11.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getRightOperand().(Literal).getValue()="1"
		and target_11.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="45"
		and target_11.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vp_4717
		and target_11.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getRightOperand().(Literal).getValue()="2"
		and target_11.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="33"
}

predicate func_12(Variable vp_4717, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vp_4717
}

predicate func_13(Variable vp_4717, LogicalAndExpr target_13) {
		target_13.getAnOperand() instanceof EqualityOperation
		and target_13.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vp_4717
		and target_13.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getRightOperand().(Literal).getValue()="1"
		and target_13.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="60"
}

predicate func_14(Variable vstate_4719, BlockStmt target_14) {
		target_14.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_14.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstate_4719
		and target_14.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="2"
		and target_14.getStmt(2).(BreakStmt).toString() = "break;"
}

predicate func_16(Variable vp_4717, LogicalAndExpr target_16) {
		target_16.getAnOperand() instanceof EqualityOperation
		and target_16.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vp_4717
		and target_16.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getRightOperand().(Literal).getValue()="1"
		and target_16.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="60"
}

predicate func_17(Variable vstate_4719, ExprStmt target_17) {
		target_17.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstate_4719
		and target_17.getExpr().(AssignExpr).getRValue().(Literal).getValue()="4"
}

from Function func, Variable vbuf_4717, Variable vp_4717, Variable vstate_4719, EqualityOperation target_3, EqualityOperation target_4, EqualityOperation target_5, BlockStmt target_6, LogicalAndExpr target_7, LogicalAndExpr target_8, LogicalAndExpr target_9, BlockStmt target_10, LogicalAndExpr target_11, ExprStmt target_12, LogicalAndExpr target_13, BlockStmt target_14, LogicalAndExpr target_16, ExprStmt target_17
where
not func_0(vbuf_4717, vp_4717, target_6, target_7, target_8, target_9)
and not func_1(vbuf_4717, vp_4717, vstate_4719, target_10, target_8, target_11, target_12, target_13)
and not func_2(vbuf_4717, vp_4717, vstate_4719, target_14, target_11, target_16, target_17)
and func_3(vp_4717, vstate_4719, target_10, target_3)
and func_4(vp_4717, vstate_4719, target_14, target_4)
and func_5(vp_4717, vstate_4719, target_6, target_5)
and func_6(target_6)
and func_7(vbuf_4717, vp_4717, target_7)
and func_8(vbuf_4717, vp_4717, vstate_4719, target_8)
and func_9(vp_4717, target_9)
and func_10(vstate_4719, target_10)
and func_11(vbuf_4717, vp_4717, vstate_4719, target_11)
and func_12(vp_4717, target_12)
and func_13(vp_4717, target_13)
and func_14(vstate_4719, target_14)
and func_16(vp_4717, target_16)
and func_17(vstate_4719, target_17)
and vbuf_4717.getType().hasName("char *")
and vp_4717.getType().hasName("char *")
and vstate_4719.getType().hasName("uint8_t")
and vbuf_4717.getParentScope+() = func
and vp_4717.getParentScope+() = func
and vstate_4719.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
