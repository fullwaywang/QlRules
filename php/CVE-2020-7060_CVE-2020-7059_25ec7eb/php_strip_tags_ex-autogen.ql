/**
 * @name php-25ec7eb3463f34a2be666c6785d1c6b3cc89575e-php_strip_tags_ex
 * @id cpp/php/25ec7eb3463f34a2be666c6785d1c6b3cc89575e/php-strip-tags-ex
 * @description php-25ec7eb3463f34a2be666c6785d1c6b3cc89575e-ext/standard/string.c-php_strip_tags_ex CVE-2020-7059
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vbuf_5058, Variable vp_5058, Variable vis_xml_5064, BlockStmt target_6, ExprStmt target_7, LogicalAndExpr target_8, LogicalAndExpr target_9, LogicalAndExpr target_10) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand().(VariableAccess).getTarget()=vis_xml_5064
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vp_5058
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vbuf_5058
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vis_xml_5064
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vp_5058
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getRightOperand().(Literal).getValue()="1"
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="45"
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_6
		and target_7.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_8.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_9.getAnOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_10.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vbuf_5058, Variable vp_5058, BlockStmt target_11, LogicalAndExpr target_8, ExprStmt target_12, EqualityOperation target_3) {
	exists(LogicalAndExpr target_1 |
		target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vp_5058
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vbuf_5058
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and target_1.getAnOperand() instanceof EqualityOperation
		and target_1.getParent().(IfStmt).getThen()=target_11
		and target_8.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation())
		and target_12.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable vbuf_5058, Variable vp_5058, BlockStmt target_13, LogicalAndExpr target_14, ExprStmt target_15, EqualityOperation target_4) {
	exists(LogicalAndExpr target_2 |
		target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vp_5058
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vbuf_5058
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and target_2.getAnOperand() instanceof EqualityOperation
		and target_2.getParent().(IfStmt).getThen()=target_13
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_14.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_15.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_4.getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_3(Variable vp_5058, BlockStmt target_11, EqualityOperation target_3) {
		target_3.getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vp_5058
		and target_3.getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getRightOperand().(Literal).getValue()="1"
		and target_3.getAnOperand().(CharLiteral).getValue()="60"
		and target_3.getParent().(IfStmt).getThen()=target_11
}

predicate func_4(Variable vp_5058, BlockStmt target_13, EqualityOperation target_4) {
		target_4.getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vp_5058
		and target_4.getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getRightOperand().(Literal).getValue()="1"
		and target_4.getAnOperand().(CharLiteral).getValue()="60"
		and target_4.getParent().(IfStmt).getThen()=target_13
}

predicate func_5(Variable vp_5058, Variable vis_xml_5064, BlockStmt target_6, VariableAccess target_5) {
		target_5.getTarget()=vis_xml_5064
		and target_5.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vp_5058
		and target_5.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getRightOperand().(Literal).getValue()="1"
		and target_5.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="45"
		and target_5.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_6
}

predicate func_6(BlockStmt target_6) {
		target_6.getStmt(0).(BreakStmt).toString() = "break;"
}

predicate func_7(Variable vbuf_5058, Variable vp_5058, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vp_5058
		and target_7.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vbuf_5058
}

predicate func_8(Variable vbuf_5058, Variable vp_5058, LogicalAndExpr target_8) {
		target_8.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vp_5058
		and target_8.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vbuf_5058
		and target_8.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vp_5058
}

predicate func_9(Variable vp_5058, LogicalAndExpr target_9) {
		target_9.getAnOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__ctype_b_loc")
		and target_9.getAnOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vp_5058
		and target_9.getAnOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
}

predicate func_10(Variable vp_5058, Variable vis_xml_5064, LogicalAndExpr target_10) {
		target_10.getAnOperand().(VariableAccess).getTarget()=vis_xml_5064
		and target_10.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vp_5058
		and target_10.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getRightOperand().(Literal).getValue()="1"
		and target_10.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="45"
}

predicate func_11(Variable vp_5058, BlockStmt target_11) {
		target_11.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="3"
		and target_11.getStmt(2).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vp_5058
		and target_11.getStmt(3).(GotoStmt).toString() = "goto ..."
		and target_11.getStmt(3).(GotoStmt).getName() ="state_3"
}

predicate func_12(Variable vp_5058, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vp_5058
}

predicate func_13(Variable vp_5058, BlockStmt target_13) {
		target_13.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_13.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="2"
		and target_13.getStmt(2).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vp_5058
		and target_13.getStmt(3).(GotoStmt).toString() = "goto ..."
		and target_13.getStmt(3).(GotoStmt).getName() ="state_2"
}

predicate func_14(Variable vbuf_5058, Variable vp_5058, LogicalAndExpr target_14) {
		target_14.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vp_5058
		and target_14.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vbuf_5058
		and target_14.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vp_5058
}

predicate func_15(Variable vp_5058, ExprStmt target_15) {
		target_15.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vp_5058
}

from Function func, Variable vbuf_5058, Variable vp_5058, Variable vis_xml_5064, EqualityOperation target_3, EqualityOperation target_4, VariableAccess target_5, BlockStmt target_6, ExprStmt target_7, LogicalAndExpr target_8, LogicalAndExpr target_9, LogicalAndExpr target_10, BlockStmt target_11, ExprStmt target_12, BlockStmt target_13, LogicalAndExpr target_14, ExprStmt target_15
where
not func_0(vbuf_5058, vp_5058, vis_xml_5064, target_6, target_7, target_8, target_9, target_10)
and not func_1(vbuf_5058, vp_5058, target_11, target_8, target_12, target_3)
and not func_2(vbuf_5058, vp_5058, target_13, target_14, target_15, target_4)
and func_3(vp_5058, target_11, target_3)
and func_4(vp_5058, target_13, target_4)
and func_5(vp_5058, vis_xml_5064, target_6, target_5)
and func_6(target_6)
and func_7(vbuf_5058, vp_5058, target_7)
and func_8(vbuf_5058, vp_5058, target_8)
and func_9(vp_5058, target_9)
and func_10(vp_5058, vis_xml_5064, target_10)
and func_11(vp_5058, target_11)
and func_12(vp_5058, target_12)
and func_13(vp_5058, target_13)
and func_14(vbuf_5058, vp_5058, target_14)
and func_15(vp_5058, target_15)
and vbuf_5058.getType().hasName("const char *")
and vp_5058.getType().hasName("const char *")
and vis_xml_5064.getType().hasName("char")
and vbuf_5058.getParentScope+() = func
and vp_5058.getParentScope+() = func
and vis_xml_5064.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
