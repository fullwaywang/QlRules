/**
 * @name ffmpeg-2960576378d17d71cc8dccc926352ce568b5eec1-kempf_decode_tile
 * @id cpp/ffmpeg/2960576378d17d71cc8dccc926352ce568b5eec1/kempf-decode-tile
 * @description ffmpeg-2960576378d17d71cc8dccc926352ce568b5eec1-libavcodec/g2meet.c-kempf_decode_tile CVE-2013-4264
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vsrc_338, Variable vzsize_341, Variable vsrc_end_343, Variable vsub_type_346, ReturnStmt target_3, ExprStmt target_4, ExprStmt target_5, EqualityOperation target_6, EqualityOperation target_7) {
	exists(AddExpr target_0 |
		target_0.getAnOperand().(VariableAccess).getTarget()=vzsize_341
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vsub_type_346
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="2"
		and target_0.getParent().(LTExpr).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vsrc_end_343
		and target_0.getParent().(LTExpr).getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vsrc_338
		and target_0.getParent().(LTExpr).getGreaterOperand().(VariableAccess).getTarget()=vzsize_341
		and target_0.getParent().(LTExpr).getParent().(IfStmt).getThen()=target_3
		and target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getLocation())
		and target_6.getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_7.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vsrc_338, Variable vsrc_end_343, NotExpr target_8, ExprStmt target_9, ExprStmt target_10, RelationalOperation target_11, PointerArithmeticOperation target_12) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vsrc_338
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vsrc_end_343
		and target_1.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1094995529"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
		and target_9.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_10.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation())
		and target_11.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation().isBefore(target_1.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_12.getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vsrc_338, Variable vzsize_341, Variable vsrc_end_343, ReturnStmt target_3, VariableAccess target_2) {
		target_2.getTarget()=vzsize_341
		and target_2.getParent().(LTExpr).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vsrc_end_343
		and target_2.getParent().(LTExpr).getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vsrc_338
		and target_2.getParent().(LTExpr).getParent().(IfStmt).getThen()=target_3
}

predicate func_3(ReturnStmt target_3) {
		target_3.getExpr().(UnaryMinusExpr).getValue()="-1094995529"
}

predicate func_4(Parameter vsrc_338, Variable vzsize_341, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vzsize_341
		and target_4.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vsrc_338
		and target_4.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_4.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_4.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vsrc_338
		and target_4.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
}

predicate func_5(Parameter vsrc_338, Variable vzsize_341, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("uncompress")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="kempf_buf"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("G2MContext *")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("uLongf")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vsrc_338
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vzsize_341
}

predicate func_6(Variable vsub_type_346, EqualityOperation target_6) {
		target_6.getAnOperand().(VariableAccess).getTarget()=vsub_type_346
		and target_6.getAnOperand().(Literal).getValue()="2"
}

predicate func_7(Variable vsub_type_346, EqualityOperation target_7) {
		target_7.getAnOperand().(VariableAccess).getTarget()=vsub_type_346
		and target_7.getAnOperand().(Literal).getValue()="2"
}

predicate func_8(NotExpr target_8) {
		target_8.getOperand().(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_9(Parameter vsrc_338, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_9.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vsrc_338
		and target_9.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="1"
}

predicate func_10(Parameter vsrc_338, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_10.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vsrc_338
}

predicate func_11(Parameter vsrc_338, Variable vzsize_341, Variable vsrc_end_343, RelationalOperation target_11) {
		 (target_11 instanceof GTExpr or target_11 instanceof LTExpr)
		and target_11.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vsrc_end_343
		and target_11.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vsrc_338
		and target_11.getGreaterOperand().(VariableAccess).getTarget()=vzsize_341
}

predicate func_12(Parameter vsrc_338, Variable vsrc_end_343, PointerArithmeticOperation target_12) {
		target_12.getLeftOperand().(VariableAccess).getTarget()=vsrc_end_343
		and target_12.getRightOperand().(VariableAccess).getTarget()=vsrc_338
}

from Function func, Parameter vsrc_338, Variable vzsize_341, Variable vsrc_end_343, Variable vsub_type_346, VariableAccess target_2, ReturnStmt target_3, ExprStmt target_4, ExprStmt target_5, EqualityOperation target_6, EqualityOperation target_7, NotExpr target_8, ExprStmt target_9, ExprStmt target_10, RelationalOperation target_11, PointerArithmeticOperation target_12
where
not func_0(vsrc_338, vzsize_341, vsrc_end_343, vsub_type_346, target_3, target_4, target_5, target_6, target_7)
and not func_1(vsrc_338, vsrc_end_343, target_8, target_9, target_10, target_11, target_12)
and func_2(vsrc_338, vzsize_341, vsrc_end_343, target_3, target_2)
and func_3(target_3)
and func_4(vsrc_338, vzsize_341, target_4)
and func_5(vsrc_338, vzsize_341, target_5)
and func_6(vsub_type_346, target_6)
and func_7(vsub_type_346, target_7)
and func_8(target_8)
and func_9(vsrc_338, target_9)
and func_10(vsrc_338, target_10)
and func_11(vsrc_338, vzsize_341, vsrc_end_343, target_11)
and func_12(vsrc_338, vsrc_end_343, target_12)
and vsrc_338.getType().hasName("const uint8_t *")
and vzsize_341.getType().hasName("int")
and vsrc_end_343.getType().hasName("const uint8_t *")
and vsub_type_346.getType().hasName("int")
and vsrc_338.getFunction() = func
and vzsize_341.(LocalVariable).getFunction() = func
and vsrc_end_343.(LocalVariable).getFunction() = func
and vsub_type_346.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
