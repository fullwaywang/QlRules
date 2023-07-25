/**
 * @name ffmpeg-76cc0f0f673353cd4746cd3b83838ae335e5d9ed-decode_plane
 * @id cpp/ffmpeg/76cc0f0f673353cd4746cd3b83838ae335e5d9ed/decode-plane
 * @description ffmpeg-76cc0f0f673353cd4746cd3b83838ae335e5d9ed-libavcodec/utvideodec.c-decode_plane CVE-2018-6912
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdst_242, Variable vcbit_256, Variable vdest_257, BlockStmt target_5, RelationalOperation target_6, ExprStmt target_7, AddressOfExpr target_8, ExprStmt target_9) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GTExpr or target_0 instanceof LTExpr)
		and target_0.getGreaterOperand().(MulExpr).getLeftOperand().(Literal).getValue()="3"
		and target_0.getGreaterOperand().(MulExpr).getRightOperand().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vdst_242
		and target_0.getGreaterOperand().(MulExpr).getRightOperand().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vdest_257
		and target_0.getGreaterOperand().(MulExpr).getRightOperand().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="7"
		and target_0.getGreaterOperand().(MulExpr).getRightOperand().(DivExpr).getRightOperand().(Literal).getValue()="8"
		and target_0.getLesserOperand().(FunctionCall).getTarget().hasName("get_bits_left")
		and target_0.getLesserOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vcbit_256
		and target_0.getParent().(IfStmt).getThen()=target_5
		and target_6.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getGreaterOperand().(MulExpr).getRightOperand().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getGreaterOperand().(MulExpr).getRightOperand().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation())
		and target_8.getOperand().(VariableAccess).getLocation().isBefore(target_0.getLesserOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation())
		and target_9.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_0.getGreaterOperand().(MulExpr).getRightOperand().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getLocation()))
}

predicate func_1(EqualityOperation target_4, Function func) {
	exists(ReturnStmt target_1 |
		target_1.getExpr().(UnaryMinusExpr).getValue()="-1094995529"
		and target_1.getParent().(IfStmt).getCondition()=target_4
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Variable vpbit_256, Variable vp_257, Variable vbits_272, Variable vsub_277, Variable vadd_277, Variable vk_278, AddressOfExpr target_10, AddressOfExpr target_11, AssignPointerAddExpr target_12, ExprStmt target_13, BinaryBitwiseOperation target_14, AddExpr target_15, ExprStmt target_16) {
	exists(IfStmt target_2 |
		target_2.getCondition() instanceof EqualityOperation
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vp_257
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_2.getElse().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vbits_272
		and target_2.getElse().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_2.getElse().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getRightOperand().(Literal).getValue()="8"
		and target_2.getElse().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("get_bits_left")
		and target_2.getElse().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vpbit_256
		and target_2.getElse().(BlockStmt).getStmt(2).(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1094995529"
		and target_2.getElse().(BlockStmt).getStmt(3).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vk_278
		and target_2.getElse().(BlockStmt).getStmt(3).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_2.getElse().(BlockStmt).getStmt(3).(ForStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vk_278
		and target_2.getElse().(BlockStmt).getStmt(3).(ForStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="8"
		and target_2.getElse().(BlockStmt).getStmt(3).(ForStmt).getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vk_278
		and target_2.getElse().(BlockStmt).getStmt(3).(ForStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("get_bits_le")
		and target_2.getElse().(BlockStmt).getStmt(3).(ForStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vadd_277
		and target_2.getElse().(BlockStmt).getStmt(3).(ForStmt).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignSubExpr).getRValue().(VariableAccess).getTarget()=vsub_277
		and target_2.getElse().(BlockStmt).getStmt(3).(ForStmt).getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vadd_277
		and target_10.getOperand().(VariableAccess).getLocation().isBefore(target_2.getElse().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation())
		and target_2.getElse().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation().isBefore(target_11.getOperand().(VariableAccess).getLocation())
		and target_12.getLValue().(VariableAccess).getLocation().isBefore(target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_13.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_14.getRightOperand().(SubExpr).getRightOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_2.getElse().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_2.getElse().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_15.getAnOperand().(VariableAccess).getLocation())
		and target_16.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_2.getElse().(BlockStmt).getStmt(3).(ForStmt).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignSubExpr).getRValue().(VariableAccess).getLocation()))
}

/*predicate func_3(Variable vpbit_256, Variable vbits_272, EqualityOperation target_4, AddressOfExpr target_10, AddressOfExpr target_11, BinaryBitwiseOperation target_14, AddExpr target_15) {
	exists(IfStmt target_3 |
		target_3.getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vbits_272
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getRightOperand().(Literal).getValue()="8"
		and target_3.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("get_bits_left")
		and target_3.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vpbit_256
		and target_3.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1094995529"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(2)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_10.getOperand().(VariableAccess).getLocation().isBefore(target_3.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation())
		and target_3.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation().isBefore(target_11.getOperand().(VariableAccess).getLocation())
		and target_14.getRightOperand().(SubExpr).getRightOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_3.getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_15.getAnOperand().(VariableAccess).getLocation()))
}

*/
predicate func_4(Variable vbits_272, BlockStmt target_5, EqualityOperation target_4) {
		target_4.getAnOperand().(VariableAccess).getTarget()=vbits_272
		and target_4.getAnOperand().(Literal).getValue()="0"
		and target_4.getParent().(IfStmt).getThen()=target_5
}

predicate func_5(Variable vp_257, BlockStmt target_5) {
		target_5.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vp_257
		and target_5.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_6(Parameter vdst_242, Variable vp_257, RelationalOperation target_6) {
		 (target_6 instanceof GTExpr or target_6 instanceof LTExpr)
		and target_6.getLesserOperand().(VariableAccess).getTarget()=vp_257
		and target_6.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vdst_242
}

predicate func_7(Parameter vdst_242, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vdst_242
}

predicate func_8(Variable vcbit_256, AddressOfExpr target_8) {
		target_8.getOperand().(VariableAccess).getTarget()=vcbit_256
}

predicate func_9(Variable vdest_257, Variable vp_257, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vp_257
		and target_9.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vdest_257
}

predicate func_10(Variable vpbit_256, AddressOfExpr target_10) {
		target_10.getOperand().(VariableAccess).getTarget()=vpbit_256
}

predicate func_11(Variable vpbit_256, AddressOfExpr target_11) {
		target_11.getOperand().(VariableAccess).getTarget()=vpbit_256
}

predicate func_12(Variable vp_257, AssignPointerAddExpr target_12) {
		target_12.getLValue().(VariableAccess).getTarget()=vp_257
		and target_12.getRValue().(Literal).getValue()="8"
}

predicate func_13(Variable vpbit_256, Variable vp_257, Variable vbits_272, Variable vk_278, ExprStmt target_13) {
		target_13.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_257
		and target_13.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vk_278
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("get_bits_le")
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vpbit_256
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vbits_272
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(Literal).getValue()="1"
}

predicate func_14(Variable vbits_272, BinaryBitwiseOperation target_14) {
		target_14.getLeftOperand().(HexLiteral).getValue()="128"
		and target_14.getRightOperand().(SubExpr).getLeftOperand().(Literal).getValue()="8"
		and target_14.getRightOperand().(SubExpr).getRightOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vbits_272
		and target_14.getRightOperand().(SubExpr).getRightOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
}

predicate func_15(Variable vbits_272, AddExpr target_15) {
		target_15.getAnOperand().(VariableAccess).getTarget()=vbits_272
		and target_15.getAnOperand().(Literal).getValue()="1"
}

predicate func_16(Variable vp_257, Variable vbits_272, Variable vsub_277, Variable vadd_277, Variable vk_278, ExprStmt target_16) {
		target_16.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vadd_277
		and target_16.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(ComplementExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_257
		and target_16.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(ComplementExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vk_278
		and target_16.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getRightOperand().(VariableAccess).getTarget()=vsub_277
		and target_16.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(SubExpr).getLeftOperand().(Literal).getValue()="8"
		and target_16.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vbits_272
}

from Function func, Parameter vdst_242, Variable vcbit_256, Variable vpbit_256, Variable vdest_257, Variable vp_257, Variable vbits_272, Variable vsub_277, Variable vadd_277, Variable vk_278, EqualityOperation target_4, BlockStmt target_5, RelationalOperation target_6, ExprStmt target_7, AddressOfExpr target_8, ExprStmt target_9, AddressOfExpr target_10, AddressOfExpr target_11, AssignPointerAddExpr target_12, ExprStmt target_13, BinaryBitwiseOperation target_14, AddExpr target_15, ExprStmt target_16
where
not func_0(vdst_242, vcbit_256, vdest_257, target_5, target_6, target_7, target_8, target_9)
and not func_1(target_4, func)
and not func_2(vpbit_256, vp_257, vbits_272, vsub_277, vadd_277, vk_278, target_10, target_11, target_12, target_13, target_14, target_15, target_16)
and func_4(vbits_272, target_5, target_4)
and func_5(vp_257, target_5)
and func_6(vdst_242, vp_257, target_6)
and func_7(vdst_242, target_7)
and func_8(vcbit_256, target_8)
and func_9(vdest_257, vp_257, target_9)
and func_10(vpbit_256, target_10)
and func_11(vpbit_256, target_11)
and func_12(vp_257, target_12)
and func_13(vpbit_256, vp_257, vbits_272, vk_278, target_13)
and func_14(vbits_272, target_14)
and func_15(vbits_272, target_15)
and func_16(vp_257, vbits_272, vsub_277, vadd_277, vk_278, target_16)
and vdst_242.getType().hasName("uint8_t *")
and vcbit_256.getType().hasName("GetBitContext")
and vpbit_256.getType().hasName("GetBitContext")
and vdest_257.getType().hasName("uint8_t *")
and vp_257.getType().hasName("uint8_t *")
and vbits_272.getType().hasName("int")
and vsub_277.getType().hasName("uint32_t")
and vadd_277.getType().hasName("uint32_t")
and vk_278.getType().hasName("int")
and vdst_242.getParentScope+() = func
and vcbit_256.getParentScope+() = func
and vpbit_256.getParentScope+() = func
and vdest_257.getParentScope+() = func
and vp_257.getParentScope+() = func
and vbits_272.getParentScope+() = func
and vsub_277.getParentScope+() = func
and vadd_277.getParentScope+() = func
and vk_278.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
