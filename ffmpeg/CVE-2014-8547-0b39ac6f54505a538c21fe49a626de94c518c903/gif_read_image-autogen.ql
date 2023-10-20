/**
 * @name ffmpeg-0b39ac6f54505a538c21fe49a626de94c518c903-gif_read_image
 * @id cpp/ffmpeg/0b39ac6f54505a538c21fe49a626de94c518c903/gif-read-image
 * @description ffmpeg-0b39ac6f54505a538c21fe49a626de94c518c903-libavcodec/gifdec.c-gif_read_image CVE-2014-8547
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vpass_65, Variable vy1_65, Variable vlinesize_65, Variable vptr_66, Variable vptr1_66, VariableAccess target_11, SwitchStmt target_12, ExprStmt target_10, RelationalOperation target_2, ExprStmt target_13, ExprStmt target_14, ExprStmt target_15, ExprStmt target_16, ExprStmt target_9) {
	exists(WhileStmt target_0 |
		target_0.getCondition() instanceof RelationalOperation
		and target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vy1_65
		and target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand() instanceof Literal
		and target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(VariableAccess).getTarget()=vpass_65
		and target_0.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vptr_66
		and target_0.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vptr1_66
		and target_0.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vlinesize_65
		and target_0.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vy1_65
		and target_0.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vpass_65
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
		and target_12.getExpr().(VariableAccess).getLocation().isBefore(target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(VariableAccess).getLocation())
		and target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(VariableAccess).getLocation().isBefore(target_10.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation())
		and target_2.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_13.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation())
		and target_14.getExpr().(AssignPointerAddExpr).getRValue().(MulExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_0.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_0.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_15.getExpr().(AssignPointerAddExpr).getRValue().(MulExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_16.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_0.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_9.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation()))
}

/*predicate func_1(Variable vpass_65, Variable vy1_65, SwitchStmt target_12, ExprStmt target_17) {
	exists(BinaryBitwiseOperation target_1 |
		target_1.getLeftOperand() instanceof Literal
		and target_1.getRightOperand().(VariableAccess).getTarget()=vpass_65
		and target_1.getParent().(AssignExpr).getRValue() = target_1
		and target_1.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vy1_65
		and target_12.getExpr().(VariableAccess).getLocation().isBefore(target_1.getRightOperand().(VariableAccess).getLocation())
		and target_1.getRightOperand().(VariableAccess).getLocation().isBefore(target_17.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation()))
}

*/
predicate func_2(Variable vheight_64, Variable vy1_65, BlockStmt target_18, RelationalOperation target_2) {
		 (target_2 instanceof GEExpr or target_2 instanceof LEExpr)
		and target_2.getGreaterOperand().(VariableAccess).getTarget()=vy1_65
		and target_2.getLesserOperand().(VariableAccess).getTarget()=vheight_64
		and target_2.getParent().(IfStmt).getThen()=target_18
}

predicate func_3(Variable vpass_65, VariableAccess target_3) {
		target_3.getTarget()=vpass_65
}

predicate func_5(Variable vpass_65, Variable vy1_65, Variable vlinesize_65, Variable vptr_66, Variable vptr1_66, VariableAccess target_19, IfStmt target_5) {
		target_5.getCondition() instanceof RelationalOperation
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vy1_65
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(VariableAccess).getTarget()=vpass_65
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(Literal).getValue()="2"
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse() instanceof Literal
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vptr_66
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vptr1_66
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vlinesize_65
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vy1_65
		and target_5.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vpass_65
		and target_5.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_19
}

/*predicate func_6(Variable vpass_65, Variable vy1_65, ConditionalExpr target_6) {
		target_6.getCondition().(VariableAccess).getTarget()=vpass_65
		and target_6.getThen().(Literal).getValue()="2"
		and target_6.getElse() instanceof Literal
		and target_6.getParent().(AssignExpr).getRValue() = target_6
		and target_6.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vy1_65
}

*/
predicate func_7(Variable vheight_64, Variable vpass_65, Variable vy1_65, Variable vlinesize_65, Variable vptr_66, Variable vptr1_66, VariableAccess target_19, IfStmt target_7) {
		target_7.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vy1_65
		and target_7.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vheight_64
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vy1_65
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_7.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vptr_66
		and target_7.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vptr1_66
		and target_7.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vlinesize_65
		and target_7.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vpass_65
		and target_7.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_19
}

/*predicate func_8(Variable vy1_65, RelationalOperation target_20, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vy1_65
		and target_8.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_20
}

*/
predicate func_9(Variable vlinesize_65, Variable vptr_66, Variable vptr1_66, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vptr_66
		and target_9.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vptr1_66
		and target_9.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vlinesize_65
}

predicate func_10(Variable vpass_65, ExprStmt target_10) {
		target_10.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vpass_65
}

predicate func_11(Variable vis_interleaved_65, VariableAccess target_11) {
		target_11.getTarget()=vis_interleaved_65
}

predicate func_12(Variable vpass_65, Variable vy1_65, SwitchStmt target_12) {
		target_12.getExpr().(VariableAccess).getTarget()=vpass_65
		and target_12.getStmt().(BlockStmt).getStmt(0).(SwitchCase).toString() = "default: "
		and target_12.getStmt().(BlockStmt).getStmt(1).(SwitchCase).getExpr().(Literal).getValue()="0"
		and target_12.getStmt().(BlockStmt).getStmt(2).(SwitchCase).getExpr().(Literal).getValue()="1"
		and target_12.getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vy1_65
		and target_12.getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(Literal).getValue()="8"
}

predicate func_13(Variable vy1_65, ExprStmt target_13) {
		target_13.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vy1_65
		and target_13.getExpr().(AssignAddExpr).getRValue().(Literal).getValue()="4"
}

predicate func_14(Variable vlinesize_65, Variable vptr_66, ExprStmt target_14) {
		target_14.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vptr_66
		and target_14.getExpr().(AssignPointerAddExpr).getRValue().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vlinesize_65
		and target_14.getExpr().(AssignPointerAddExpr).getRValue().(MulExpr).getRightOperand().(Literal).getValue()="8"
}

predicate func_15(Variable vlinesize_65, Variable vptr_66, ExprStmt target_15) {
		target_15.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vptr_66
		and target_15.getExpr().(AssignPointerAddExpr).getRValue().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vlinesize_65
		and target_15.getExpr().(AssignPointerAddExpr).getRValue().(MulExpr).getRightOperand().(Literal).getValue()="4"
}

predicate func_16(Variable vptr_66, Variable vptr1_66, ExprStmt target_16) {
		target_16.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vptr_66
		and target_16.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vptr1_66
}

predicate func_17(Variable vpass_65, ExprStmt target_17) {
		target_17.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vpass_65
}

predicate func_18(Variable vy1_65, Variable vlinesize_65, Variable vptr_66, Variable vptr1_66, BlockStmt target_18) {
		target_18.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vy1_65
		and target_18.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof ConditionalExpr
		and target_18.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vptr_66
		and target_18.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vptr1_66
		and target_18.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vlinesize_65
		and target_18.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vy1_65
}

predicate func_19(Variable vpass_65, VariableAccess target_19) {
		target_19.getTarget()=vpass_65
}

predicate func_20(Variable vheight_64, Variable vy1_65, RelationalOperation target_20) {
		 (target_20 instanceof GEExpr or target_20 instanceof LEExpr)
		and target_20.getGreaterOperand().(VariableAccess).getTarget()=vy1_65
		and target_20.getLesserOperand().(VariableAccess).getTarget()=vheight_64
}

from Function func, Variable vheight_64, Variable vis_interleaved_65, Variable vpass_65, Variable vy1_65, Variable vlinesize_65, Variable vptr_66, Variable vptr1_66, RelationalOperation target_2, VariableAccess target_3, IfStmt target_5, IfStmt target_7, ExprStmt target_9, ExprStmt target_10, VariableAccess target_11, SwitchStmt target_12, ExprStmt target_13, ExprStmt target_14, ExprStmt target_15, ExprStmt target_16, ExprStmt target_17, BlockStmt target_18, VariableAccess target_19, RelationalOperation target_20
where
not func_0(vpass_65, vy1_65, vlinesize_65, vptr_66, vptr1_66, target_11, target_12, target_10, target_2, target_13, target_14, target_15, target_16, target_9)
and func_2(vheight_64, vy1_65, target_18, target_2)
and func_3(vpass_65, target_3)
and func_5(vpass_65, vy1_65, vlinesize_65, vptr_66, vptr1_66, target_19, target_5)
and func_7(vheight_64, vpass_65, vy1_65, vlinesize_65, vptr_66, vptr1_66, target_19, target_7)
and func_9(vlinesize_65, vptr_66, vptr1_66, target_9)
and func_10(vpass_65, target_10)
and func_11(vis_interleaved_65, target_11)
and func_12(vpass_65, vy1_65, target_12)
and func_13(vy1_65, target_13)
and func_14(vlinesize_65, vptr_66, target_14)
and func_15(vlinesize_65, vptr_66, target_15)
and func_16(vptr_66, vptr1_66, target_16)
and func_17(vpass_65, target_17)
and func_18(vy1_65, vlinesize_65, vptr_66, vptr1_66, target_18)
and func_19(vpass_65, target_19)
and func_20(vheight_64, vy1_65, target_20)
and vheight_64.getType().hasName("int")
and vis_interleaved_65.getType().hasName("int")
and vpass_65.getType().hasName("int")
and vy1_65.getType().hasName("int")
and vlinesize_65.getType().hasName("int")
and vptr_66.getType().hasName("uint8_t *")
and vptr1_66.getType().hasName("uint8_t *")
and vheight_64.(LocalVariable).getFunction() = func
and vis_interleaved_65.(LocalVariable).getFunction() = func
and vpass_65.(LocalVariable).getFunction() = func
and vy1_65.(LocalVariable).getFunction() = func
and vlinesize_65.(LocalVariable).getFunction() = func
and vptr_66.(LocalVariable).getFunction() = func
and vptr1_66.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
