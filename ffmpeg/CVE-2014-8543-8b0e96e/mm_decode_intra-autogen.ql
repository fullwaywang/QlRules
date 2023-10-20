/**
 * @name ffmpeg-8b0e96e1f21b761ca15dbb470cd619a1ebf86c3e-mm_decode_intra
 * @id cpp/ffmpeg/8b0e96e1f21b761ca15dbb470cd619a1ebf86c3e/mm-decode-intra
 * @description ffmpeg-8b0e96e1f21b761ca15dbb470cd619a1ebf86c3e-libavcodec/mmvideo.c-mm_decode_intra CVE-2014-8543
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vhalf_vert_86, Variable vy_88, Parameter vs_86, IfStmt target_2, PointerArithmeticOperation target_3, PointerArithmeticOperation target_4) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand().(VariableAccess).getTarget()=vhalf_vert_86
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vy_88
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vhalf_vert_86
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="avctx"
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_86
		and target_0.getParent().(IfStmt).getThen().(ExprStmt).getExpr() instanceof FunctionCall
		and target_0.getAnOperand().(VariableAccess).getLocation().isBefore(target_2.getCondition().(VariableAccess).getLocation())
		and target_3.getAnOperand().(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_4.getAnOperand().(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vhalf_vert_86, VariableAccess target_1) {
		target_1.getTarget()=vhalf_vert_86
		and target_1.getParent().(IfStmt).getThen().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_2(Parameter vhalf_vert_86, IfStmt target_2) {
		target_2.getCondition().(VariableAccess).getTarget()=vhalf_vert_86
		and target_2.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memset")
		and target_2.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_2.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_2.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_2.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("int")
		and target_2.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_3(Variable vy_88, Parameter vs_86, PointerArithmeticOperation target_3) {
		target_3.getAnOperand().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_3.getAnOperand().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="frame"
		and target_3.getAnOperand().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_86
		and target_3.getAnOperand().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_3.getAnOperand().(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vy_88
		and target_3.getAnOperand().(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="linesize"
		and target_3.getAnOperand().(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="frame"
		and target_3.getAnOperand().(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_86
		and target_3.getAnOperand().(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_3.getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_4(Variable vy_88, Parameter vs_86, PointerArithmeticOperation target_4) {
		target_4.getAnOperand().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_4.getAnOperand().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="frame"
		and target_4.getAnOperand().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_86
		and target_4.getAnOperand().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_4.getAnOperand().(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vy_88
		and target_4.getAnOperand().(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_4.getAnOperand().(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="linesize"
		and target_4.getAnOperand().(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="frame"
		and target_4.getAnOperand().(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_86
		and target_4.getAnOperand().(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_4.getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
}

from Function func, Parameter vhalf_vert_86, Variable vy_88, Parameter vs_86, VariableAccess target_1, IfStmt target_2, PointerArithmeticOperation target_3, PointerArithmeticOperation target_4
where
not func_0(vhalf_vert_86, vy_88, vs_86, target_2, target_3, target_4)
and func_1(vhalf_vert_86, target_1)
and func_2(vhalf_vert_86, target_2)
and func_3(vy_88, vs_86, target_3)
and func_4(vy_88, vs_86, target_4)
and vhalf_vert_86.getType().hasName("int")
and vy_88.getType().hasName("int")
and vs_86.getType().hasName("MmContext *")
and vhalf_vert_86.getFunction() = func
and vy_88.(LocalVariable).getFunction() = func
and vs_86.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
