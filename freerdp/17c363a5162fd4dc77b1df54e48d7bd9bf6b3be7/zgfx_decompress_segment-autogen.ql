/**
 * @name freerdp-17c363a5162fd4dc77b1df54e48d7bd9bf6b3be7-zgfx_decompress_segment
 * @id cpp/freerdp/17c363a5162fd4dc77b1df54e48d7bd9bf6b3be7/zgfx-decompress-segment
 * @description freerdp-17c363a5162fd4dc77b1df54e48d7bd9bf6b3be7-libfreerdp/codec/zgfx.c-zgfx_decompress_segment CVE-2018-8784
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vzgfx_221, Parameter vstream_221, ReturnStmt target_17, ExprStmt target_18, LogicalOrExpr target_15) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vzgfx_221
		and target_0.getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vstream_221
		and target_0.getParent().(IfStmt).getThen()=target_17
		and target_0.getAnOperand().(NotExpr).getOperand().(VariableAccess).getLocation().isBefore(target_18.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(NotExpr).getOperand().(VariableAccess).getLocation().isBefore(target_15.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Variable vcbSegment_232, ExprStmt target_19, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcbSegment_232
		and target_1.getExpr().(AssignExpr).getRValue() instanceof SubExpr
		and (func.getEntryPoint().(BlockStmt).getStmt(11)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(11).getFollowingStmt()=target_1)
		and target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_19.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_2(Parameter vsegmentSize_221, BlockStmt target_20, LogicalOrExpr target_15) {
	exists(LogicalOrExpr target_2 |
		target_2.getAnOperand() instanceof LogicalOrExpr
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vsegmentSize_221
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="4294967295"
		and target_2.getParent().(IfStmt).getThen()=target_20
		and target_15.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_3(NotExpr target_11, Function func) {
	exists(ReturnStmt target_3 |
		target_3.getExpr().(Literal).getValue()="0"
		and target_3.getParent().(IfStmt).getCondition()=target_11
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Variable vcbSegment_232, BlockStmt target_21, ExprStmt target_22) {
	exists(RelationalOperation target_4 |
		 (target_4 instanceof GTExpr or target_4 instanceof LTExpr)
		and target_4.getGreaterOperand().(VariableAccess).getTarget()=vcbSegment_232
		and target_4.getLesserOperand().(SizeofExprOperator).getValue()="65536"
		and target_4.getParent().(IfStmt).getThen()=target_21
		and target_22.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(MulExpr).getRightOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_4.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_5(EqualityOperation target_12, Function func) {
	exists(ReturnStmt target_5 |
		target_5.getExpr().(Literal).getValue()="0"
		and target_5.getParent().(IfStmt).getCondition()=target_12
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(Parameter vzgfx_221, Variable vc_223, Variable vopIndex_226, Variable vdistance_230, Variable vZGFX_TOKEN_TABLE, ExprStmt target_23, ArrayExpr target_24, ArrayExpr target_25, EqualityOperation target_13) {
	exists(IfStmt target_6 |
		target_6.getCondition() instanceof EqualityOperation
		and target_6.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="tokenType"
		and target_6.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vZGFX_TOKEN_TABLE
		and target_6.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vopIndex_226
		and target_6.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_6.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("zgfx_GetBits")
		and target_6.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vzgfx_221
		and target_6.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="valueBits"
		and target_6.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vc_223
		and target_6.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vc_223
		and target_6.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="HistoryBufferSize"
		and target_6.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(4).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="OutputCount"
		and target_6.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(4).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_6.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vc_223
		and target_6.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("zgfx_GetBits")
		and target_6.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vzgfx_221
		and target_6.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="valueBits"
		and target_6.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdistance_230
		and target_6.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(2).(IfStmt).getCondition() instanceof EqualityOperation
		and target_6.getThen().(BlockStmt).getStmt(1).(BreakStmt).toString() = "break;"
		and target_6.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_23.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_24.getArrayOffset().(VariableAccess).getLocation().isBefore(target_6.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation())
		and target_6.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation().isBefore(target_25.getArrayOffset().(VariableAccess).getLocation())
		and target_6.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_13.getAnOperand().(VariableAccess).getLocation()))
}

/*predicate func_7(Parameter vzgfx_221, EqualityOperation target_26, ExprStmt target_27) {
	exists(IfStmt target_7 |
		target_7.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="OutputCount"
		and target_7.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vzgfx_221
		and target_7.getCondition().(RelationalOperation).getLesserOperand().(SizeofExprOperator).getValue()="65536"
		and target_7.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(4)=target_7
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_26
		and target_27.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
/*predicate func_8(Parameter vzgfx_221, Variable vextra_225, Variable vcount_229, Variable vdistance_230, EqualityOperation target_26, ExprStmt target_23, EqualityOperation target_13) {
	exists(IfStmt target_8 |
		target_8.getCondition() instanceof EqualityOperation
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("zgfx_GetBits")
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vzgfx_221
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="bits"
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vzgfx_221
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcount_229
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="3"
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcount_229
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="4"
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vextra_225
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="2"
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("zgfx_GetBits")
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vzgfx_221
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(3).(WhileStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="bits"
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(3).(WhileStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("zgfx_GetBits")
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vzgfx_221
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vextra_225
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vcount_229
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(PointerFieldAccess).getTarget().getName()="bits"
		and target_8.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcount_229
		and target_8.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(SizeofExprOperator).getValue()="65536"
		and target_8.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="OutputCount"
		and target_8.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vzgfx_221
		and target_8.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_8.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("zgfx_history_buffer_ring_read")
		and target_8.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vzgfx_221
		and target_8.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdistance_230
		and target_8.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="OutputBuffer"
		and target_8.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getTarget().getName()="OutputCount"
		and target_8.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vcount_229
		and target_8.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("zgfx_history_buffer_ring_write")
		and target_8.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vzgfx_221
		and target_8.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="OutputBuffer"
		and target_8.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getTarget().getName()="OutputCount"
		and target_8.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcount_229
		and target_8.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="OutputCount"
		and target_8.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vzgfx_221
		and target_8.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vcount_229
		and target_8.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("zgfx_GetBits")
		and target_8.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vzgfx_221
		and target_8.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="15"
		and target_8.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcount_229
		and target_8.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="bits"
		and target_8.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vzgfx_221
		and target_8.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignSubExpr).getLValue().(PointerFieldAccess).getTarget().getName()="cBitsRemaining"
		and target_8.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignSubExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vzgfx_221
		and target_8.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignSubExpr).getRValue().(PointerFieldAccess).getTarget().getName()="cBitsCurrent"
		and target_8.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignSubExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vzgfx_221
		and target_8.getElse().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="cBitsCurrent"
		and target_8.getElse().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vzgfx_221
		and target_8.getElse().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_8.getElse().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="BitsCurrent"
		and target_8.getElse().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vzgfx_221
		and target_8.getElse().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_8.getElse().(BlockStmt).getStmt(5).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcount_229
		and target_8.getElse().(BlockStmt).getStmt(5).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(SizeofExprOperator).getValue()="65536"
		and target_8.getElse().(BlockStmt).getStmt(5).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="OutputCount"
		and target_8.getElse().(BlockStmt).getStmt(5).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vzgfx_221
		and target_8.getElse().(BlockStmt).getStmt(5).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_8.getElse().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_8.getElse().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="OutputBuffer"
		and target_8.getElse().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getTarget().getName()="OutputCount"
		and target_8.getElse().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="pbInputCurrent"
		and target_8.getElse().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vzgfx_221
		and target_8.getElse().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcount_229
		and target_8.getElse().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("zgfx_history_buffer_ring_write")
		and target_8.getElse().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vzgfx_221
		and target_8.getElse().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="pbInputCurrent"
		and target_8.getElse().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vzgfx_221
		and target_8.getElse().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcount_229
		and target_8.getElse().(BlockStmt).getStmt(8).(ExprStmt).getExpr().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="pbInputCurrent"
		and target_8.getElse().(BlockStmt).getStmt(8).(ExprStmt).getExpr().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vzgfx_221
		and target_8.getElse().(BlockStmt).getStmt(8).(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=vcount_229
		and target_8.getElse().(BlockStmt).getStmt(9).(ExprStmt).getExpr().(AssignSubExpr).getLValue().(PointerFieldAccess).getTarget().getName()="cBitsRemaining"
		and target_8.getElse().(BlockStmt).getStmt(9).(ExprStmt).getExpr().(AssignSubExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vzgfx_221
		and target_8.getElse().(BlockStmt).getStmt(9).(ExprStmt).getExpr().(AssignSubExpr).getRValue().(MulExpr).getLeftOperand().(Literal).getValue()="8"
		and target_8.getElse().(BlockStmt).getStmt(9).(ExprStmt).getExpr().(AssignSubExpr).getRValue().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vcount_229
		and target_8.getElse().(BlockStmt).getStmt(10).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="OutputCount"
		and target_8.getElse().(BlockStmt).getStmt(10).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vzgfx_221
		and target_8.getElse().(BlockStmt).getStmt(10).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vcount_229
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(2)=target_8
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_26
		and target_23.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_13.getAnOperand().(VariableAccess).getLocation().isBefore(target_8.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

*/
/*predicate func_9(Parameter vzgfx_221, Variable vcount_229, EqualityOperation target_13, ExprStmt target_28, ExprStmt target_29) {
	exists(IfStmt target_9 |
		target_9.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcount_229
		and target_9.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(SizeofExprOperator).getValue()="65536"
		and target_9.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="OutputCount"
		and target_9.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vzgfx_221
		and target_9.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_9
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13
		and target_9.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_28.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_29.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_9.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

*/
/*predicate func_10(Parameter vzgfx_221, Variable vcount_229, EqualityOperation target_13, AddressOfExpr target_30, ExprStmt target_31, ExprStmt target_32) {
	exists(IfStmt target_10 |
		target_10.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcount_229
		and target_10.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(SizeofExprOperator).getValue()="65536"
		and target_10.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="OutputCount"
		and target_10.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vzgfx_221
		and target_10.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(5)=target_10
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13
		and target_10.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_30.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_31.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_10.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_10.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_32.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

*/
predicate func_11(Variable vflags_224, BlockStmt target_20, NotExpr target_11) {
		target_11.getOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vflags_224
		and target_11.getOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="32"
		and target_11.getParent().(IfStmt).getThen()=target_20
}

predicate func_12(Variable vopIndex_226, Variable vinPrefix_228, Variable vZGFX_TOKEN_TABLE, BlockStmt target_21, EqualityOperation target_12) {
		target_12.getAnOperand().(VariableAccess).getTarget()=vinPrefix_228
		and target_12.getAnOperand().(ValueFieldAccess).getTarget().getName()="prefixCode"
		and target_12.getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vZGFX_TOKEN_TABLE
		and target_12.getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vopIndex_226
		and target_12.getParent().(IfStmt).getThen()=target_21
}

predicate func_13(Variable vdistance_230, BlockStmt target_33, EqualityOperation target_13) {
		target_13.getAnOperand().(VariableAccess).getTarget()=vdistance_230
		and target_13.getAnOperand().(Literal).getValue()="0"
		and target_13.getParent().(IfStmt).getThen()=target_33
}

predicate func_14(Parameter vsegmentSize_221, SubExpr target_14) {
		target_14.getLeftOperand().(VariableAccess).getTarget()=vsegmentSize_221
		and target_14.getRightOperand().(Literal).getValue()="1"
}

predicate func_15(Parameter vstream_221, Parameter vsegmentSize_221, ReturnStmt target_17, LogicalOrExpr target_15) {
		target_15.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("Stream_GetRemainingLength")
		and target_15.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstream_221
		and target_15.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vsegmentSize_221
		and target_15.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vsegmentSize_221
		and target_15.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="1"
		and target_15.getParent().(IfStmt).getThen()=target_17
}

predicate func_16(Function func, Initializer target_16) {
		target_16.getExpr() instanceof SubExpr
		and target_16.getExpr().getEnclosingFunction() = func
}

predicate func_17(ReturnStmt target_17) {
		target_17.getExpr().(Literal).getValue()="0"
}

predicate func_18(Parameter vzgfx_221, ExprStmt target_18) {
		target_18.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="OutputCount"
		and target_18.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vzgfx_221
		and target_18.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_19(Parameter vstream_221, Variable vcbSegment_232, ExprStmt target_19) {
		target_19.getExpr().(FunctionCall).getTarget().hasName("Stream_Seek")
		and target_19.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstream_221
		and target_19.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcbSegment_232
}

predicate func_20(Parameter vzgfx_221, Variable vcbSegment_232, BlockStmt target_20) {
		target_20.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("zgfx_history_buffer_ring_write")
		and target_20.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vzgfx_221
		and target_20.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcbSegment_232
		and target_20.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_20.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="OutputBuffer"
		and target_20.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vzgfx_221
		and target_20.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcbSegment_232
}

predicate func_21(Parameter vzgfx_221, Variable vc_223, Variable vopIndex_226, Variable vdistance_230, Variable vZGFX_TOKEN_TABLE, BlockStmt target_21) {
		target_21.getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="tokenType"
		and target_21.getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vZGFX_TOKEN_TABLE
		and target_21.getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vopIndex_226
		and target_21.getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_21.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("zgfx_GetBits")
		and target_21.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vzgfx_221
		and target_21.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="valueBits"
		and target_21.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vc_223
		and target_21.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="valueBase"
		and target_21.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="bits"
		and target_21.getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("zgfx_GetBits")
		and target_21.getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vzgfx_221
		and target_21.getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="valueBits"
		and target_21.getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdistance_230
		and target_21.getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="valueBase"
		and target_21.getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="bits"
}

predicate func_22(Parameter vzgfx_221, Variable vcbSegment_232, ExprStmt target_22) {
		target_22.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="cBitsRemaining"
		and target_22.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vzgfx_221
		and target_22.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(MulExpr).getLeftOperand().(Literal).getValue()="8"
		and target_22.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(MulExpr).getRightOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vcbSegment_232
		and target_22.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(MulExpr).getRightOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_22.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="pbInputEnd"
		and target_22.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vzgfx_221
}

predicate func_23(Parameter vzgfx_221, Variable vopIndex_226, Variable vdistance_230, Variable vZGFX_TOKEN_TABLE, ExprStmt target_23) {
		target_23.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdistance_230
		and target_23.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="valueBase"
		and target_23.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vZGFX_TOKEN_TABLE
		and target_23.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vopIndex_226
		and target_23.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="bits"
		and target_23.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vzgfx_221
}

predicate func_24(Variable vopIndex_226, Variable vZGFX_TOKEN_TABLE, ArrayExpr target_24) {
		target_24.getArrayBase().(VariableAccess).getTarget()=vZGFX_TOKEN_TABLE
		and target_24.getArrayOffset().(VariableAccess).getTarget()=vopIndex_226
}

predicate func_25(Variable vopIndex_226, Variable vZGFX_TOKEN_TABLE, ArrayExpr target_25) {
		target_25.getArrayBase().(VariableAccess).getTarget()=vZGFX_TOKEN_TABLE
		and target_25.getArrayOffset().(VariableAccess).getTarget()=vopIndex_226
}

predicate func_26(Variable vopIndex_226, Variable vZGFX_TOKEN_TABLE, EqualityOperation target_26) {
		target_26.getAnOperand().(ValueFieldAccess).getTarget().getName()="tokenType"
		and target_26.getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vZGFX_TOKEN_TABLE
		and target_26.getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vopIndex_226
		and target_26.getAnOperand().(Literal).getValue()="0"
}

predicate func_27(Parameter vzgfx_221, ExprStmt target_27) {
		target_27.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="HistoryIndex"
		and target_27.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vzgfx_221
		and target_27.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_28(Parameter vzgfx_221, Variable vcount_229, Variable vdistance_230, ExprStmt target_28) {
		target_28.getExpr().(FunctionCall).getTarget().hasName("zgfx_history_buffer_ring_read")
		and target_28.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vzgfx_221
		and target_28.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdistance_230
		and target_28.getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="OutputBuffer"
		and target_28.getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vzgfx_221
		and target_28.getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getTarget().getName()="OutputCount"
		and target_28.getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vzgfx_221
		and target_28.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vcount_229
}

predicate func_29(Parameter vzgfx_221, Variable vcount_229, ExprStmt target_29) {
		target_29.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vcount_229
		and target_29.getExpr().(AssignAddExpr).getRValue().(PointerFieldAccess).getTarget().getName()="bits"
		and target_29.getExpr().(AssignAddExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vzgfx_221
}

predicate func_30(Parameter vzgfx_221, AddressOfExpr target_30) {
		target_30.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="OutputBuffer"
		and target_30.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vzgfx_221
		and target_30.getOperand().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getTarget().getName()="OutputCount"
		and target_30.getOperand().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vzgfx_221
}

predicate func_31(Parameter vzgfx_221, Variable vcount_229, ExprStmt target_31) {
		target_31.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcount_229
		and target_31.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="bits"
		and target_31.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vzgfx_221
}

predicate func_32(Parameter vzgfx_221, Variable vcount_229, ExprStmt target_32) {
		target_32.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_32.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="OutputBuffer"
		and target_32.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vzgfx_221
		and target_32.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getTarget().getName()="OutputCount"
		and target_32.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vzgfx_221
		and target_32.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="pbInputCurrent"
		and target_32.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vzgfx_221
		and target_32.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcount_229
}

predicate func_33(Parameter vzgfx_221, Variable vextra_225, Variable vcount_229, BlockStmt target_33) {
		target_33.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("zgfx_GetBits")
		and target_33.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vzgfx_221
		and target_33.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_33.getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="bits"
		and target_33.getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vzgfx_221
		and target_33.getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_33.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcount_229
		and target_33.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="3"
		and target_33.getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcount_229
		and target_33.getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="4"
		and target_33.getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vextra_225
		and target_33.getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="2"
		and target_33.getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("zgfx_GetBits")
		and target_33.getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vzgfx_221
		and target_33.getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
}

from Function func, Parameter vzgfx_221, Parameter vstream_221, Parameter vsegmentSize_221, Variable vc_223, Variable vflags_224, Variable vextra_225, Variable vopIndex_226, Variable vinPrefix_228, Variable vcount_229, Variable vdistance_230, Variable vcbSegment_232, Variable vZGFX_TOKEN_TABLE, NotExpr target_11, EqualityOperation target_12, EqualityOperation target_13, SubExpr target_14, LogicalOrExpr target_15, Initializer target_16, ReturnStmt target_17, ExprStmt target_18, ExprStmt target_19, BlockStmt target_20, BlockStmt target_21, ExprStmt target_22, ExprStmt target_23, ArrayExpr target_24, ArrayExpr target_25, EqualityOperation target_26, ExprStmt target_27, ExprStmt target_28, ExprStmt target_29, AddressOfExpr target_30, ExprStmt target_31, ExprStmt target_32, BlockStmt target_33
where
not func_0(vzgfx_221, vstream_221, target_17, target_18, target_15)
and not func_1(vcbSegment_232, target_19, func)
and not func_2(vsegmentSize_221, target_20, target_15)
and not func_3(target_11, func)
and not func_4(vcbSegment_232, target_21, target_22)
and not func_5(target_12, func)
and not func_6(vzgfx_221, vc_223, vopIndex_226, vdistance_230, vZGFX_TOKEN_TABLE, target_23, target_24, target_25, target_13)
and func_11(vflags_224, target_20, target_11)
and func_12(vopIndex_226, vinPrefix_228, vZGFX_TOKEN_TABLE, target_21, target_12)
and func_13(vdistance_230, target_33, target_13)
and func_14(vsegmentSize_221, target_14)
and func_15(vstream_221, vsegmentSize_221, target_17, target_15)
and func_16(func, target_16)
and func_17(target_17)
and func_18(vzgfx_221, target_18)
and func_19(vstream_221, vcbSegment_232, target_19)
and func_20(vzgfx_221, vcbSegment_232, target_20)
and func_21(vzgfx_221, vc_223, vopIndex_226, vdistance_230, vZGFX_TOKEN_TABLE, target_21)
and func_22(vzgfx_221, vcbSegment_232, target_22)
and func_23(vzgfx_221, vopIndex_226, vdistance_230, vZGFX_TOKEN_TABLE, target_23)
and func_24(vopIndex_226, vZGFX_TOKEN_TABLE, target_24)
and func_25(vopIndex_226, vZGFX_TOKEN_TABLE, target_25)
and func_26(vopIndex_226, vZGFX_TOKEN_TABLE, target_26)
and func_27(vzgfx_221, target_27)
and func_28(vzgfx_221, vcount_229, vdistance_230, target_28)
and func_29(vzgfx_221, vcount_229, target_29)
and func_30(vzgfx_221, target_30)
and func_31(vzgfx_221, vcount_229, target_31)
and func_32(vzgfx_221, vcount_229, target_32)
and func_33(vzgfx_221, vextra_225, vcount_229, target_33)
and vzgfx_221.getType().hasName("ZGFX_CONTEXT *")
and vstream_221.getType().hasName("wStream *")
and vsegmentSize_221.getType().hasName("size_t")
and vc_223.getType().hasName("BYTE")
and vflags_224.getType().hasName("BYTE")
and vextra_225.getType().hasName("UINT32")
and vopIndex_226.getType().hasName("int")
and vinPrefix_228.getType().hasName("int")
and vcount_229.getType().hasName("UINT32")
and vdistance_230.getType().hasName("UINT32")
and vcbSegment_232.getType().hasName("size_t")
and vZGFX_TOKEN_TABLE.getType() instanceof ArrayType
and vzgfx_221.getParentScope+() = func
and vstream_221.getParentScope+() = func
and vsegmentSize_221.getParentScope+() = func
and vc_223.getParentScope+() = func
and vflags_224.getParentScope+() = func
and vextra_225.getParentScope+() = func
and vopIndex_226.getParentScope+() = func
and vinPrefix_228.getParentScope+() = func
and vcount_229.getParentScope+() = func
and vdistance_230.getParentScope+() = func
and vcbSegment_232.getParentScope+() = func
and not vZGFX_TOKEN_TABLE.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
