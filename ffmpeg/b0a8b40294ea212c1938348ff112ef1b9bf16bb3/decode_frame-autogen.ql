/**
 * @name ffmpeg-b0a8b40294ea212c1938348ff112ef1b9bf16bb3-decode_frame
 * @id cpp/ffmpeg/b0a8b40294ea212c1938348ff112ef1b9bf16bb3/decode-frame
 * @description ffmpeg-b0a8b40294ea212c1938348ff112ef1b9bf16bb3-libavcodec/exr.c-decode_frame CVE-2020-35965
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vavctx_1688, Variable vymax_1696, ExprStmt target_2, RelationalOperation target_3, ExprStmt target_4, ExprStmt target_5, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vymax_1696
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_1688
		and target_0.getThen() instanceof ForStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(31)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(31).getFollowingStmt()=target_0)
		and target_2.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vptr_1694, Variable vi_1696, Variable vy_1696, Parameter vavctx_1688, Variable vymax_1696, Variable vplanes_1697, Variable vout_line_size_1698, Function func, ForStmt target_1) {
		target_1.getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_1696
		and target_1.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vi_1696
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vplanes_1697
		and target_1.getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vi_1696
		and target_1.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vptr_1694
		and target_1.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_1.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_1696
		and target_1.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vymax_1696
		and target_1.getStmt().(BlockStmt).getStmt(1).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vy_1696
		and target_1.getStmt().(BlockStmt).getStmt(1).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vymax_1696
		and target_1.getStmt().(BlockStmt).getStmt(1).(ForStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vy_1696
		and target_1.getStmt().(BlockStmt).getStmt(1).(ForStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_1.getStmt().(BlockStmt).getStmt(1).(ForStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_1688
		and target_1.getStmt().(BlockStmt).getStmt(1).(ForStmt).getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vy_1696
		and target_1.getStmt().(BlockStmt).getStmt(1).(ForStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memset")
		and target_1.getStmt().(BlockStmt).getStmt(1).(ForStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vptr_1694
		and target_1.getStmt().(BlockStmt).getStmt(1).(ForStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_1.getStmt().(BlockStmt).getStmt(1).(ForStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vout_line_size_1698
		and target_1.getStmt().(BlockStmt).getStmt(1).(ForStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vptr_1694
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1
}

predicate func_2(Parameter vavctx_1688, ExprStmt target_2) {
		target_2.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="execute2"
		and target_2.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_1688
		and target_2.getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vavctx_1688
		and target_2.getExpr().(VariableCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="thread_data"
		and target_2.getExpr().(VariableCall).getArgument(3).(Literal).getValue()="0"
}

predicate func_3(Variable vy_1696, Parameter vavctx_1688, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getLesserOperand().(VariableAccess).getTarget()=vy_1696
		and target_3.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_3.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_1688
}

predicate func_4(Variable vymax_1696, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vymax_1696
		and target_4.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_4.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="ymax"
		and target_4.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_4.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(Literal).getValue()="0"
		and target_4.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="ymax"
		and target_4.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(AddExpr).getAnOperand().(Literal).getValue()="1"
}

predicate func_5(Variable vptr_1694, Variable vi_1696, Variable vymax_1696, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vptr_1694
		and target_5.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_5.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_1696
		and target_5.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vymax_1696
		and target_5.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="linesize"
		and target_5.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_1696
}

from Function func, Variable vptr_1694, Variable vi_1696, Variable vy_1696, Parameter vavctx_1688, Variable vymax_1696, Variable vplanes_1697, Variable vout_line_size_1698, ForStmt target_1, ExprStmt target_2, RelationalOperation target_3, ExprStmt target_4, ExprStmt target_5
where
not func_0(vavctx_1688, vymax_1696, target_2, target_3, target_4, target_5, func)
and func_1(vptr_1694, vi_1696, vy_1696, vavctx_1688, vymax_1696, vplanes_1697, vout_line_size_1698, func, target_1)
and func_2(vavctx_1688, target_2)
and func_3(vy_1696, vavctx_1688, target_3)
and func_4(vymax_1696, target_4)
and func_5(vptr_1694, vi_1696, vymax_1696, target_5)
and vptr_1694.getType().hasName("uint8_t *")
and vi_1696.getType().hasName("int")
and vy_1696.getType().hasName("int")
and vavctx_1688.getType().hasName("AVCodecContext *")
and vymax_1696.getType().hasName("int")
and vplanes_1697.getType().hasName("int")
and vout_line_size_1698.getType().hasName("int")
and vptr_1694.getParentScope+() = func
and vi_1696.getParentScope+() = func
and vy_1696.getParentScope+() = func
and vavctx_1688.getParentScope+() = func
and vymax_1696.getParentScope+() = func
and vplanes_1697.getParentScope+() = func
and vout_line_size_1698.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
