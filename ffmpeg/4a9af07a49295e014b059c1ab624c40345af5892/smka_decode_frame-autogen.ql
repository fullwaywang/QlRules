/**
 * @name ffmpeg-4a9af07a49295e014b059c1ab624c40345af5892-smka_decode_frame
 * @id cpp/ffmpeg/4a9af07a49295e014b059c1ab624c40345af5892/smka-decode-frame
 * @description ffmpeg-4a9af07a49295e014b059c1ab624c40345af5892-libavcodec/smacker.c-smka_decode_frame CVE-2015-8365
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vavctx_623, Variable vunp_size_636, Variable vbits_637, ExprStmt target_1, RelationalOperation target_2, RelationalOperation target_3, RelationalOperation target_4, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RemExpr).getLeftOperand().(VariableAccess).getTarget()=vunp_size_636
		and target_0.getCondition().(RemExpr).getRightOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="channels"
		and target_0.getCondition().(RemExpr).getRightOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_623
		and target_0.getCondition().(RemExpr).getRightOperand().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vbits_637
		and target_0.getCondition().(RemExpr).getRightOperand().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_623
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="unp_size %d is odd\n"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vunp_size_636
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-22"
		and (func.getEntryPoint().(BlockStmt).getStmt(23)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(23).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignExpr).getRValue().(DivExpr).getRightOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RemExpr).getRightOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RemExpr).getRightOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getCondition().(RemExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_3.getGreaterOperand().(DivExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RemExpr).getRightOperand().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_4.getGreaterOperand().(BinaryBitwiseOperation).getRightOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vavctx_623, Variable vunp_size_636, Variable vbits_637, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="nb_samples"
		and target_1.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vunp_size_636
		and target_1.getExpr().(AssignExpr).getRValue().(DivExpr).getRightOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="channels"
		and target_1.getExpr().(AssignExpr).getRValue().(DivExpr).getRightOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_623
		and target_1.getExpr().(AssignExpr).getRValue().(DivExpr).getRightOperand().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vbits_637
		and target_1.getExpr().(AssignExpr).getRValue().(DivExpr).getRightOperand().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
}

predicate func_2(Parameter vavctx_623, RelationalOperation target_2) {
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ff_get_buffer")
		and target_2.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_623
		and target_2.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_2.getGreaterOperand().(Literal).getValue()="0"
}

predicate func_3(Variable vunp_size_636, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getGreaterOperand().(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vunp_size_636
		and target_3.getGreaterOperand().(DivExpr).getRightOperand().(Literal).getValue()="2"
}

predicate func_4(Variable vbits_637, RelationalOperation target_4) {
		 (target_4 instanceof GTExpr or target_4 instanceof LTExpr)
		and target_4.getGreaterOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_4.getGreaterOperand().(BinaryBitwiseOperation).getRightOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vbits_637
}

from Function func, Parameter vavctx_623, Variable vunp_size_636, Variable vbits_637, ExprStmt target_1, RelationalOperation target_2, RelationalOperation target_3, RelationalOperation target_4
where
not func_0(vavctx_623, vunp_size_636, vbits_637, target_1, target_2, target_3, target_4, func)
and func_1(vavctx_623, vunp_size_636, vbits_637, target_1)
and func_2(vavctx_623, target_2)
and func_3(vunp_size_636, target_3)
and func_4(vbits_637, target_4)
and vavctx_623.getType().hasName("AVCodecContext *")
and vunp_size_636.getType().hasName("int")
and vbits_637.getType().hasName("int")
and vavctx_623.getParentScope+() = func
and vunp_size_636.getParentScope+() = func
and vbits_637.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
