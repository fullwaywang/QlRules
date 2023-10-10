/**
 * @name ffmpeg-13451f5520ce6b0afde861b2285dda659f8d4fb4-atrac3_decode_init
 * @id cpp/ffmpeg/13451f5520ce6b0afde861b2285dda659f8d4fb4/atrac3-decode-init
 * @description ffmpeg-13451f5520ce6b0afde861b2285dda659f8d4fb4-libavcodec/atrac3.c-atrac3_decode_init CVE-2013-0858
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vq_870, Parameter vavctx_865, ExprStmt target_1, EqualityOperation target_2, ExprStmt target_3, ExprStmt target_4, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="coding_mode"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vq_870
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="18"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="channels"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_865
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="2"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_865
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Invalid coding mode\n"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1094995529"
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Variable vq_870, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="scrambled_stream"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vq_870
		and target_1.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
}

predicate func_2(Variable vq_870, EqualityOperation target_2) {
		target_2.getAnOperand().(PointerFieldAccess).getTarget().getName()="coding_mode"
		and target_2.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vq_870
		and target_2.getAnOperand().(Literal).getValue()="2"
}

predicate func_3(Parameter vavctx_865, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_3.getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_3.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_3.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Unknown extradata size %d.\n"
		and target_3.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="extradata_size"
		and target_3.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_865
}

predicate func_4(Parameter vavctx_865, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_865
		and target_4.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_4.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Version %d != 4.\n"
		and target_4.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType().hasName("int")
}

from Function func, Variable vq_870, Parameter vavctx_865, ExprStmt target_1, EqualityOperation target_2, ExprStmt target_3, ExprStmt target_4
where
not func_0(vq_870, vavctx_865, target_1, target_2, target_3, target_4, func)
and func_1(vq_870, target_1)
and func_2(vq_870, target_2)
and func_3(vavctx_865, target_3)
and func_4(vavctx_865, target_4)
and vq_870.getType().hasName("ATRAC3Context *")
and vavctx_865.getType().hasName("AVCodecContext *")
and vq_870.(LocalVariable).getFunction() = func
and vavctx_865.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
