/**
 * @name ffmpeg-6f2a3958cfac135c60b509a61a4fd39432d8f9a9-ffmpeg_cleanup
 * @id cpp/ffmpeg/6f2a3958cfac135c60b509a61a4fd39432d8f9a9/ffmpeg-cleanup
 * @description ffmpeg-6f2a3958cfac135c60b509a61a4fd39432d8f9a9-fftools/ffmpeg.c-ffmpeg_cleanup CVE-2020-22054
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vost_548, AddressOfExpr target_1, AddressOfExpr target_2) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("av_dict_free")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="swr_opts"
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vost_548
		and target_1.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vost_548, AddressOfExpr target_1) {
		target_1.getOperand().(PointerFieldAccess).getTarget().getName()="sws_dict"
		and target_1.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vost_548
}

predicate func_2(Variable vost_548, AddressOfExpr target_2) {
		target_2.getOperand().(PointerFieldAccess).getTarget().getName()="enc_ctx"
		and target_2.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vost_548
}

from Function func, Variable vost_548, AddressOfExpr target_1, AddressOfExpr target_2
where
not func_0(vost_548, target_1, target_2)
and func_1(vost_548, target_1)
and func_2(vost_548, target_2)
and vost_548.getType().hasName("OutputStream *")
and vost_548.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
